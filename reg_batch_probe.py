"""批量判定一批邮箱在 OpenAI 的注册状态（已注册 / 未注册 / 未知）。

用在你丢了本地库、只想反查「这批邮箱哪些跑过注册」的场景。判定只走到
注册链路第 5 步（authorize/continue），不设密码、不建号、不发码
（login_password 那条路实测不发码）。

用法:
    python reg_batch_probe.py --input emails.txt --output result.json --workers 12

输入格式与邮箱池导入一致（每行一个）:
    邮箱----中转链接
    邮箱

输出:
    result.json   结构化结果（含每个号的状态、页面类型、耗时、尝试次数）
    result.txt    人类可读名单（已注册 / 未注册 / 未知 三段）

默认支持断点续跑：已判定过的邮箱直接从输出文件里复用，只补没判定的。
加 --fresh 忽略旧结果全部重跑。
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import random
import re
import string
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# sentinel 需要 node 子进程跑 OpenAI 真实 sdk.js。PATH 上通常没有，指到随附运行时。
_BUNDLED_NODE = (
    Path.home() / ".cache" / "codex-runtimes" / "codex-primary-runtime"
    / "dependencies" / "node" / "bin" / "node.exe"
)
if _BUNDLED_NODE.exists():
    os.environ.setdefault("OPENAI_SENTINEL_NODE_PATH", str(_BUNDLED_NODE))

logging.basicConfig(
    level=logging.WARNING,          # 业务日志太多，默认只看警告
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)

from registration_probe import (  # noqa: E402
    STATUS_REGISTERED,
    STATUS_UNKNOWN,
    STATUS_UNREGISTERED,
    probe_registration,
)

# 每个号最多试几次。409 invalid_state 是偶发的（sentinel 计算期间会话过期），
# 换个出口再来一次通常就好了，所以值得重试而不是直接判未知。
_MAX_ATTEMPTS = 3
_RETRY_SLEEP = 4.0

_print_lock = threading.Lock()


def _load_input(path: Path) -> list[dict[str, str]]:
    """读输入，取每行第一段当邮箱。带中转链接的只保留邮箱（判定不需要链接）。"""
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"-{4,}", line, maxsplit=1)
        email = parts[0].strip().lower()
        if "@" not in email or email in seen:
            continue
        seen.add(email)
        rows.append({"email": email, "relay_url": parts[1].strip() if len(parts) > 1 else ""})
    return rows


def _load_previous(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return {}
    out = {}
    for item in data.get("details") or []:
        email = str(item.get("email") or "").strip().lower()
        # 只复用确定性结论；unknown 要重试（上次可能只是出口抖动）
        if email and item.get("status") in (STATUS_REGISTERED, STATUS_UNREGISTERED):
            out[email] = item
    return out


def _exit_for(index: int, region: str = "") -> str:
    """给每个并发槽位签发一条独立出口（不同 sid = 不同 IP）。

    同一条凭据轮换 sid 就是注册流程里 sessionize_proxy 的做法：任务间出口
    不同，避免一批判定全压在同一个 IP 上。

    region 留空则沿用代理池里的地区记号。判定与出口地区无关（服务端按邮箱
    查账号，不看 IP 归属），所以这里可以按延迟挑：代理主机在哪个地区，
    就用哪个地区的出口，链路最短。
    """
    from webui import db

    pool = [ln.strip() for ln in (db.get_setting("proxy_pool", "") or "").splitlines() if ln.strip()]
    if not pool:
        return ""
    template = pool[index % len(pool)]
    suffix = "".join(random.choices(string.ascii_letters + string.digits, k=6))
    proxy = template
    if region:
        proxy = re.sub(r"region-[A-Za-z0-9]+", f"region-{region.upper()}", proxy)
    proxy = re.sub(r"sid-[A-Za-z0-9]+", f"sid-P{index:03d}{suffix}", proxy, count=1)
    return re.sub(r"-t-\d+", "-t-1440", proxy)


def _probe_with_retry(row: dict[str, str], slot: int, region: str = "") -> dict[str, Any]:
    email = row["email"]
    last: dict[str, Any] = {}
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        # 每次重试换一条出口：409 多半是会话/出口侧的瞬态
        proxy = _exit_for(slot * _MAX_ATTEMPTS + attempt, region)
        # 判定不需要 sentinel（见 registration_probe.probe_registration），
        # 关掉能省掉每个号约三分之一的耗时。
        result = probe_registration(email, proxy=proxy, country="IN", use_sentinel=False)
        last = result
        if result.get("status") in (STATUS_REGISTERED, STATUS_UNREGISTERED):
            result["attempts"] = attempt
            return result
        if attempt < _MAX_ATTEMPTS:
            time.sleep(_RETRY_SLEEP)
    last["attempts"] = _MAX_ATTEMPTS
    return last


def _write_reports(path: Path, rows: list[dict[str, Any]], started_at: float) -> None:
    buckets: dict[str, list[dict[str, Any]]] = {
        STATUS_REGISTERED: [], STATUS_UNREGISTERED: [], STATUS_UNKNOWN: [],
    }
    for item in rows:
        buckets.setdefault(str(item.get("status")), []).append(item)

    payload = {
        "generated_at": time.time(),
        "started_at": started_at,
        "elapsed_seconds": round(time.time() - started_at, 1),
        "total": len(rows),
        "counts": {k: len(v) for k, v in buckets.items()},
        "details": rows,
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = [
        f"# OpenAI 注册状态判定  生成于 {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"# 合计 {len(rows)} 个：已注册 {len(buckets[STATUS_REGISTERED])} / "
        f"未注册 {len(buckets[STATUS_UNREGISTERED])} / 未知 {len(buckets[STATUS_UNKNOWN])}",
        "",
    ]
    for title, key in (("== 已注册 ==", STATUS_REGISTERED),
                       ("== 未注册 ==", STATUS_UNREGISTERED),
                       ("== 未知（没探成，需重跑）==", STATUS_UNKNOWN)):
        items = buckets.get(key) or []
        lines.append(f"{title}（{len(items)}）")
        for item in sorted(items, key=lambda x: x["email"]):
            note = item.get("reason") or item.get("error") or ""
            lines.append(f"{item['email']}\t{note}")
        lines.append("")
    path.with_suffix(".txt").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="邮箱清单（email 或 email----中转链接，每行一个）")
    ap.add_argument("--output", default="reg_probe_result.json", help="结果 JSON 路径")
    ap.add_argument("--workers", type=int, default=10, help="并发数（默认 10）")
    ap.add_argument("--limit", type=int, default=0, help="只跑前 N 个（0=全部，调试用）")
    ap.add_argument(
        "--region", default="SG",
        help="出口地区记号（默认 SG，与代理主机同地、链路最短）。"
             "判定与地区无关；填 IN 可回到印度出口。",
    )
    ap.add_argument("--fresh", action="store_true", help="忽略已有结果，全部重跑")
    args = ap.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output)
    if not in_path.exists():
        print(f"输入文件不存在: {in_path}")
        return 2

    rows = _load_input(in_path)
    if args.limit:
        rows = rows[: args.limit]
    if not rows:
        print("输入里没有可用邮箱")
        return 2

    previous = {} if args.fresh else _load_previous(out_path)
    todo = [r for r in rows if r["email"] not in previous]
    print(f"总计 {len(rows)} 个，已有结论 {len(previous)} 个，本次待判 {len(todo)} 个，"
          f"并发 {args.workers}，出口地区 {args.region or '(池内原样)'}")

    started_at = time.time()
    collected: dict[str, dict[str, Any]] = dict(previous)
    done = 0

    if todo:
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            futures = {
                pool.submit(_probe_with_retry, row, idx % max(1, args.workers), args.region): row
                for idx, row in enumerate(todo)
            }
            for future in as_completed(futures):
                result = future.result()
                collected[str(result.get("email"))] = result
                done += 1
                if done % 10 == 0 or done == len(todo):
                    with _print_lock:
                        print(f"  进度 {done}/{len(todo)}  "
                              f"已注册 {sum(1 for v in collected.values() if v.get('status') == STATUS_REGISTERED)}  "
                              f"未注册 {sum(1 for v in collected.values() if v.get('status') == STATUS_UNREGISTERED)}  "
                              f"未知 {sum(1 for v in collected.values() if v.get('status') == STATUS_UNKNOWN)}")
                    # 边跑边落盘：500 个号要跑十几分钟，中途断了不该白跑
                    _write_reports(out_path, list(collected.values()), started_at)

    ordered = [collected[r["email"]] for r in rows if r["email"] in collected]
    _write_reports(out_path, ordered, started_at)
    counts = {s: sum(1 for v in ordered if v.get("status") == s)
              for s in (STATUS_REGISTERED, STATUS_UNREGISTERED, STATUS_UNKNOWN)}
    print(f"完成：{json.dumps(counts, ensure_ascii=False)}")
    print(f"结果已写入 {out_path} 与 {out_path.with_suffix('.txt')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
