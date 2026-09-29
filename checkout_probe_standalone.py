#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""int31.space 支付能力探测 —— 单文件版（可直接拷到另一台机器跑）。

它做的事：拿一个 OpenAI 的 access_token + 一条**印度**代理，去
https://int31.space/public/checkout-capabilities 实探这个号发起 checkout
时真实要付多少钱。返回 result.amountMinor = 0 才是真 0 元可领；大于 0 就是
该号实际要付的金额（例如 169407 分 = ₹1694.07）。

接口（2026-09-27 实测 + 前端 bundle 反解）：
  · POST /public/api/checkout-capabilities
        body {accessToken, proxyUrl}      -> 202 {taskId,status,statusUrl,email}
  · POST /public/api/checkout-capabilities/batch
        body {taskIds:[...]}              -> {tasks:[...],missingTaskIds:[...]}
  · 限流：连发几次会 429，响应带 retryAfterSeconds，必须按它退避。
  · 代理只认 http:// 写法；socks5/socks5h 一律 CheckoutTransportException。

用法（先装依赖：pip install curl_cffi）：
  # 1) 单个 AT + 单条印度代理
  python checkout_probe_standalone.py --token "eyJhbGci..." --proxy "http://user:pass@host:port"

  # 2) 一批 AT（每行一个）+ 一条代理模板（脚本自己换新 sid 并验活）
  python checkout_probe_standalone.py --tokens-file tokens.txt \
      --proxy-template "http://USER-region-Rand-sid-xxxx-t-30:PASS@GATEWAY:3010"

  # 3) 多代理轮换（每行一条）+ 结果写 CSV
  python checkout_probe_standalone.py --tokens-file tokens.txt \
      --proxy-file proxies.txt --out result.csv --interval 6

参数：
  --token/--tokens-file   access_token（二选一，可都传）
  --proxy/--proxy-file/--proxy-template
                          代理：单条 / 多行文件 / 模板（模板会替换 region-XX→IN、
                          sid-XX 换新、-t-N 拉长，并先验活再用于探测）
  --wait                  单个任务最多等多少秒（默认 180）
  --interval              两次探测之间的间隔秒数（默认 6，防限流）
  --out                   结果 CSV 路径（默认 checkout_probe_result.csv）
  --retries               传输类失败（探测服务连不上代理）重试次数（默认 2）
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import re
import string
import sys
import time
from pathlib import Path

try:
    from curl_cffi import requests as cffi_requests
except ImportError:  # pragma: no cover
    print("缺少依赖：先执行  pip install curl_cffi", file=sys.stderr)
    raise SystemExit(2)

BASE = "https://int31.space"
SUBMIT_URL = f"{BASE}/public/api/checkout-capabilities"
POLL_URL = f"{SUBMIT_URL}/batch"
TRACE_URL = "https://cloudflare.com/cdn-cgi/trace"
TERMINAL = {"SUCCEEDED", "COMPLETED", "FAILED", "CANCELLED", "EXPIRED"}


def session():
    s = cffi_requests.Session(impersonate="chrome")
    s.trust_env = False
    return s


def http_json(method: str, url: str, *, payload=None, timeout=45, proxy="") -> tuple[int, dict]:
    """发一个请求，返回 (状态码, JSON)。代理按 http:// 传给 curl。"""
    s = session()
    try:
        kwargs: dict = {"timeout": timeout}
        if payload is not None:
            kwargs["json"] = payload
            kwargs["headers"] = {"Content-Type": "application/json"}
        if proxy:
            # 本机走这条代理时也可以用 socks5h；但发给探测服务的必须是 http://
            kwargs["proxies"] = {"http": proxy, "https": proxy}
        resp = s.request(method, url, **kwargs)
        try:
            data = resp.json() if (resp.text or "").strip() else {}
        except Exception:
            data = {}
        return resp.status_code, data
    finally:
        try:
            s.close()
        except Exception:
            pass


def proxy_alive(proxy: str) -> bool:
    """本机验活：同一 sid 用 socks5h:// 走一遍 trace。

    cliproxy:3010 不支持 HTTP CONNECT，本机用 http:// 必超时；而探测服务那边
    只认 http:// 写法。提交用 http://、验活用 socks5h://，sid 相同即同一出口。
    """
    verify = re.sub(r"^https?://", "socks5h://", proxy)
    s = session()
    try:
        s.proxies = {"http": verify, "https": verify}
        resp = s.get(TRACE_URL, timeout=12)
        return resp.status_code == 200 and "loc=" in (resp.text or "")
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def build_india_proxy(template: str) -> str:
    """把代理模板改写成印度静态会话（region→IN、换新 sid、拉长 TTL、http://）。"""
    sid = "".join(random.choices(string.ascii_letters + string.digits, k=8))
    out = template.strip()
    out = re.sub(r"region-[A-Za-z0-9]+", "region-IN", out)
    out = re.sub(r"sid-[A-Za-z0-9]+", f"sid-{sid}", out, count=1)
    out = re.sub(r"-t-\d+", "-t-1440", out)
    out = re.sub(r"^socks5h?://", "http://", out)
    return out


class RateLimited(Exception):
    def __init__(self, retry_after: int):
        super().__init__(f"探测接口限流，{retry_after}s 后可再试")
        self.retry_after = retry_after


def submit(token: str, proxy: str) -> dict:
    status, data = http_json("POST", SUBMIT_URL, payload={"accessToken": token, "proxyUrl": proxy})
    if status == 429:
        retry = int((data or {}).get("retryAfterSeconds") or 600)
        raise RateLimited(retry)
    if status >= 400:
        raise RuntimeError(f"提交失败 HTTP {status}: {json.dumps(data, ensure_ascii=False)[:200]}")
    return data


def poll(task_id: str) -> dict:
    status, data = http_json("POST", POLL_URL, payload={"taskIds": [task_id]}, timeout=40)
    if status >= 400:
        raise RuntimeError(f"轮询失败 HTTP {status}")
    tasks = (data or {}).get("tasks") or []
    return tasks[0] if tasks else {}


def probe_once(token: str, proxy: str, wait_seconds: float = 180.0, poll_every: float = 5.0) -> dict:
    """跑完一次探测，返回终态任务对象。"""
    created = submit(token, proxy)
    task_id = created.get("taskId")
    if not task_id:
        raise RuntimeError(f"提交后没有 taskId: {str(created)[:160]}")
    deadline = time.time() + wait_seconds
    task: dict = {}
    while time.time() < deadline:
        time.sleep(poll_every)
        task = poll(task_id) or {}
        if str(task.get("status") or "").upper() in TERMINAL:
            return task
    return task or {"taskId": task_id, "status": "TIMEOUT"}


def probe(token: str, proxy: str, *, retries: int = 2, wait_seconds: float = 180.0,
          template: str = "") -> dict:
    """带自愈的探测：传输失败换新印度会话重试；限流按服务端提示退避。"""
    current = proxy
    for attempt in range(retries + 1):
        try:
            task = probe_once(token, current, wait_seconds=wait_seconds)
        except RateLimited as exc:
            return {"ok": False, "rate_limited": True, "retry_after": exc.retry_after,
                    "error": str(exc), "proxy": current}
        except Exception as exc:
            return {"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:160]}",
                    "proxy": current}
        status = str(task.get("status") or "").upper()
        failure = str(task.get("failureType") or "")
        result = task.get("result") if isinstance(task.get("result"), dict) else {}
        if failure == "CheckoutTransportException" and attempt < retries:
            # 探测服务连不上这条代理：换一条新会话再来
            if template:
                current = build_india_proxy(template)
                print(f"    传输失败，换新印度会话重试: {current.split('@')[0][:48]}...")
            else:
                print("    传输失败，重试同一条代理…")
                time.sleep(3)
            continue
        amount = result.get("amountMinor")
        return {
            "ok": status in ("SUCCEEDED", "COMPLETED"),
            "task_id": task.get("taskId") or "",
            "status": status,
            "failure_type": failure,
            "email": task.get("email") or "",
            "amount_minor": amount,
            "currency": result.get("currency") or "",
            "free_trial": amount == 0 and bool(result),
            "payment_methods": result.get("paymentMethodTypes") or [],
            "checkout_backend": result.get("checkoutBackend") or "",
            "processor_entity": result.get("processorEntity") or "",
            "provider_country": result.get("providerCountry") or "",
            "proxy": current,
            "checked_at": int(time.time()),
        }
    return {"ok": False, "error": "重试次数用尽", "proxy": current}


def read_lines(path: str) -> list[str]:
    return [line.strip() for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def main() -> int:
    ap = argparse.ArgumentParser(description="int31.space 支付能力探测（单文件版）")
    ap.add_argument("--token", action="append", default=[], help="access_token，可重复")
    ap.add_argument("--tokens-file", default="", help="每行一个 access_token")
    ap.add_argument("--proxy", default="", help="单条代理（http:// 写法）")
    ap.add_argument("--proxy-file", default="", help="每行一条代理，轮换使用")
    ap.add_argument("--proxy-template", default="", help="代理模板，脚本自动改印度+换 sid+验活")
    ap.add_argument("--wait", type=float, default=180.0, help="单任务最长等待秒数")
    ap.add_argument("--interval", type=float, default=6.0, help="两次探测之间的间隔（秒）")
    ap.add_argument("--out", default="checkout_probe_result.csv", help="结果 CSV 路径")
    ap.add_argument("--retries", type=int, default=2, help="传输失败重试次数")
    args = ap.parse_args()

    tokens = list(args.token)
    if args.tokens_file:
        tokens += read_lines(args.tokens_file)
    tokens = [t.strip() for t in tokens if t.strip()]
    if not tokens:
        print("没有 access_token：用 --token 或 --tokens-file 传进来", file=sys.stderr)
        return 2

    proxies = []
    if args.proxy:
        proxies.append(args.proxy.strip())
    if args.proxy_file:
        proxies += read_lines(args.proxy_file)
    if not proxies and args.proxy_template:
        # 先造一条并验活，验不通就再造
        for _ in range(5):
            candidate = build_india_proxy(args.proxy_template)
            if proxy_alive(candidate):
                proxies.append(candidate)
                break
            print("  印度会话不可用，换一条…")
    if not proxies:
        print("没有可用代理：用 --proxy / --proxy-file / --proxy-template 传", file=sys.stderr)
        return 2

    out_path = Path(args.out)
    header = ["token_tail", "email", "status", "ok", "free_trial", "amount_minor",
              "currency", "payment_methods", "checkout_backend", "processor_entity",
              "provider_country", "failure_type", "task_id", "checked_at", "error"]
    with out_path.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=header, extrasaction="ignore")
        writer.writeheader()
        for index, token in enumerate(tokens):
            proxy = proxies[index % len(proxies)]
            if args.proxy_template and not proxy_alive(proxy):
                proxy = build_india_proxy(args.proxy_template)
                print("  当前代理已失效，换新会话")
            print(f"[{index + 1}/{len(tokens)}] 探测 {token[:12]}… 代理 {proxy.split('@')[0][:46]}")
            outcome = probe(
                token, proxy, retries=args.retries, wait_seconds=args.wait,
                template=args.proxy_template,
            )
            row = {"token_tail": token[-8:], **outcome}
            row["payment_methods"] = ",".join(row.get("payment_methods") or [])
            writer.writerow(row)
            fh.flush()
            if outcome.get("rate_limited"):
                retry = int(outcome.get("retry_after") or 0)
                print(f"  被限流：服务端要求 {retry}s 后再试，已写入结果，先停。")
                break
            verdict = ("₹0 可领" if outcome.get("free_trial")
                       else (f"{outcome.get('amount_minor')} {outcome.get('currency')}"
                             if outcome.get("amount_minor") is not None
                             else outcome.get("error") or outcome.get("failure_type") or "?"))
            print(f"  -> {outcome.get('status') or '?'} | {verdict}")
            if index < len(tokens) - 1:
                time.sleep(max(0.0, args.interval))

    print(f"结果已写入: {out_path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
