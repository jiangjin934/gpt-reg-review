#!/usr/bin/env python3
"""纯协议 ChatGPT 注册（Outlook 邮箱版）。

用 Outlook 4 段接码账号 + 纯 HTTP 协议（curl_cffi + sentinel PoW + IMAP）
直接走 OpenAI authorize 状态机，无浏览器、无 Camoufox、无 Playwright。

接码账号 4 段格式（用 ---- 分隔）：
    email----password----client_id----microsoft_refresh_token

用法：
    python register_outlook.py 'xxx@outlook.jp----<pwd>----<client_id>----M.C538_...'

可选环境变量：
    PROXY                出口代理 URL，例如 socks5://user:pass@host:port
    OTP_TIMEOUT          OTP 等待秒数（默认 60，下限 30）
    WEBUI_ALLOW_LOGIN    1 = 邮箱被 OpenAI 识为已注册时走 OTP login 拿凭证
                         (默认 0：fast-fail 抛 RuntimeError，换下一个号)
    SKIP_OAUTH_TOKEN_EXCHANGE  1=跳过 OAuth refresh_token 交换
    AUTH_HTTP_TRACE      1=打印每次 HTTP 请求详情（调试用）
"""
from __future__ import annotations

import json
import logging
import os
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from config import Config  # noqa: E402
from mail_outlook import OutlookMailProvider  # noqa: E402
from auth_flow import AuthFlow, PasswordRequiredError  # noqa: E402
from webui import db  # noqa: E402
from webui.environment import EnvironmentAllocationError, allocate_environment  # noqa: E402

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)


def main():
    if len(sys.argv) < 2:
        print(
            "Usage: python register_outlook.py "
            "'email----password----client_id----refresh_token'",
            file=sys.stderr,
        )
        sys.exit(2)

    parts = sys.argv[1].split("----")
    if len(parts) != 4:
        print(f"4 段格式错: 拿到 {len(parts)} 段", file=sys.stderr)
        sys.exit(2)
    email, password, client_id, refresh = parts
    logger.info(
        f"账号: {email}  client_id={client_id[:8]}…  refresh_token len={len(refresh)}"
    )

    cfg = Config()
    cfg.proxy = os.environ.get("PROXY") or None

    # The CLI uses the same immutable environment ledger as WebUI tasks. This
    # keeps direct protocol registrations from reusing an exit IP or profile.
    db.init_db()
    run_id = f"cli_{uuid.uuid4().hex[:12]}"
    cli_log_dir = ROOT / "data" / "cli_runs"
    cli_log_dir.mkdir(parents=True, exist_ok=True)
    db.create_run(run_id, email, str(cli_log_dir / f"{run_id}.log"))
    environment_options = {
        "proxy": cfg.proxy or "",
        "proxy_pool": os.environ.get("PROXY_POOL", ""),
        "fingerprint_country": os.environ.get("FINGERPRINT_COUNTRY", ""),
        "fingerprint_browser_family": os.environ.get(
            "FINGERPRINT_BROWSER_FAMILY", "auto"
        ),
        "browser_engine": "playwright",
    }
    try:
        frozen_environment = allocate_environment(run_id, environment_options)
        db.update_run_environment(run_id, frozen_environment)
    except Exception as exc:
        db.finish_run(run_id, "failed", str(exc), category="network")
        if isinstance(exc, EnvironmentAllocationError):
            raise
        raise EnvironmentAllocationError(f"任务环境初始化失败: {exc}") from exc

    # The selected proxy and profile are authoritative for this task.
    cfg.proxy = frozen_environment.get("proxy") or None

    def record_environment_observation(observation: dict) -> None:
        try:
            db.record_run_observation(run_id, observation)
        except Exception as exc:
            logger.debug("环境观测写入失败: %s", exc)

    mail = OutlookMailProvider(
        email=email, password=password,
        client_id=client_id, refresh_token=refresh,
    )

    partial = False
    flow = None
    try:
        flow = AuthFlow(
            cfg,
            fingerprint=frozen_environment["fingerprint"],
            fingerprint_country=frozen_environment.get("country_code", ""),
            fingerprint_browser_family=frozen_environment.get("browser_family", "auto"),
            environment=frozen_environment,
            environment_observer=record_environment_observation,
        )
        logger.info("[auth_flow] run_register 启动 (纯协议 + outlook IMAP) ...")
        result = flow.run_register(mail)
        d = result.to_dict()
    except PasswordRequiredError as e:
        db.finish_run(run_id, "failed", str(e), category="account")
        raise
    except RuntimeError as e:
        # 拿到部分凭证（access_token / refresh_token 任一）也算成功，保留下来
        if flow is None:
            db.finish_run(run_id, "failed", str(e), category="unknown")
            raise
        d = flow.result.to_dict()
        if d.get("access_token") or d.get("refresh_token") or d.get("session_token"):
            partial = True
            logger.warning(f"[register] 流程异常: {e}")
            logger.warning("[register] 但已拿到部分凭证，继续保存")
        else:
            db.finish_run(run_id, "failed", str(e), category="unknown")
            raise
    except Exception as e:
        db.finish_run(run_id, "failed", str(e), category="unknown")
        raise

    logger.info(
        f"[register] 完成 email={d.get('email')} "
        f"access_token=len{len(d.get('access_token') or '')} "
        f"session_token=len{len(d.get('session_token') or '')} "
        f"refresh_token=len{len(d.get('refresh_token') or '')}"
    )
    db.finish_run(run_id, "done")

    out_path = ROOT / f"account_{email.replace('@', '_at_')}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=2)
    tag = " (部分凭证, 缺 session_token / 可能因为账号需要补手机)" if partial else ""
    print(
        f"\n=== DONE{tag} ===\n账号凭证已写入: {out_path}"
        f"\nrun_id: {run_id}"
        f"\n环境: ip={frozen_environment.get('exit_ip', '')} "
        f"fingerprint={frozen_environment.get('fingerprint_id', '')} "
        f"timezone={frozen_environment['fingerprint'].get('timezone', '')} "
        f"locale={frozen_environment['fingerprint'].get('locale', '')} "
        f"screen={frozen_environment['fingerprint'].get('screen', '')}"
    )


if __name__ == "__main__":
    main()
