"""账号预热：注册完成后先以真人节奏"看两眼"站点，再去做试用检测。

协议链路能补的"人工痕迹"只有会话行为与节奏，所以这里按真实用户的顺序补三步：

  1) 整页导航 ``chatgpt.com``（带注册时的 cookie / oai-did）
  2) 停 1.5~4.0 秒（人在读页面）
  3) 调一次 ``/backend-api/me``（网页端登录后必发）
  4) 再停 0.8~2.5 秒

全程使用任务冻结的同一个代理 + 同一套指纹，和随后的试用检测保持"同一台机器、
同一个人"的身份连续性。任何一步失败都不影响已保存的账号 —— 调用方按 best-effort
处理即可。
"""
from __future__ import annotations

import logging
import random
import time
from typing import Any, Mapping

logger = logging.getLogger("webui.account_warm")

_HOME_URL = "https://chatgpt.com/"
_ME_URL = "https://chatgpt.com/backend-api/me"


def warm_account(
    *,
    access_token: str = "",
    cookie_header: str = "",
    proxy: str | None = None,
    fingerprint: Mapping[str, Any] | None = None,
    device_id: str = "",
    timeout: float = 20.0,
    visit_home: bool = False,
) -> dict:
    """按真人节奏预热一次账号，返回 {ok, home_status, me_status}。"""
    from http_client import create_http_session

    from .environment import _navigation_headers_from_fingerprint

    fp = dict(fingerprint or {})
    impersonate = str(fp.get("impersonate") or "chrome")
    ua = str(fp.get("user_agent") or "") or None
    cookie = (cookie_header or "").strip()
    result: dict[str, Any] = {"ok": False, "home_status": 0, "me_status": 0}

    session = create_http_session(
        proxy=(proxy or "").strip() or None,
        impersonate=impersonate,
        user_agent=ua,
    )
    try:
        # ① 真人打开站点：整页导航。
        # 默认不重复抓首页 —— 同一会话在 warmup 阶段刚完整加载过 chatgpt.com
        # （实测一次 470KB），这里再抓一遍只是白烧流量，阅读节奏用下面的
        # 停顿 + /backend-api/me 一样能体现。需要时可传 visit_home=True。
        if visit_home:
            headers = _navigation_headers_from_fingerprint(fp)
            if cookie:
                headers["Cookie"] = cookie
            resp = session.get(_HOME_URL, headers=headers, timeout=timeout)
            result["home_status"] = int(getattr(resp, "status_code", 0) or 0)

        # ② 停留：读页面
        time.sleep(random.uniform(1.5, 4.0))

        # ③ 账户接口：网页端登录后必发的那一个
        api_headers = {
            "Accept": "application/json",
            "Accept-Language": fp.get("lang_full") or "en-US,en;q=0.9",
            "User-Agent": ua or "",
            "Origin": "https://chatgpt.com",
            "Referer": "https://chatgpt.com/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
        }
        if access_token:
            api_headers["Authorization"] = f"Bearer {access_token}"
        if device_id:
            api_headers["OAI-Device-Id"] = device_id
        if cookie:
            api_headers["Cookie"] = cookie
        if fp.get("sec_ch_ua"):
            api_headers["sec-ch-ua"] = fp["sec_ch_ua"]
            api_headers["sec-ch-ua-mobile"] = fp.get("sec_ch_ua_mobile") or "?0"
            api_headers["sec-ch-ua-platform"] = fp.get("sec_ch_ua_platform") or '"macOS"'
        # ③ 账户接口。**不跟随重定向**：token/cookie 不被接受时这里会 302 到
        #    chatgpt.com/api/auth/error，跟随过去等于白拉一个 500KB 的错误页
        #    （实测占单任务流量 24%）。我们只关心"这次请求发生过"。
        resp2 = session.get(
            _ME_URL, headers=api_headers, timeout=timeout, allow_redirects=False
        )
        result["me_status"] = int(getattr(resp2, "status_code", 0) or 0)

        # ④ 再看一眼：真人从首页到订阅页之间总有一点停顿
        time.sleep(random.uniform(0.8, 2.5))
        result["ok"] = True
        logger.info(
            "[warm] 账号预热完成 home=%s me=%s", result["home_status"], result["me_status"]
        )
    finally:
        try:
            session.close()
        except Exception:  # noqa: BLE001
            pass
    return result
