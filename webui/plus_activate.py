"""int31.space 的 Plus 开通接入（提炼 checkout + UPI 支付 + 状态同步）。

协议（2026-09-26 实测确认）：
  1) POST /public/api/checkout/flow
       body: {accessToken, cdk, paymentMethodType, publisherCdk,
              publisherProvider, submitPaymentTask, ...}
       → 202 + 任务对象（taskId / statusUrl / plusVerificationStatus）
  2) GET  /public/api/checkout/flow/{taskId}      任务进度与 Plus 验证状态
  3) GET  /public/api/checkout/flow/results?cdk=  该 CDK 下的完成记录（含支付结果）
  4) POST /public/api/checkout/cdk/validate       剩余次数
  5) GET  /public/api/checkout/flow/status        服务负载

⚠️ 站点在 Cloudflare 后面：urllib 会被 1010 拦（实测），必须用 curl_cffi 的
浏览器 TLS 画像 + 完整浏览器头。
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Iterable, Optional

from curl_cffi import requests as cffi_requests

from . import db

logger = logging.getLogger("webui.plus_activate")

SERVICE_BASE = "https://int31.space"
PUBLIC_BASE = f"{SERVICE_BASE}/public/api/checkout"

# 默认配置（主人 2026-09-26 提供）。可在 WebUI 里改，存 settings。
DEFAULT_CHECKOUT_CDK = "AAM-FBC52472D40C1A8144C8E80F5A183A48"
DEFAULT_PAYMENT_CDK = "CDK-53SMZ-VAPCI-6CVJG-EGYTS"
DEFAULT_PROVIDER = "cdk-scan"
DEFAULT_PAYMENT_METHOD = "UPI"
# 0 元试用对应的促销活动（前端硬编码的同一个 id）：
#   applyPromotion=true + promotionCampaignId=plus-1-month-free + maxAmountCents=0
# 缺了这组参数会生成 ₹1999 的普通付费单（实测踩过）。
DEFAULT_PROMOTION_ID = "plus-1-month-free"

_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
_HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Origin": SERVICE_BASE,
    "Referer": f"{SERVICE_BASE}/public/checkout",
    "User-Agent": _UA,
    "sec-ch-ua": '"Chromium";v="131", "Google Chrome";v="131", "Not-A.Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"macOS"',
}


def _setting_flag(key: str, default: str = "0") -> bool:
    return (db.get_setting(key, default) or default).strip().lower() in (
        "1", "true", "yes", "on",
    )


def require_approval() -> bool:
    """命中试用后是否必须由主人授权才提交。

    2026-09-26 主人明确要求：可开通 Plus 的账号必须先授权，才能提交
    「提炼 + 支付」。所以默认值是 1（需要授权），关掉才回到全自动。
    """
    return _setting_flag("plus_require_approval", "1")


def config() -> dict:
    """读取（并补默认值）开通配置。"""
    return {
        "checkout_cdk": db.get_setting("plus_checkout_cdk", DEFAULT_CHECKOUT_CDK)
        or DEFAULT_CHECKOUT_CDK,
        "payment_cdk": db.get_setting("plus_payment_cdk", DEFAULT_PAYMENT_CDK)
        or DEFAULT_PAYMENT_CDK,
        "provider": db.get_setting("plus_publisher_provider", DEFAULT_PROVIDER)
        or DEFAULT_PROVIDER,
        "payment_method": db.get_setting("plus_payment_method", DEFAULT_PAYMENT_METHOD)
        or DEFAULT_PAYMENT_METHOD,
        "promotion_id": db.get_setting("plus_promotion_id", DEFAULT_PROMOTION_ID)
        or DEFAULT_PROMOTION_ID,
        "auto_submit": (db.get_setting("plus_auto_submit", "1") or "1").strip()
        in ("1", "true", "yes", "on"),
        "require_approval": require_approval(),
    }


def _session():
    session = cffi_requests.Session(impersonate="chrome")
    session.trust_env = False
    session.proxies = {"https": "", "http": ""}
    return session


def _request(method: str, path: str, *, json_body: Optional[dict] = None, timeout: int = 60) -> Any:
    session = _session()
    try:
        resp = session.request(
            method,
            f"{PUBLIC_BASE}{path}",
            headers=_HEADERS,
            json=json_body,
            timeout=timeout,
        )
        text = resp.text or ""
        if resp.status_code >= 400:
            raise RuntimeError(f"HTTP {resp.status_code}: {text[:200]}")
        return resp.json() if text.strip() else {}
    finally:
        try:
            session.close()
        except Exception:  # noqa: BLE001
            pass


def service_status() -> dict:
    return _request("GET", "/flow/status", timeout=30)


def cdk_balance(cdk: Optional[str] = None) -> dict:
    cdk = cdk or config()["checkout_cdk"]
    return _request("POST", "/cdk/validate", json_body={"cdk": cdk}, timeout=30)


def submit_one(
    access_token: str,
    *,
    email: str = "",
    checkout_cdk: str = "",
    payment_cdk: str = "",
    provider: str = "",
    payment_method: str = "",
) -> dict:
    """提交单个 access_token 的提炼 + 支付任务，返回任务对象。"""
    cfg = config()
    payload = {
        "accessToken": access_token,
        "cdk": (checkout_cdk or cfg["checkout_cdk"]).strip(),
        "paymentMethodType": (payment_method or cfg["payment_method"]).strip().upper(),
        "automaticMomoPayment": False,
        "maxAmountCents": 0,
        "proxyUrls": [],
        "applyPromotion": True,
        "promotionCampaignId": (cfg.get("promotion_id") or DEFAULT_PROMOTION_ID),
        "submitPaymentTask": True,
        "publisherCdk": (payment_cdk or cfg["payment_cdk"]).strip(),
        "publisherProvider": (provider or cfg["provider"]).strip(),
        "allowNonZeroPublisherAmount": False,
        "inputCount": 1,
        "duplicateCount": 0,
        "blockedDomainCount": 0,
    }
    task = _request("POST", "/flow", json_body=payload, timeout=90)
    logger.info(
        "[plus] 提交成功 email=%s task=%s",
        email or task.get("email"), task.get("taskId"),
    )
    return task


def task_status(task_id: str) -> dict:
    return _request("GET", f"/flow/{task_id}", timeout=30)


def results_by_cdk(cdk: Optional[str] = None) -> list[dict]:
    cdk = cdk or config()["checkout_cdk"]
    # ⚠️ 必须是 /flow/results —— 少了 /flow 会拼成 /checkout/results，
    # 服务端对未知路径统一回 401（不是 404），很容易误判成权限问题。
    data = _request("GET", f"/flow/results?cdk={cdk}", timeout=45)
    return data if isinstance(data, list) else []


def _is_activated(task: dict) -> bool:
    """判定一个任务是否「已开通 Plus」。

    实测口径：0 元 checkout 支付成功（result.paymentStatus=succeeded）
    或 Plus 验证确认（plusVerificationStatus=CONFIRMED）都算开通。
    """
    result = task.get("result") or {}
    if str(result.get("paymentStatus") or "").lower() == "succeeded":
        return True
    return str(task.get("plusVerificationStatus") or "").upper() == "CONFIRMED"


def sync_activations() -> dict:
    """把服务侧的最新状态同步进本地 plus_activations 表。"""
    cfg = config()
    updated = 0
    hits = 0

    # 1) 按 CDK 拉完成记录（含支付结果）——最终判定来源
    try:
        for item in results_by_cdk(cfg["checkout_cdk"]):
            email = (item.get("email") or "").strip().lower()
            if not email:
                continue
            result = item.get("result") or {}
            task = {
                "result": result,
                "plusVerificationStatus": item.get("plusVerificationStatus"),
            }
            activated = _is_activated(task)
            db.upsert_plus_activation(
                email,
                task_id=item.get("taskId"),
                checkout_url=result.get("hostedUrl") or "",
                payment_status=str(result.get("paymentStatus") or ""),
                status="COMPLETED",
                activated=1 if activated else 0,
                detail_json=json.dumps(item, ensure_ascii=False)[:4000],
            )
            updated += 1
            hits += 1 if activated else 0
    except Exception as exc:  # noqa: BLE001
        logger.warning("[plus] 拉取 CDK 结果失败: %s", exc)

    # 2) 刷新本地有 task_id 的任务（拿进度/验证状态）
    for row in db.list_plus_activations():
        task_id = (row.get("task_id") or "").strip()
        if not task_id:
            continue
        try:
            task = task_status(task_id)
        except Exception as exc:  # noqa: BLE001
            logger.debug("[plus] 任务状态查询失败 %s: %s", task_id, exc)
            continue
        result = task.get("result") or {}
        activated = _is_activated(task) or int(row.get("activated") or 0) == 1
        db.upsert_plus_activation(
            row["email"],
            task_id=task_id,
            status=str(task.get("status") or ""),
            plus_status=str(task.get("plusVerificationStatus") or ""),
            progress=int(task.get("progressPercent") or 0),
            checkout_url=str(result.get("hostedUrl") or row.get("checkout_url") or ""),
            payment_status=str(result.get("paymentStatus") or row.get("payment_status") or ""),
            activated=1 if activated else 0,
            detail_json=json.dumps(task, ensure_ascii=False)[:4000],
        )
        updated += 1
        hits += 1 if activated else 0

    return {
        "ok": True,
        "updated": updated,
        "activated": db.count_plus_activated(),
        "activated_hits": hits,
    }


def queue_for_approval(email: str, *, reason: str = "trial_eligible") -> dict:
    """命中试用先排队等授权：只落状态，不发任何提炼 / 支付请求。"""
    email = (email or "").strip().lower()
    if not email:
        return {"ok": False, "error": "empty email"}
    db.upsert_plus_activation(
        email,
        status="pending_approval",
        plus_status="awaiting_authorization",
        progress=0,
        activated=0,
        detail_json=json.dumps(
            {
                "queued_at": time.time(),
                "reason": reason,
                "note": "等待主人授权后再提交提炼 + 支付",
            },
            ensure_ascii=False,
        ),
    )
    logger.info("[plus] 命中试用已排队等待授权 email=%s", email)
    return {"ok": True, "pending": True}


def auto_submit_if_eligible(email: str, access_token: str) -> Optional[dict]:
    """命中试用后的唯一入口：默认只排队等主人授权，授权后才真正提交。

    · plus_auto_submit=0 → 整个 Plus 流程关掉；
    · plus_require_approval=1（默认）→ 落 pending_approval，等 /api/plus/approve；
    · plus_require_approval=0 → 回到全自动直接提交。
    去重：已有 task_id 或已 activated 的号不再重复提交，避免白扣 CDK 次数。
    """
    if not _setting_flag("plus_auto_submit", "1"):
        return None
    email = (email or "").strip().lower()
    token = (access_token or "").strip()
    if not email:
        return None
    existing = db.get_plus_activation(email)
    if existing and ((existing.get("task_id") or "").strip() or int(existing.get("activated") or 0) == 1):
        return None
    if require_approval():
        if existing and str(existing.get("status") or "") == "pending_approval":
            return None
        return queue_for_approval(email)
    if not token:
        return None
    try:
        task = submit_one(token, email=email)
    except Exception as exc:  # noqa: BLE001
        logger.warning("[plus] 自动开通提交失败 %s: %s", email, exc)
        return {"ok": False, "error": str(exc)[:200]}
    cfg = config()
    db.upsert_plus_activation(
        email,
        task_id=task.get("taskId") or "",
        checkout_cdk=cfg["checkout_cdk"],
        payment_cdk=cfg["payment_cdk"],
        provider=cfg["provider"],
        payment_method=cfg["payment_method"],
        status=str(task.get("status") or ""),
        plus_status=str(task.get("plusVerificationStatus") or ""),
        progress=int(task.get("progressPercent") or 0),
        detail_json=json.dumps(task, ensure_ascii=False)[:4000],
    )
    logger.info("[plus] 命中试用已自动提交开通任务 email=%s task=%s", email, task.get("taskId"))
    return {"ok": True, "task_id": task.get("taskId")}


def approve_many(emails: Iterable[str]) -> dict:
    """主人授权后逐个提交「提炼 + 支付」（服务是单 token 一任务）。"""
    cfg = config()
    results = []
    for raw in emails:
        email = (raw or "").strip().lower()
        if not email:
            continue
        row = db.get_plus_activation(email) or {}
        if (row.get("task_id") or "").strip() or int(row.get("activated") or 0) == 1:
            results.append({"email": email, "ok": False, "error": "已提交过，跳过"})
            continue
        cred = db.get_registered(email)
        token = ((cred or {}).get("access_token") or "").strip()
        if not token:
            results.append({"email": email, "ok": False, "error": "本地没有 access_token"})
            continue
        try:
            task = submit_one(token, email=email)
        except Exception as exc:  # noqa: BLE001
            results.append({"email": email, "ok": False, "error": str(exc)[:200]})
            db.upsert_plus_activation(
                email,
                status="pending_approval",
                detail_json=json.dumps(
                    {"error": str(exc)[:400], "failed_at": time.time()},
                    ensure_ascii=False,
                ),
            )
            continue
        db.upsert_plus_activation(
            email,
            task_id=task.get("taskId") or "",
            checkout_cdk=cfg["checkout_cdk"],
            payment_cdk=cfg["payment_cdk"],
            provider=cfg["provider"],
            payment_method=cfg["payment_method"],
            status=str(task.get("status") or "SUBMITTED"),
            plus_status=str(task.get("plusVerificationStatus") or ""),
            progress=int(task.get("progressPercent") or 0),
            detail_json=json.dumps(task, ensure_ascii=False)[:4000],
        )
        logger.info("[plus] 授权后已提交 email=%s task=%s", email, task.get("taskId"))
        results.append({"email": email, "ok": True, "task_id": task.get("taskId")})
    ok = sum(1 for r in results if r.get("ok"))
    return {
        "ok": True, "total": len(results), "succeeded": ok,
        "failed": len(results) - ok, "results": results,
    }


def reject_many(emails: Iterable[str]) -> dict:
    """主人拒绝：只落状态，不发任何请求。"""
    rejected = 0
    for raw in emails:
        email = (raw or "").strip().lower()
        if not email:
            continue
        db.upsert_plus_activation(
            email,
            status="rejected",
            plus_status="rejected_by_owner",
            progress=0,
            activated=0,
        )
        rejected += 1
    return {"ok": True, "rejected": rejected}


def submit_many(emails: Iterable[str]) -> dict:
    """批量提交：逐个 access_token 调服务（服务是单 token 一任务）。"""
    cfg = config()
    results = []
    for raw in emails:
        email = (raw or "").strip().lower()
        if not email:
            continue
        cred = db.get_registered(email)
        token = (cred or {}).get("access_token") or ""
        if not token:
            results.append({"email": email, "ok": False, "error": "本地没有 access_token"})
            continue
        try:
            task = submit_one(token, email=email)
            db.upsert_plus_activation(
                email,
                task_id=task.get("taskId") or "",
                checkout_cdk=cfg["checkout_cdk"],
                payment_cdk=cfg["payment_cdk"],
                provider=cfg["provider"],
                payment_method=cfg["payment_method"],
                status=str(task.get("status") or ""),
                plus_status=str(task.get("plusVerificationStatus") or ""),
                progress=int(task.get("progressPercent") or 0),
                detail_json=json.dumps(task, ensure_ascii=False)[:4000],
            )
            results.append({"email": email, "ok": True, "task_id": task.get("taskId")})
        except Exception as exc:  # noqa: BLE001
            results.append({"email": email, "ok": False, "error": str(exc)[:200]})
    ok = sum(1 for r in results if r.get("ok"))
    return {
        "ok": True, "total": len(results), "succeeded": ok,
        "failed": len(results) - ok, "results": results,
    }
