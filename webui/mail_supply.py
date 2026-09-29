"""ReMail(remail.aishop6.com) 自动供号：邮箱池空了自动下单买 iCloud 邮箱。

接口（2026-09-27 用主人给的 key 实测 + /openapi.json 核对）：
  · GET  /v1/open/apikey/profile        查 key 状态与余额
  · GET  /v1/open/orders                查已购订单（active = 还在收件窗口内）
  · POST /v1/open/orders                单买 1 个（serviceMode=purchase）
  · POST /v1/open/orders/batch          批量买 2~100 个
  · GET  /v1/pickup?email=&token=       取件读信（用订单里的 serviceToken）

订单里直接带 deliveryEmail + serviceToken，拼成
``https://remail.aishop6.com/pickup?email=..&token=st_..`` 就是号池那行能直接用的
中转链接（icloud_relay provider 已支持这个格式）。
"""
from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from datetime import datetime
from typing import Any, Iterable, Optional

from curl_cffi import requests as cffi_requests

from . import db

logger = logging.getLogger("webui.mail_supply")

BASE = "https://remail.aishop6.com"
PICKUP_BASE = f"{BASE}/pickup"
DEFAULT_API_KEY = "rk-265789bc-057b-434e-b005-9e76ffad8ca4"
DEFAULT_PROJECT_ID = 2          # chatgpt
DEFAULT_SUFFIX = "icloud.com"
DEFAULT_BATCH_SIZE = 20
DEFAULT_MIN_AVAILABLE = 5
MIN_ORDER_QUANTITY = 2
MAX_ORDER_QUANTITY = 100

_refill_lock = threading.Lock()
_last_refill_at = 0.0


class MailSupplyError(RuntimeError):
    """供号接口失败。"""


def _setting(key: str, default: str) -> str:
    try:
        return (db.get_setting(key, default) or default).strip()
    except Exception:  # noqa: BLE001
        return default


def _flag(key: str, default: bool) -> bool:
    raw = _setting(key, "1" if default else "0").lower()
    return raw in ("1", "true", "yes", "on")


def config() -> dict:
    try:
        batch_size = int(_setting("remail_batch_size", str(DEFAULT_BATCH_SIZE)))
    except ValueError:
        batch_size = DEFAULT_BATCH_SIZE
    try:
        min_available = int(_setting("remail_min_available", str(DEFAULT_MIN_AVAILABLE)))
    except ValueError:
        min_available = DEFAULT_MIN_AVAILABLE
    try:
        project_id = int(_setting("remail_project_id", str(DEFAULT_PROJECT_ID)))
    except ValueError:
        project_id = DEFAULT_PROJECT_ID
    return {
        "api_key": _setting("remail_api_key", DEFAULT_API_KEY),
        "project_id": project_id,
        "email_suffix": _setting("remail_email_suffix", DEFAULT_SUFFIX),
        "auto_buy": _flag("remail_auto_buy", True),
        "batch_size": max(MIN_ORDER_QUANTITY, min(MAX_ORDER_QUANTITY, batch_size)),
        "min_available": max(0, min(1000, min_available)),
        "service_mode": _setting("remail_service_mode", "purchase") or "purchase",
        "supply": _setting("remail_supply", "private_first") or "private_first",
    }


def _session():
    session = cffi_requests.Session(impersonate="chrome")
    session.trust_env = False
    return session


def _request(
    method: str,
    path: str,
    *,
    params: Optional[dict] = None,
    json_body: Optional[dict] = None,
    timeout: int = 45,
    idempotent: bool = False,
) -> Any:
    cfg = config()
    headers = {
        "X-API-Key": cfg["api_key"],
        "Accept": "application/json",
    }
    if json_body is not None:
        headers["Content-Type"] = "application/json"
    if idempotent:
        headers["Idempotency-Key"] = str(uuid.uuid4())
    session = _session()
    try:
        resp = session.request(
            method,
            BASE + path,
            params=params or {},
            headers=headers,
            json=json_body,
            timeout=timeout,
        )
        text = resp.text or ""
        if resp.status_code >= 400:
            message = text[:200]
            try:
                message = (resp.json() or {}).get("message") or message
            except Exception:  # noqa: BLE001
                pass
            raise MailSupplyError(f"ReMail {method} {path} -> HTTP {resp.status_code}: {message}")
        return resp.json() if text.strip() else {}
    except MailSupplyError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise MailSupplyError(f"ReMail {method} {path} 请求失败: {str(exc)[:160]}") from exc
    finally:
        try:
            session.close()
        except Exception:  # noqa: BLE001
            pass


def profile() -> dict:
    """查 key 状态与余额。"""
    data = _request("GET", "/v1/open/apikey/profile", timeout=30)
    return data.get("apiKey") or data


def balance() -> float:
    try:
        return float(profile().get("balance") or 0)
    except Exception:  # noqa: BLE001
        return 0.0


def _pickup_url(email: str, token: str) -> str:
    return f"{PICKUP_BASE}?email={email}&token={token}"


def order_to_row(order: dict) -> Optional[dict]:
    """订单 → 号池导入行（email----中转链接）。缺投递信息返回 None。"""
    email = str(order.get("deliveryEmail") or "").strip().lower()
    token = str(order.get("serviceToken") or "").strip()
    if not email or not token:
        return None
    return {
        "email": email,
        "kind": "icloud_relay",
        "relay_url": _pickup_url(email, token),
    }


def active_orders(limit: int = 100) -> list[dict]:
    data = _request(
        "GET",
        "/v1/open/orders",
        params={"status": "active", "limit": max(1, min(100, int(limit)))},
        timeout=45,
    )
    if isinstance(data, list):
        return data
    return data.get("items") or []


def order_detail(order_no: str) -> dict:
    """订单详情：比列表多 serviceToken / verificationCode，取件必须用详情。"""
    return _request("GET", f"/v1/open/orders/{order_no}", timeout=30) or {}


def _order_expired(order: dict) -> bool:
    raw = str(order.get("receiveUntil") or "").strip()
    if not raw:
        return False
    try:
        stamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return False
    if stamp.tzinfo is None:
        return False
    return stamp.timestamp() < time.time()


def import_rows(rows: Iterable[dict]) -> dict:
    """把订单行按 icloud_relay 格式写进号池。"""
    lines = [
        f"{row['email']}----{row['relay_url']}"
        for row in rows
        if row and row.get("email") and row.get("relay_url")
    ]
    if not lines:
        return {"parsed": 0, "inserted": 0, "updated": 0, "skipped": 0}
    return db.import_accounts("\n".join(lines), kind="icloud_relay")


def import_active_orders(limit: int = 100) -> dict:
    """把还没过收件窗口的已购邮箱免费导入号池。"""
    try:
        orders = active_orders(limit=limit)
    except MailSupplyError as exc:
        return {"ok": False, "error": str(exc), "orders": 0, "inserted": 0}
    rows = []
    skipped_expired = 0
    for order in orders:
        if _order_expired(order):
            skipped_expired += 1
            continue
        row = order_to_row(order)
        # 列表接口不带 serviceToken（实测），得回查一次详情才拿得到取件 token。
        if row is None and order.get("orderNo"):
            try:
                row = order_to_row(order_detail(str(order["orderNo"])))
            except MailSupplyError as exc:
                logger.warning("[mail_supply] 订单详情查询失败 %s: %s", order.get("orderNo"), exc)
        if row:
            rows.append(row)
    result = import_rows(rows)
    return {
        "ok": True,
        "orders": len(orders),
        "expired": skipped_expired,
        "usable": len(rows),
        **result,
    }


def buy(quantity: Optional[int] = None) -> list[dict]:
    """下单买邮箱：1 个走单买接口，2~100 走批量接口。"""
    cfg = config()
    try:
        wanted = int(quantity if quantity is not None else cfg["batch_size"])
    except (TypeError, ValueError):
        wanted = cfg["batch_size"]
    wanted = max(1, min(MAX_ORDER_QUANTITY, wanted))
    body = {"projectId": cfg["project_id"], "emailSuffix": cfg["email_suffix"]}
    if wanted == 1:
        order = _request(
            "POST",
            "/v1/open/orders",
            params={"serviceMode": cfg["service_mode"], "supply": cfg["supply"]},
            json_body=body,
            timeout=90,
            idempotent=True,
        )
        orders = [order] if isinstance(order, dict) else list(order or [])
    else:
        orders = _request(
            "POST",
            "/v1/open/orders/batch",
            params={"serviceMode": cfg["service_mode"], "supply": cfg["supply"]},
            json_body={**body, "quantity": wanted},
            timeout=180,
            idempotent=True,
        )
        if isinstance(orders, dict):
            orders = orders.get("items") or orders.get("orders") or []
    out = []
    for item in orders:
        if not isinstance(item, dict):
            continue
        # 批量下单返回的是 {index, status, order:{...}} 包装（OpenAPI 里的
        # CreateOrderBatchItemResponse）——之前直接把包装当订单读，取不到
        # deliveryEmail/serviceToken，结果「买 20 个、入库 0 个」白扣 1200。
        nested = item.get("order") if isinstance(item.get("order"), dict) else None
        if str(item.get("status") or "").lower() == "failed" and not (
            nested or {}
        ).get("deliveryEmail"):
            logger.warning(
                "[mail_supply] 批量下单有条目失败: %s",
                json.dumps(item.get("error") or {}, ensure_ascii=False)[:160],
            )
            continue
        order = dict(nested or item)
        if not order.get("serviceToken") and order.get("orderNo"):
            try:
                order.update(order_detail(str(order["orderNo"])))
            except MailSupplyError as exc:
                logger.warning(
                    "[mail_supply] 下单后取详情失败 %s: %s", order.get("orderNo"), exc
                )
        out.append(order)
    logger.info(
        "[mail_supply] 已下单 %s 个邮箱（请求 %s 个，含取件凭证 %s 个），余额约 %s",
        len(out),
        wanted,
        sum(1 for order in out if order.get("serviceToken") and order.get("deliveryEmail")),
        balance(),
    )
    return out


def refill(quantity: Optional[int] = None, *, reason: str = "", force: bool = False) -> dict:
    """补货：先免费导入已购 active 订单，不够再下单买新的。

    force=False 时只在号池可用数低于阈值（min_available）才动手；
    并发调用由 _refill_lock 串行化，避免 20 个 worker 同时下单。
    """
    global _last_refill_at
    cfg = config()
    if not cfg["api_key"]:
        return {"ok": False, "error": "没有配置 ReMail API Key"}
    with _refill_lock:
        available = int(db.stats().get("available") or 0)
        if not force and available > cfg["min_available"]:
            return {"ok": True, "skipped": True, "available": available}
        if not force and time.time() - _last_refill_at < 30:
            return {"ok": True, "skipped": True, "reason": "冷却中", "available": available}

        imported = import_active_orders()
        available = int(db.stats().get("available") or 0)
        if available > cfg["min_available"]:
            _last_refill_at = time.time()
            return {
                "ok": True,
                "bought": 0,
                "imported": imported.get("inserted", 0) + imported.get("updated", 0),
                "available": available,
                "source": "existing_orders",
            }
        if not cfg["auto_buy"]:
            return {
                "ok": False,
                "error": "自动下单已关闭，且已购订单不足",
                "available": available,
                "imported": imported.get("inserted", 0),
            }

        orders = buy(quantity)
        rows = [row for row in (order_to_row(order) for order in orders) if row]
        if orders and not rows:
            # 花了钱却没有任何可取件凭证：立刻停下并进冷却，绝不再买第二批
            # （历史事故：批量响应包装没拆，连买两批 2400 全部没入库）。
            _last_refill_at = time.time()
            logger.error(
                "[mail_supply] 下单 %s 个但凭证据解析为 0（未入库），进入冷却避免重复扣费",
                len(orders),
            )
            return {
                "ok": False,
                "error": f"下单 {len(orders)} 个但没解析出取件凭证（未入库，已在冷却中）",
                "bought": len(orders),
                "imported": 0,
                "available": available,
                "balance": balance(),
            }
        result = import_rows(rows)
        _last_refill_at = time.time()
        available = int(db.stats().get("available") or 0)
        logger.info(
            "[mail_supply] 补货完成（%s）：买 %s 个、入库 %s 个，可用 %s",
            reason or "-",
            len(orders),
            result.get("inserted", 0) + result.get("updated", 0),
            available,
        )
        return {
            "ok": True,
            "bought": len(orders),
            "imported": result.get("inserted", 0) + result.get("updated", 0),
            "available": available,
            "source": "purchased",
            "balance": balance(),
        }


def status() -> dict:
    """给 WebUI 用的状态：配置 + 余额 + 已购订单 + 当前可用号。"""
    cfg = config()
    out: dict = {"config": cfg, "available": int(db.stats().get("available") or 0)}
    try:
        info = profile()
        out["balance"] = info.get("balance")
        out["key_name"] = info.get("name")
        out["key_enabled"] = info.get("enabled")
    except Exception as exc:  # noqa: BLE001
        out["error"] = str(exc)[:200]
    try:
        orders = active_orders()
        out["active_orders"] = len(orders)
        out["usable_orders"] = sum(1 for o in orders if not _order_expired(o))
    except Exception as exc:  # noqa: BLE001
        out.setdefault("error", str(exc)[:200])
    return out
