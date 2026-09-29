"""SQLite 号池 + 注册结果存储。

表结构：
  outlook_accounts: 接码号池（多种邮箱混放，kind 列区分 + 状态机）
  registered:       注册成功结果（凭证 JSON）

关于 outlook_accounts 这个表名：
    它现在装的不止 outlook（还有 gmail / icloud / qq ...），名字已经不准，
    但改表名要动迁移和一堆 SQL，收益只是好看一点，风险不值。
    真正区分类型的是 kind 列。

凭证字段用「并集列」而不是 extra_json：
    outlook/gmail 用 password+client_id+refresh_token，
    icloud 这类中转只用 relay_url，各自把不用的列留空。
    几种邮箱的规模下，并集列比 JSON 好 —— 能建索引、能加约束、
    SQL 里直接看得见。加新邮箱时如果要新字段，就再 ALTER 加一列。
"""
from __future__ import annotations

import base64
import json
import sqlite3
import sys
import threading
import time
from pathlib import Path
from typing import Any, Mapping, Optional

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

DB_PATH = Path(__file__).resolve().parent / "webui.db"

_lock = threading.Lock()  # SQLite 写入串行化


def _conn() -> sqlite3.Connection:
    con = sqlite3.connect(str(DB_PATH), check_same_thread=False, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    return con


def init_db():
    con = _conn()
    con.executescript("""
        CREATE TABLE IF NOT EXISTS outlook_accounts (
            email           TEXT PRIMARY KEY,
            password        TEXT,
            client_id       TEXT,
            refresh_token   TEXT,
            relay_url       TEXT,       -- 中转取码 URL（icloud 类用，其余留空）
            kind            TEXT NOT NULL DEFAULT 'outlook',
                            -- 邮箱类型，对应 mail_providers 注册表的 kind
            status          TEXT NOT NULL DEFAULT 'available',
                            -- available / in_use / done / failed
            imported_at     REAL,
            claimed_at      REAL,
            finished_at     REAL,
            fail_reason     TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_outlook_status ON outlook_accounts(status);
        -- idx_outlook_kind 不在这里建：老库此刻还没有 kind 列，
        -- 建索引会当场报错。放到下面补完列之后再建。

        CREATE TABLE IF NOT EXISTS settings (
            key     TEXT PRIMARY KEY,
            value   TEXT
        );

        CREATE TABLE IF NOT EXISTS registered (
            email           TEXT PRIMARY KEY,
            password        TEXT,
            access_token    TEXT,
            session_token   TEXT,
            refresh_token   TEXT,
            id_token        TEXT,
            device_id       TEXT,
            csrf_token      TEXT,
            cookie_header   TEXT,
            totp_secret     TEXT,
            totp_factor_id  TEXT,
            extra_json      TEXT,
            created_at      REAL
        );

        CREATE TABLE IF NOT EXISTS runs (
            run_id          TEXT PRIMARY KEY,
            email           TEXT,
            status          TEXT,        -- running / done / failed
            started_at      REAL,
            finished_at     REAL,
            log_path        TEXT,
            error           TEXT,
            error_category  TEXT,        -- network / account / unknown
            allocation_id    TEXT,
            proxy            TEXT,
            proxy_fingerprint TEXT,
            exit_ip          TEXT,
            exit_country     TEXT,
            country_code     TEXT,
            country_source   TEXT,
            browser_family   TEXT,
            browser_engine   TEXT,
            fingerprint_id   TEXT,
            fingerprint_signature TEXT,
            fingerprint_json TEXT,
            environment_json TEXT,
            runtime_observation_json TEXT,
            probe_json      TEXT
        );

        CREATE TABLE IF NOT EXISTS environment_ledger (
            allocation_id          TEXT PRIMARY KEY,
            run_id                 TEXT NOT NULL UNIQUE,
            proxy                  TEXT,
            proxy_fingerprint      TEXT NOT NULL,
            exit_ip                TEXT NOT NULL UNIQUE,
            exit_country           TEXT,
            country_code           TEXT,
            country_source         TEXT,
            browser_family         TEXT NOT NULL,
            browser_engine         TEXT NOT NULL,
            fingerprint_id         TEXT NOT NULL UNIQUE,
            fingerprint_signature  TEXT NOT NULL UNIQUE,
            fingerprint_json       TEXT NOT NULL,
            created_at             REAL NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_environment_created
            ON environment_ledger(created_at DESC);

        CREATE TABLE IF NOT EXISTS operation_probes (
            probe_id        INTEGER PRIMARY KEY AUTOINCREMENT,
            operation       TEXT NOT NULL,
            status          TEXT NOT NULL,
            timestamp       REAL NOT NULL,
            duration_ms     INTEGER,
            error           TEXT,
            error_category  TEXT,
            details_json    TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_operation_probes_time
            ON operation_probes(timestamp DESC, probe_id DESC);
        CREATE INDEX IF NOT EXISTS idx_operation_probes_operation
            ON operation_probes(operation, timestamp DESC, probe_id DESC);

        -- Plus 开通流水（提炼 + 支付）：一个邮箱一行，记录外部服务返回的
        -- taskId / 支付状态 / Plus 验证状态。注册结果页据此显示「已开通Plus」。
        CREATE TABLE IF NOT EXISTS plus_activations (
            email           TEXT PRIMARY KEY,
            task_id         TEXT,
            checkout_cdk    TEXT,
            payment_cdk     TEXT,
            provider        TEXT,
            payment_method  TEXT,
            status          TEXT,
            plus_status     TEXT,
            progress        INTEGER,
            checkout_url    TEXT,
            payment_status  TEXT,
            activated       INTEGER NOT NULL DEFAULT 0,
            submitted_at    REAL,
            updated_at      REAL,
            detail_json     TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_plus_activations_activated
            ON plus_activations(activated DESC, updated_at DESC);
    """)
    con.commit()
    # 老 DB migrate：error_category 在后期才加，对已建表补列
    cur = con.execute("PRAGMA table_info(runs)")
    cols = {r[1] for r in cur.fetchall()}
    if "error_category" not in cols:
        con.execute("ALTER TABLE runs ADD COLUMN error_category TEXT")
        con.commit()

    # Task environment columns were added after the original runs table. Keep
    # this migration idempotent so existing WebUI databases gain the ledger
    # metadata without losing their historical run rows.
    run_migrations = {
        "allocation_id": "TEXT",
        "proxy": "TEXT",
        "proxy_fingerprint": "TEXT",
        "exit_ip": "TEXT",
        "exit_country": "TEXT",
        "country_code": "TEXT",
        "country_source": "TEXT",
        "browser_family": "TEXT",
        "browser_engine": "TEXT",
        "fingerprint_id": "TEXT",
        "fingerprint_signature": "TEXT",
        "fingerprint_json": "TEXT",
        "environment_json": "TEXT",
        "runtime_observation_json": "TEXT",
        "probe_json": "TEXT",
        # 流量计数（2026-09-26 加）：本次任务通过 HTTP 会话收发的字节数。
        # 由 registrar 在任务收尾时写入，注册结果页用来显示「用了多少流量」。
        "traffic_rx": "INTEGER",
        "traffic_tx": "INTEGER",
    }
    for name, sql_type in run_migrations.items():
        if name not in cols:
            con.execute(f"ALTER TABLE runs ADD COLUMN {name} {sql_type}")
    con.commit()

    # 老 DB migrate：号池多邮箱混放（kind / relay_url 在后期才加）
    # 存量行全部是 outlook 时代导进去的，DEFAULT 'outlook' 正好把它们
    # 归位，不需要额外 UPDATE。重复执行无副作用。
    cur = con.execute("PRAGMA table_info(outlook_accounts)")
    acc_cols = {r[1] for r in cur.fetchall()}
    if "kind" not in acc_cols:
        con.execute(
            "ALTER TABLE outlook_accounts ADD COLUMN kind TEXT NOT NULL DEFAULT 'outlook'"
        )
        con.commit()
    if "relay_url" not in acc_cols:
        con.execute("ALTER TABLE outlook_accounts ADD COLUMN relay_url TEXT")
        con.commit()
    # 索引建在补列之后，否则老库上 CREATE INDEX 会因为没有 kind 列而失败
    con.execute(
        "CREATE INDEX IF NOT EXISTS idx_outlook_kind ON outlook_accounts(kind, status)"
    )
    con.commit()

    # 老 DB migrate：registered 的 2FA 两列（totp_secret / totp_factor_id）后期才加。
    # secret 一次性下发、服务端取不回，务必单独补列持久化。重复执行无副作用。
    cur = con.execute("PRAGMA table_info(registered)")
    reg_cols = {r[1] for r in cur.fetchall()}
    if "totp_secret" not in reg_cols:
        con.execute("ALTER TABLE registered ADD COLUMN totp_secret TEXT")
        con.commit()
    if "totp_factor_id" not in reg_cols:
        con.execute("ALTER TABLE registered ADD COLUMN totp_factor_id TEXT")
        con.commit()


# ──────────────────────── outlook 号池 ────────────────────────


def parse_lines(text: str, kind: str = "") -> list[dict]:
    """解析导入文本，委托给 mail_providers 注册表。

    kind 指定 → 用该 provider 的格式解析（推荐）
    kind 为空 → 按段数猜（段数唯一时才行，Outlook/Gmail 都是 4 段会猜不出）

    非法行抛 ImportValidationError（带行号和原因），**不再静默跳过**。
    以前这里是 `if len(parts) != 4: continue`，用户看到"导入成功"
    但号少了几个，完全没法排查。
    """
    from mail_providers import parse_import_text

    return parse_import_text(text or "", kind)


def import_accounts(text: str, kind: str = "") -> dict:
    """批量入库。已存在的 email 仅在凭证变化时更新。

    解析阶段全对才写：有一行非法就整批拒绝（抛 ImportValidationError），
    不会出现"写进去一半"对不上账的情况。
    """
    rows = parse_lines(text, kind)
    now = time.time()
    inserted = updated = skipped = 0
    with _lock:
        con = _conn()
        for r in rows:
            row_kind = r.get("kind") or kind or "outlook"
            # 凭证并集：不同 provider 用不同子集，没有的留空字符串
            password = r.get("password", "") or ""
            client_id = r.get("client_id", "") or ""
            refresh = r.get("refresh_token", "") or ""
            relay = r.get("relay_url", "") or ""

            cur = con.execute(
                "SELECT refresh_token, relay_url, kind FROM outlook_accounts WHERE email=?",
                (r["email"],),
            )
            existing = cur.fetchone()
            if existing is None:
                con.execute(
                    "INSERT INTO outlook_accounts(email, password, client_id, refresh_token, "
                    "relay_url, kind, status, imported_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, 'available', ?)",
                    (r["email"], password, client_id, refresh, relay, row_kind, now),
                )
                inserted += 1
            elif (
                (existing["refresh_token"] or "") != refresh
                or (existing["relay_url"] or "") != relay
                or (existing["kind"] or "") != row_kind
            ):
                # 凭证或类型变了 → 覆盖并重置为可用
                con.execute(
                    "UPDATE outlook_accounts SET refresh_token=?, password=?, client_id=?, "
                    "relay_url=?, kind=?, status='available', imported_at=?, fail_reason=NULL "
                    "WHERE email=?",
                    (refresh, password, client_id, relay, row_kind, now, r["email"]),
                )
                updated += 1
            else:
                skipped += 1
        con.commit()
    return {"parsed": len(rows), "inserted": inserted, "updated": updated, "skipped": skipped}


def count_accounts(status: str = "", kind: str = "", q: str = "") -> int:
    con = _conn()
    sql = "SELECT COUNT(*) FROM outlook_accounts"
    where, args = [], []
    if status:
        where.append("status=?")
        args.append(status)
    if kind:
        where.append("kind=?")
        args.append(kind.strip().lower())
    if q:
        like = f"%{q.strip().lower()}%"
        where.append(
            "(lower(email) LIKE ? OR lower(COALESCE(relay_url,'')) LIKE ?)"
        )
        args += [like, like]
    if where:
        sql += " WHERE " + " AND ".join(where)
    return con.execute(sql, args).fetchone()[0]


def list_accounts(
    status: str = "", limit: int = 50, offset: int = 0, kind: str = "", q: str = ""
) -> list[dict]:
    con = _conn()
    sql = "SELECT * FROM outlook_accounts"
    where, args = [], []
    if status:
        where.append("status=?")
        args.append(status)
    if kind:
        where.append("kind=?")
        args.append(kind.strip().lower())
    if q:
        like = f"%{q.strip().lower()}%"
        where.append(
            "(lower(email) LIKE ? OR lower(COALESCE(relay_url,'')) LIKE ?)"
        )
        args += [like, like]
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY imported_at DESC LIMIT ? OFFSET ?"
    args += [limit, offset]
    return [dict(r) for r in con.execute(sql, args).fetchall()]


def stats_by_kind() -> dict:
    """按邮箱类型分组统计，给 WebUI 顶部展示"每种邮箱各有多少号"。"""
    con = _conn()
    cur = con.execute(
        "SELECT kind, status, COUNT(*) AS n FROM outlook_accounts GROUP BY kind, status"
    )
    out: dict[str, dict] = {}
    for r in cur.fetchall():
        k = r["kind"] or "outlook"
        slot = out.setdefault(
            k, {"available": 0, "in_use": 0, "done": 0, "failed": 0, "total": 0}
        )
        slot[r["status"]] = r["n"]
        slot["total"] += r["n"]
    return out


def get_account(email: str) -> Optional[dict]:
    con = _conn()
    cur = con.execute("SELECT * FROM outlook_accounts WHERE email=?", (email.lower(),))
    row = cur.fetchone()
    return dict(row) if row else None


def claim_account(email: str) -> Optional[dict]:
    """原子 claim 指定邮箱（available / failed -> in_use）。

    failed 也允许重试 claim：之前 OpenAI 风控误判 / 网络抖动等导致 fail 的号
    应允许用户手动重试，已 done 的号才禁止重 claim（防误覆盖凭证）。

    按 email 指定时不过滤 kind —— 用户点名要这个号，它是什么类型
    由记录自己的 kind 列说了算，调用方读 account["kind"] 即可。
    """
    email = (email or "").strip().lower()
    if not email:
        return None
    with _lock:
        con = _conn()
        cur = con.execute(
            "SELECT * FROM outlook_accounts WHERE email=? AND status IN ('available', 'failed')",
            (email,),
        )
        row = cur.fetchone()
        if not row:
            return None
        rc = con.execute(
            "UPDATE outlook_accounts SET status='in_use', claimed_at=?, fail_reason=NULL "
            "WHERE email=? AND status IN ('available', 'failed')",
            (time.time(), email),
        )
        con.commit()
        if rc.rowcount != 1:
            return None
        return dict(row)


def _already_registered_without_password(con, email: str) -> bool:
    """历史上有成功注册记录、但本地已没有该邮箱的密码 → 不能再跑。

    场景：主人清空过「注册结果」，密码/2FA 随之丢失；池子里那些邮箱一旦被
    重置回 available，重跑只会撞 OpenAI 的「已有账号缺密码」，白烧一个邮箱。
    有密码（registered 行带 password）时不拦——那种重跑是合法的重登/补凭证。
    """
    key = (email or "").strip().lower()
    if not key:
        return False
    try:
        row = con.execute(
            "SELECT 1 FROM registered WHERE email=? AND length(coalesce(password,''))>0",
            (key,),
        ).fetchone()
        if row:
            return False
        done = con.execute(
            "SELECT 1 FROM runs WHERE lower(email)=? AND status='done' LIMIT 1",
            (key,),
        ).fetchone()
        return bool(done)
    except Exception:  # noqa: BLE001
        return False


def claim_next(kind: str = "") -> Optional[dict]:
    """原子 claim 任一 available 号。

    kind 指定 → 只从该类型里挑（"选了 gmail 就只跑 gmail 号"）
    kind 为空 → 全池子里挑最早导入的

    多类型混放的关键就在这里：号池里 outlook 和 gmail 并存，
    但当前配置选了哪种，就只 claim 哪种，不会串。
    """
    k = (kind or "").strip().lower()
    with _lock:
        con = _conn()
        for _ in range(50):  # 有限重试，避免并发抢号时无限递归爆栈
            if k:
                cur = con.execute(
                    "SELECT * FROM outlook_accounts WHERE status='available' AND kind=? "
                    "ORDER BY imported_at ASC LIMIT 1",
                    (k,),
                )
            else:
                cur = con.execute(
                    "SELECT * FROM outlook_accounts WHERE status='available' "
                    "ORDER BY imported_at ASC LIMIT 1"
                )
            row = cur.fetchone()
            if not row:
                return None
            # 防重复烧号：这个邮箱历史上已经注册成功过（runs.status='done'），
            # 但本地已经没有它的密码（注册结果被清空）→ 再跑必然撞
            # 「已有账号且缺密码」。直接判失败，换下一个，别浪费邮箱窗口。
            if _already_registered_without_password(con, row["email"]):
                con.execute(
                    "UPDATE outlook_accounts SET status='failed', finished_at=?, "
                    "fail_reason=? WHERE email=? AND status='available'",
                    (
                        time.time(),
                        "[account] 历史已注册成功但本地无密码（注册结果被清空）；"
                        "重跑必然撞「已有账号缺密码」，已跳过",
                        row["email"],
                    ),
                )
                con.commit()
                continue
            rc = con.execute(
                "UPDATE outlook_accounts SET status='in_use', claimed_at=? "
                "WHERE email=? AND status='available'",
                (time.time(), row["email"]),
            )
            con.commit()
            if rc.rowcount == 1:
                return dict(row)
            # 被别的线程抢走了，换下一个再试
        return None


def mark_done(email: str) -> None:
    with _lock:
        con = _conn()
        con.execute(
            "UPDATE outlook_accounts SET status='done', finished_at=?, fail_reason=NULL WHERE email=?",
            (time.time(), email.lower()),
        )
        con.commit()


def mark_failed(email: str, reason: str = "") -> None:
    with _lock:
        con = _conn()
        con.execute(
            "UPDATE outlook_accounts SET status='failed', finished_at=?, fail_reason=? WHERE email=?",
            (time.time(), (reason or "")[:500], email.lower()),
        )
        con.commit()


def release_unused(email: str) -> None:
    """claim 后没真注册（异常 / 用户取消）→ 还回 available。"""
    with _lock:
        con = _conn()
        con.execute(
            "UPDATE outlook_accounts SET status='available', claimed_at=NULL "
            "WHERE email=? AND status='in_use'",
            (email.lower(),),
        )
        con.commit()


def release_retryable(email: str, reason: str = "") -> None:
    """暂态失败（如中转 OTP 超时）→ 还回 available，但排到队尾。

    与 release_unused 的区别：保留 fail_reason 供诊断，并把 imported_at 推到
    当前时间，claim_next 按 imported_at ASC 取号，这个号会自然排到所有新号
    之后，稍后（号池转完一圈）再自动重试 —— "刷新后即可解决"的邮箱不该被
    永久隔离成 failed。
    """
    with _lock:
        con = _conn()
        con.execute(
            "UPDATE outlook_accounts SET status='available', claimed_at=NULL, "
            "fail_reason=?, imported_at=? "
            "WHERE email=? AND status IN ('in_use','failed')",
            ((reason or "")[:500], time.time(), email.lower()),
        )
        con.commit()


def reset_to_available(email: str) -> bool:
    """手动重置单个号：done / failed → available，清空时间戳和失败原因。

    场景：注册成功但 refresh_token 没拿到，主人想重新跑一遍这个号。
    """
    with _lock:
        con = _conn()
        rc = con.execute(
            "UPDATE outlook_accounts SET status='available', claimed_at=NULL, "
            "finished_at=NULL, fail_reason=NULL "
            "WHERE lower(email)=lower(?)",
            (email,),
        )
        con.commit()
        return rc.rowcount > 0


def bulk_reset_to_available(emails: list[str]) -> int:
    """批量重置多个号。返回实际被改的行数。"""
    if not emails:
        return 0
    with _lock:
        con = _conn()
        rc = con.execute(
            f"UPDATE outlook_accounts SET status='available', claimed_at=NULL, "
            f"finished_at=NULL, fail_reason=NULL "
            f"WHERE lower(email) IN ({','.join(['lower(?)'] * len(emails))})",
            emails,
        )
        con.commit()
        return rc.rowcount


def reset_failed_to_available() -> int:
    """把所有 failed 号一次性重置为 available（清掉 fail_reason）。返回受影响行数。

    场景：代理短暂抽风导致一波号被冤枉标 failed，主人想给它们一次机会。
    """
    with _lock:
        con = _conn()
        rc = con.execute(
            "UPDATE outlook_accounts SET status='available', fail_reason=NULL, "
            "finished_at=NULL WHERE status='failed'"
        )
        con.commit()
        return rc.rowcount


def release_stale_in_use(stale_seconds: float = 1800) -> int:
    """把 claimed_at 超过 N 秒还在 in_use 的号释放回 available。

    场景：上次 webui 强退/进程崩溃，号卡在 in_use 永远不释放。默认 30 分钟。
    """
    with _lock:
        con = _conn()
        cutoff = time.time() - stale_seconds
        rc = con.execute(
            "UPDATE outlook_accounts SET status='available', claimed_at=NULL "
            "WHERE status='in_use' AND (claimed_at IS NULL OR claimed_at < ?)",
            (cutoff,),
        )
        con.commit()
        return rc.rowcount


def interrupt_running_runs(reason: str = "") -> int:
    """把仍标为 running 的运行记录改成 interrupted。

    只在**进程启动时**调用：那一刻 DB 里还是 running 的，必然是上一个进程
    留下的 —— 进程都没了，任务不可能还在跑，但状态字段停在了 running，
    界面上会一直显示「运行中」，永远不会结束。2026-09-29 实测踩到：暂停批量
    任务后有 10 条记录卡在 running，配上对应号卡在 in_use，看起来像"还在跑"，
    实际早就停了，这让主人完全看不出真实进度。

    与 release_stale_in_use 是一对：那个放号，这个收尾运行记录。
    """
    with _lock:
        con = _conn()
        rc = con.execute(
            "UPDATE runs SET status='interrupted', finished_at=?, error=?, "
            "error_category='interrupted' WHERE status='running'",
            (time.time(), (reason or "进程重启，运行记录未正常收尾")[:500]),
        )
        con.commit()
        return rc.rowcount


def delete_account(email: str) -> bool:
    with _lock:
        con = _conn()
        rc = con.execute("DELETE FROM outlook_accounts WHERE email=?", (email.lower(),))
        con.commit()
        return rc.rowcount > 0


def delete_accounts_by_status(status: str) -> int:
    """按状态批量删除。status 必须是 available/in_use/done/failed 之一；
    传 'all' 删全部。返回受影响行数。"""
    valid = {"available", "in_use", "done", "failed", "all"}
    s = (status or "").strip().lower()
    if s not in valid:
        return 0
    with _lock:
        con = _conn()
        if s == "all":
            rc = con.execute("DELETE FROM outlook_accounts")
        else:
            rc = con.execute("DELETE FROM outlook_accounts WHERE status=?", (s,))
        con.commit()
        return rc.rowcount


def delete_accounts_by_emails(emails: list[str]) -> int:
    """按 email 列表批量删除。返回受影响行数。"""
    cleaned = [e.strip().lower() for e in (emails or []) if e and e.strip()]
    if not cleaned:
        return 0
    with _lock:
        con = _conn()
        placeholders = ",".join("?" * len(cleaned))
        rc = con.execute(
            f"DELETE FROM outlook_accounts WHERE email IN ({placeholders})",
            cleaned,
        )
        con.commit()
        return rc.rowcount


def stats() -> dict:
    con = _conn()
    cur = con.execute(
        "SELECT status, COUNT(*) AS n FROM outlook_accounts GROUP BY status"
    )
    out = {"available": 0, "in_use": 0, "done": 0, "failed": 0, "total": 0}
    for r in cur.fetchall():
        out[r["status"]] = r["n"]
        out["total"] += r["n"]

    # Plus eligibility is stored inside registered.extra_json. Parse the JSON
    # rather than matching a substring so unrelated metadata cannot inflate
    # the dashboard count.
    out["plus_eligible"] = 0
    for row in con.execute("SELECT extra_json FROM registered WHERE extra_json IS NOT NULL"):
        try:
            plus_check = json.loads(row["extra_json"] or "{}").get("plus_check") or {}
        except (TypeError, ValueError, AttributeError):
            continue
        if plus_check.get("status") == "plus_eligible":
            out["plus_eligible"] += 1
    return out


# ──────────────────────── 注册结果存储 ────────────────────────


def save_registered(d: dict) -> None:
    """保存注册成功（或部分成功）的凭证。覆盖同邮箱旧记录。

    凭证三件套（access_token / session_token / refresh_token）单独存列；
    其余字段（如 device_id / cookie_header / id_token / 自定义元数据）打包进 extra_json。
    """
    email = (d.get("email") or "").lower()
    if not email:
        return
    password = d.get("password", "") or ""
    extra = {k: v for k, v in d.items() if k not in {
        "email", "password", "access_token", "session_token", "refresh_token",
        "id_token", "device_id", "csrf_token", "cookie_header",
        "totp_secret", "totp_factor_id",
    }}
    with _lock:
        con = _conn()
        # ⚠️ INSERT OR REPLACE 是**整行替换**，不是按字段合并 —— 没写的列会被清空。
        #    重跑同一个邮箱时这会咬人：第一轮 register_password 设了密码但 OTP 超时，
        #    save_password_early 把密码存下了；第二轮 OpenAI 已经认识这个邮箱了，
        #    走 passwordless_login 分支根本不调 register_password，
        #    这一轮的 d["password"] 是空的 —— 直接 REPLACE 就把上一轮的密码冲没了。
        #    密码是 OpenAI 侧的**持久状态**，"这一轮没设" ≠ "这个号没有密码"，
        #    所以空值不覆盖非空旧值。
        #    token 三件套正相反：每轮跑都是全新的，旧的可能已失效，照常整列覆盖。
        # totp_secret 和密码同理，甚至更严：secret【一次性下发、服务端取不回】，
        #    丢了 = 该号 2FA 永久锁死。重跑同邮箱（已绑过 2FA）时这一轮不会再绑，
        #    d 里没有 secret —— 绝不能拿空值把库里已存的 secret 冲没。
        #    与密码合成一次 SELECT，顺带把两列旧值一起兜住。
        totp_secret = (d.get("totp_secret") or "").strip()
        totp_factor_id = (d.get("totp_factor_id") or "").strip()
        if not password or not totp_secret:
            row = con.execute(
                "SELECT password, totp_secret, totp_factor_id FROM registered WHERE email=?",
                (email,),
            ).fetchone()
            if row:
                if not password and (row["password"] or "").strip():
                    password = row["password"]
                if not totp_secret and (row["totp_secret"] or "").strip():
                    totp_secret = row["totp_secret"]
                    # factor_id 跟着 secret 走：本轮没绑就沿用旧的
                    totp_factor_id = totp_factor_id or (row["totp_factor_id"] or "")
        con.execute(
            "INSERT OR REPLACE INTO registered "
            "(email, password, access_token, session_token, refresh_token, "
            "id_token, device_id, csrf_token, cookie_header, "
            "totp_secret, totp_factor_id, extra_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                email,
                password,
                d.get("access_token", ""),
                d.get("session_token", ""),
                d.get("refresh_token", ""),
                d.get("id_token", ""),
                d.get("device_id", ""),
                d.get("csrf_token", ""),
                d.get("cookie_header", ""),
                totp_secret,
                totp_factor_id,
                json.dumps(extra, ensure_ascii=False) if extra else None,
                time.time(),
            ),
        )
        con.commit()


def update_registered_tokens(
    email: str,
    tokens: Mapping[str, Any],
    *,
    extra_meta: Optional[dict] = None,
) -> bool:
    """就地刷新已注册账号的凭证（重登用）。

    与 save_registered 的整行覆盖不同，这里**只动 token 相关列**：
      · created_at 保持注册时间不变（重登不是注册）；
      · password / totp_secret 不动（那是 OpenAI 侧的持久状态，重登不会重设）；
      · extra_json 做合并（保留 plus_check 等既有元数据）。
    返回是否命中行。
    """
    email = (email or "").strip().lower()
    if not email:
        return False
    with _lock:
        con = _conn()
        row = con.execute(
            "SELECT extra_json FROM registered WHERE email=?", (email,)
        ).fetchone()
        if not row:
            return False
        extra: dict = {}
        if row["extra_json"]:
            try:
                extra = json.loads(row["extra_json"]) or {}
            except Exception:
                extra = {}
        if extra_meta:
            extra.update(extra_meta)
        con.execute(
            "UPDATE registered SET access_token=?, session_token=?, refresh_token=?, "
            "id_token=?, device_id=?, csrf_token=?, cookie_header=?, extra_json=? "
            "WHERE email=?",
            (
                tokens.get("access_token", ""),
                tokens.get("session_token", ""),
                tokens.get("refresh_token", ""),
                tokens.get("id_token", ""),
                tokens.get("device_id", ""),
                tokens.get("csrf_token", ""),
                tokens.get("cookie_header", ""),
                json.dumps(extra, ensure_ascii=False) if extra else None,
                email,
            ),
        )
        con.commit()
        return True


def save_password_early(email: str, password: str) -> None:
    """密码一在 OpenAI 侧生效就落盘，不等整个注册流程跑完。

    由 AuthFlow 的 on_password 回调触发（register_password 里 POST 200 之后）。
    此刻账号+密码在 OpenAI 那边已经建好，但本地还要过发码/验证/建账户三关，
    挂在任何一关都走不到 save_registered ——
    密码只活在内存里，进程一退号就成了谁也登不进去的孤儿。

    只写 email + password；token 三件套留空，等流程跑通后 save_registered
    用同一个 email 主键覆盖同一行补上。extra_json 打 pending 标记，
    方便一眼认出"有密码没凭证"的半成品行（跑通后会被 save_registered 清掉）。

    ⚠️ 行已存在时**只 UPDATE password**，绝不动已有的 token：
       重跑一个之前跑通过的邮箱时，不能把人家的凭证清空。
    """
    email = (email or "").strip().lower()
    password = (password or "").strip()
    if not email or not password:
        return
    with _lock:
        con = _conn()
        con.execute(
            "INSERT INTO registered "
            "(email, password, access_token, session_token, refresh_token, "
            "id_token, device_id, csrf_token, cookie_header, extra_json, created_at) "
            "VALUES (?, ?, '', '', '', '', '', '', '', ?, ?) "
            "ON CONFLICT(email) DO UPDATE SET password=excluded.password",
            (
                email,
                password,
                json.dumps({"pending": True}, ensure_ascii=False),
                time.time(),
            ),
        )
        con.commit()


def save_totp_early(email: str, secret: str, factor_id: str = "") -> None:
    """2FA secret 一从 enroll 响应拿到就落盘，不等整个注册流程跑完。

    由 registrar 的 _bind_2fa_hook 触发（钩子在「拿到 session」和「Codex 授权 /
    绑手机号接码」之间调 bind_totp_2fa_inline，成功即拿到 secret）。

    ⚠️ 早落盘的理由和 save_password_early 一模一样、甚至更急：
       secret 绑成之后，流程还要走 Codex 授权 + add-phone 接码（可能好几分钟），
       这段时间 secret 只活在 registrar 内存的 _tfa_box 里。接码太久用户一关进程，
       secret 就永久蒸发 —— 而它【一次性下发、服务端取不回】，丢了该号 2FA 锁死。
       所以一拿到手就先写库，后面接码怎么中断都不怕。

    只写 totp 两列；token / 密码留给后续 save_registered 用同一 email 主键补齐。
    ⚠️ 行已存在时**只 UPDATE totp 两列**，绝不动已有的密码 / token
       —— 重跑老号时不能把人家已存的凭证清空。
    """
    email = (email or "").strip().lower()
    secret = (secret or "").strip()
    if not email or not secret:
        return
    factor_id = (factor_id or "").strip()
    with _lock:
        con = _conn()
        con.execute(
            "INSERT INTO registered "
            "(email, password, access_token, session_token, refresh_token, "
            "id_token, device_id, csrf_token, cookie_header, "
            "totp_secret, totp_factor_id, extra_json, created_at) "
            "VALUES (?, '', '', '', '', '', '', '', '', ?, ?, ?, ?) "
            "ON CONFLICT(email) DO UPDATE SET "
            "totp_secret=excluded.totp_secret, "
            "totp_factor_id=excluded.totp_factor_id",
            (
                email,
                secret,
                factor_id,
                json.dumps({"pending": True}, ensure_ascii=False),
                time.time(),
            ),
        )
        con.commit()


def normalize_totp_secret(raw: str) -> str:
    """把用户手填的 TOTP secret 规范化成可用的 base32，非法值抛 ValueError。

    登录侧（auth_flow._totp_now）拿到 secret 直接 b32decode，**不做任何校验** ——
    脏值存进去要等到真登录时才炸，那时只看到一句 base32 解码异常，
    根本看不出是手填填错了。所以校验必须挡在写库这一关。

    接受的输入：
      - 裸 base32:  JBSWY3DPEHPK3PXP / jbswy3dp ehpk 3pxp / JBSW-Y3DP-EHPK
      - otpauth URI: otpauth://totp/ChatGPT:a@b.com?secret=JBSWY3DP&issuer=...
        （从手机 App 导出/二维码解码出来的就是这个格式，直接粘进来很常见）
    """
    s = (raw or "").strip()
    if not s:
        return ""
    # otpauth:// URI 抽 secret 参数
    if s.lower().startswith("otpauth://"):
        try:
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(s).query)
            s = (qs.get("secret") or [""])[0]
        except Exception:
            raise ValueError("otpauth 链接解析失败，请直接填 secret")
        if not s:
            raise ValueError("otpauth 链接里没有 secret 参数")
    # 去掉分隔符（手机 App 展示时常带空格/连字符）并统一大写
    s = s.replace(" ", "").replace("-", "").replace("_", "").upper()
    # base32 只有 A-Z 和 2-7，先挡掉明显非法字符再解码，报错更好懂
    if not s or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=" for c in s):
        raise ValueError("TOTP secret 含非法字符（base32 只允许 A-Z 和 2-7）")
    try:
        # 补 padding 后试解，解得开才算合法。auth_flow 那边也是这么补的。
        decoded = base64.b32decode(s + "=" * (-len(s) % 8))
    except Exception:
        raise ValueError("TOTP secret 不是合法的 base32")
    if len(decoded) < 10:
        raise ValueError(f"TOTP secret 太短（解出 {len(decoded)} 字节，通常应为 20 字节）")
    return s


def update_registered_manual(email: str, password: Optional[str] = None,
                             totp_secret: Optional[str] = None) -> bool:
    """手动修正某个已注册账号的密码 / TOTP secret。

    ⚠️ 只改**本地库**，不会同步到 OpenAI —— 这里改密码不等于改了账号密码。
       用途是把外部已知的凭证补进来，或修正记录错误。

    传 None = 该字段不动（不是清空）。用 None 而不是空串做"不修改"的标记，
    是为了留出"主人真想清空某字段"的余地（传空串即清空）。

    totp_secret 会先过 normalize_totp_secret 校验，非法直接抛 ValueError；
    宁可这里报错，也不能让脏值躺进库里等登录时才炸。

    返回 False 表示该邮箱不存在（不会凭空插入新行 —— 手填是"修正已有记录"，
    真要新增外部账号是另一件事，走单独的导入功能）。
    """
    email = (email or "").strip().lower()
    if not email:
        return False
    sets, vals = [], []
    if password is not None:
        sets.append("password=?")
        vals.append(password)
    if totp_secret is not None:
        # 空串 = 主人主动清空；非空则必须过校验
        sets.append("totp_secret=?")
        vals.append(normalize_totp_secret(totp_secret) if totp_secret.strip() else "")
    if not sets:
        return False
    with _lock:
        con = _conn()
        row = con.execute("SELECT email FROM registered WHERE email=?", (email,)).fetchone()
        if not row:
            return False
        vals.append(email)
        con.execute(f"UPDATE registered SET {', '.join(sets)} WHERE email=?", vals)
        con.commit()
        return True


def update_plus_check(email: str, plus_info: dict) -> None:
    """把 Plus 检查结果写入 extra_json.plus_check。"""
    email = email.lower()
    con = _conn()
    cur = con.execute("SELECT extra_json FROM registered WHERE email=?", (email,))
    row = cur.fetchone()
    if not row:
        return
    extra = {}
    if row["extra_json"]:
        try:
            extra = json.loads(row["extra_json"])
        except Exception:
            extra = {}
    extra["plus_check"] = plus_info
    with _lock:
        con.execute(
            "UPDATE registered SET extra_json=? WHERE email=?",
            (json.dumps(extra, ensure_ascii=False), email),
        )
        con.commit()


def update_plus_check_countries(
    email: str, per_country: dict, best: Optional[dict] = None
) -> None:
    """把多国试用检测结果写进 extra_json.plus_check_countries。

    best 非空时同步覆盖 plus_check（列表页看到的是"最好那个国家"的结论）。
    """
    email = email.lower()
    con = _conn()
    cur = con.execute("SELECT extra_json FROM registered WHERE email=?", (email,))
    row = cur.fetchone()
    if not row:
        return
    extra = {}
    if row["extra_json"]:
        try:
            extra = json.loads(row["extra_json"])
        except Exception:
            extra = {}
    if not isinstance(extra, dict):
        extra = {}
    extra["plus_check_countries"] = per_country
    if best:
        extra["plus_check"] = best
    with _lock:
        con.execute(
            "UPDATE registered SET extra_json=? WHERE email=?",
            (json.dumps(extra, ensure_ascii=False), email),
        )
        con.commit()


def _registered_where(filt: str) -> str:
    if filt == "has_rt":
        return "WHERE length(refresh_token) > 0"
    if filt == "no_rt":
        return "WHERE coalesce(length(refresh_token),0) = 0"
    if filt == "unchecked":
        return "WHERE (extra_json IS NULL OR extra_json NOT LIKE '%\"plus_check\"%')"
    if filt == "free":
        return "WHERE extra_json LIKE '%\"free\"%'"
    if filt == "plus":
        return "WHERE (extra_json LIKE '%\"plus_eligible\"%' OR extra_json LIKE '%\"plus_active\"%')"
    if filt == "banned":
        return "WHERE extra_json LIKE '%\"banned\"%'"
    if filt == "token_invalid":
        # token_invalid 从 2026-08-10 起会写库，得能筛出来，否则等于埋了：
        # 它既不在 unchecked 里（已有结论），又不在 free/plus/banned 里。
        return "WHERE extra_json LIKE '%\"token_invalid\"%'"
    if filt == "plus_activated":
        # 已开通 Plus：本地开通流水里标记 activated=1 的号。
        # 用 r.email 限定，list/count 两条 SQL 都带 r 别名（见 count_registered）。
        return "WHERE r.email IN (SELECT email FROM plus_activations WHERE activated=1)"
    return ""


# 「完整凭证」判据：密码 + 2FA secret + access_token 三样齐全才算一个注册结果。
# 2026-09-29 主人定下的口径：缺任何一样的都是废物号，不能进注册结果。
# 但**行本身不能删**：password / totp_secret 是一次性下发的（服务端取不回），
# 早落盘的半成品行是这些号唯一的恢复凭证 —— 重跑走「已有账号」分支时要靠
# 它续跑。所以这里只在展示/导出层过滤，恢复路径（get_registered）照常可见。
_COMPLETE_CRED_SQL = (
    "(length(r.password) > 0 AND length(r.totp_secret) > 0 "
    "AND length(r.access_token) > 0)"
)


def _complete_registered_where(filt: str) -> str:
    base = _registered_where(filt)
    if base:
        return f"{base} AND {_COMPLETE_CRED_SQL}"
    return f"WHERE {_COMPLETE_CRED_SQL}"


def count_registered(filter_rt: str = "all") -> int:
    con = _conn()
    # 「已开通Plus」按开通流水计数（注册结果被删掉也要能统计到）
    if (filter_rt or "").strip() == "plus_activated":
        return con.execute(
            "SELECT COUNT(*) FROM plus_activations WHERE activated=1"
        ).fetchone()[0]
    # 带 r 别名：和 list_registered 用同一套 where 子句（有的过滤要 r.email）。
    # 只统计「完整凭证」的号：缺密码/2FA/AT 的半成品不是注册结果。
    cur = con.execute(
        f"SELECT COUNT(*) FROM registered r {_complete_registered_where(filter_rt)}"
    )
    return cur.fetchone()[0]


def list_registered(limit: int = 20, offset: int = 0, filter_rt: str = "all") -> list[dict]:
    con = _conn()
    # 「已开通Plus」以开通流水为主表：主人导出后会删注册结果，
    # 但开通记录不能跟着消失，否则这一页就空了（实测踩到）。
    # 所以 LEFT JOIN registered —— 凭证还在就带出来，删了就留空。
    if (filter_rt or "").strip() == "plus_activated":
        cur = con.execute(
            "SELECT p.email, r.password, r.totp_secret, "
            "length(r.access_token) AS at_len, length(r.session_token) AS st_len, "
            "length(r.refresh_token) AS rt_len, r.extra_json, r.created_at, "
            "a.kind AS mail_kind, "
            "p.task_id, p.status AS plus_flow_status, p.plus_status, "
            "p.payment_status, p.progress AS plus_progress, p.checkout_url, "
            "p.activated AS plus_activated, p.updated_at AS plus_updated_at "
            "FROM plus_activations p "
            "LEFT JOIN registered r ON r.email = p.email "
            "LEFT JOIN outlook_accounts a ON a.email = p.email "
            "WHERE p.activated = 1 "
            "ORDER BY p.updated_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        rows = []
        for r in cur.fetchall():
            d = dict(r)
            plus = None
            if d.get("extra_json"):
                try:
                    extra = json.loads(d["extra_json"])
                    plus = extra.get("plus_check")
                except Exception:
                    pass
            d["plus_check"] = plus
            d.pop("extra_json", None)
            rows.append(d)
        return rows

    where = _complete_registered_where(filter_rt)
    cur = con.execute(
        f"SELECT r.email, r.password, r.totp_secret, "
        f"length(r.access_token) AS at_len, length(r.session_token) AS st_len, "
        f"length(r.refresh_token) AS rt_len, r.extra_json, r.created_at, "
        f"a.kind AS mail_kind FROM registered r "
        f"LEFT JOIN outlook_accounts a ON a.email = r.email {where} "
        f"ORDER BY r.created_at DESC LIMIT ? OFFSET ?",
        (limit, offset),
    )
    rows = []
    for r in cur.fetchall():
        d = dict(r)
        plus = None
        if d.get("extra_json"):
            try:
                extra = json.loads(d["extra_json"])
                plus = extra.get("plus_check")
            except Exception:
                pass
        d["plus_check"] = plus
        d.pop("extra_json", None)
        rows.append(d)
    return rows


def list_registered_full(limit: int = 5000) -> list[dict]:
    """返回完整凭证（用于批量导出）。每行同 get_registered 的格式，外加 relay_url。

    ⚠️ relay_url（中转取件链接）**不在 registered 表里**，它跟着号池那一行走
       （outlook_accounts.relay_url，icloud_relay 这类号一号一条 token）。
       导出格式「邮箱----密码----2FA----取件url」要用它，所以这里 LEFT JOIN 带出来。
       用 JOIN 而不是给 registered 加列的原因：不用迁移、**已经注册完的老号也能导**
       （只要号池那行还在）；号池行被删掉就是空串，照约定留空、分隔符保留。
    """
    con = _conn()
    cur = con.execute(
        "SELECT r.*, a.relay_url AS relay_url "
        "FROM registered r LEFT JOIN outlook_accounts a ON a.email = r.email "
        f"WHERE {_COMPLETE_CRED_SQL} "
        "ORDER BY r.created_at DESC LIMIT ?",
        (limit,),
    )
    out = []
    for row in cur.fetchall():
        d = dict(row)
        if d.get("extra_json"):
            try:
                d["extra"] = json.loads(d["extra_json"])
            except Exception:
                d["extra"] = {}
        d.pop("extra_json", None)
        out.append(d)
    return out


def list_registered_by_emails(emails: list[str]) -> list[dict]:
    """按 email 列表返回完整凭证（批量导出勾选的号用）。

    - 行序 = created_at 倒序，和「注册结果」表格里看到的一致，方便核对。
    - 查不到的 email 直接不出现（号已被删掉的情况），不报错。
    - SQLite 单条语句变量数有上限（默认 999），所以分批查。
    - relay_url 从号池表 LEFT JOIN 带出（原因见 list_registered_full）。
    """
    cleaned = [e.strip().lower() for e in (emails or []) if e and e.strip()]
    if not cleaned:
        return []

    con = _conn()
    out = []
    CHUNK = 500
    for i in range(0, len(cleaned), CHUNK):
        part = cleaned[i:i + CHUNK]
        placeholders = ",".join("?" * len(part))
        cur = con.execute(
            f"SELECT r.*, a.relay_url AS relay_url "
            f"FROM registered r LEFT JOIN outlook_accounts a ON a.email = r.email "
            f"WHERE r.email IN ({placeholders}) AND {_COMPLETE_CRED_SQL}",
            part,
        )
        for row in cur.fetchall():
            d = dict(row)
            if d.get("extra_json"):
                try:
                    d["extra"] = json.loads(d["extra_json"])
                except Exception:
                    d["extra"] = {}
            d.pop("extra_json", None)
            out.append(d)

    out.sort(key=lambda d: d.get("created_at") or 0, reverse=True)
    return out


def get_registered(email: str) -> Optional[dict]:
    con = _conn()
    cur = con.execute("SELECT * FROM registered WHERE email=?", (email.lower(),))
    row = cur.fetchone()
    if not row:
        return None
    out = dict(row)
    if out.get("extra_json"):
        try:
            out["extra"] = json.loads(out["extra_json"])
        except Exception:
            out["extra"] = {}
    out.pop("extra_json", None)
    return out


def jwt_exp(token: str) -> int:
    """从 JWT 里取 exp（秒级时间戳）。取不到返回 0。"""
    parts = str(token or "").split(".")
    if len(parts) < 2:
        return 0
    try:
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
        return int(data.get("exp") or 0)
    except Exception:
        return 0


def update_run_traffic(run_id: str, rx: int, tx: int) -> None:
    """记录一次任务通过 HTTP 会话收发的字节数。"""
    with _lock:
        con = _conn()
        con.execute(
            "UPDATE runs SET traffic_rx=?, traffic_tx=? WHERE run_id=?",
            (int(rx or 0), int(tx or 0), str(run_id)),
        )
        con.commit()


# ──────────────────────── Plus 开通流水 ────────────────────────


def upsert_plus_activation(email: str, **fields: Any) -> None:
    """写入/更新一条 Plus 开通记录（只覆盖传入的字段）。"""
    email = (email or "").strip().lower()
    if not email:
        return
    allowed = {
        "task_id", "checkout_cdk", "payment_cdk", "provider", "payment_method",
        "status", "plus_status", "progress", "checkout_url", "payment_status",
        "activated", "submitted_at", "detail_json",
    }
    payload = {k: v for k, v in fields.items() if k in allowed}
    payload["updated_at"] = time.time()
    with _lock:
        con = _conn()
        row = con.execute(
            "SELECT email FROM plus_activations WHERE email=?", (email,)
        ).fetchone()
        if row:
            if payload:
                cols = ", ".join(f"{k}=?" for k in payload)
                con.execute(
                    f"UPDATE plus_activations SET {cols} WHERE email=?",
                    (*payload.values(), email),
                )
        else:
            payload["email"] = email
            payload.setdefault("submitted_at", time.time())
            payload["activated"] = int(payload.get("activated") or 0)
            cols = ", ".join(payload.keys())
            marks = ", ".join("?" for _ in payload)
            con.execute(
                f"INSERT INTO plus_activations ({cols}) VALUES ({marks})",
                tuple(payload.values()),
            )
        con.commit()


def get_plus_activation(email: str) -> Optional[dict]:
    con = _conn()
    row = con.execute(
        "SELECT * FROM plus_activations WHERE email=?",
        ((email or "").strip().lower(),),
    ).fetchone()
    return dict(row) if row else None


def list_plus_activations(limit: int = 2000) -> list[dict]:
    con = _conn()
    rows = con.execute(
        "SELECT * FROM plus_activations ORDER BY activated DESC, updated_at DESC LIMIT ?",
        (int(limit),),
    ).fetchall()
    return [dict(r) for r in rows]


def plus_activation_map() -> dict[str, dict]:
    """email → 开通记录，供注册结果页一次取全量做展示。"""
    return {row["email"]: row for row in list_plus_activations()}


def list_plus_pending_approval(limit: int = 500) -> list[dict]:
    """待主人授权的试用号（status=pending_approval，尚未提交任何开通任务）。

    registered 可能已被主人导出后删除，所以 LEFT JOIN：凭证还在就带出来，
    删了就只靠 plus_activations 的行（邮箱 + 排队时间）展示。
    """
    con = _conn()
    cur = con.execute(
        "SELECT p.email, p.status, p.plus_status, p.updated_at, p.detail_json, "
        "r.created_at AS registered_at, r.extra_json, "
        "(SELECT exit_country FROM runs WHERE runs.email = p.email "
        " ORDER BY started_at DESC LIMIT 1) AS exit_country "
        "FROM plus_activations p "
        "LEFT JOIN registered r ON r.email = p.email "
        "WHERE p.status = 'pending_approval' "
        "ORDER BY p.updated_at DESC LIMIT ?",
        (int(limit),),
    )
    return [dict(row) for row in cur.fetchall()]


def count_plus_pending_approval() -> int:
    con = _conn()
    return con.execute(
        "SELECT COUNT(*) FROM plus_activations WHERE status='pending_approval'"
    ).fetchone()[0]


def count_plus_activated() -> int:
    con = _conn()
    return con.execute(
        "SELECT COUNT(*) FROM plus_activations WHERE activated=1"
    ).fetchone()[0]


def latest_fingerprint(email: str) -> dict:
    """取该邮箱最近一次任务冻结的指纹画像。

    支付探测必须和注册时用同一套画像。换一套 UA / 客户端提示再去打
    checkout，等于告诉服务端「这不是刚才那个客户端」——而 0 元资格本来
    就和账号加设备的信任度绑在一起。取不到（老号没有 runs 记录）时返回
    空字典，调用方回落到默认画像。
    """
    key = (email or "").strip().lower()
    if not key:
        return {}
    con = _conn()
    row = con.execute(
        "SELECT fingerprint_json FROM runs "
        "WHERE lower(email)=? AND fingerprint_json IS NOT NULL "
        "ORDER BY started_at DESC LIMIT 1",
        (key,),
    ).fetchone()
    if not row or not row["fingerprint_json"]:
        return {}
    try:
        value = json.loads(row["fingerprint_json"])
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def registered_meta(emails: Optional[list[str]] = None) -> list[dict]:
    """注册结果页的轻量元数据：每个邮箱一行。

    数据来源：
      · runs（最近一次任务）—— 出口国家 / 出口 IP / 指纹版本 / 收发流量；
      · registered —— access_token 的 exp（用来显示 AT 剩余有效期）。

    刻意只回小字段（不含凭证、不含 probe JSON），列表页一次拉全量也不重。
    """
    con = _conn()
    out: dict[str, dict] = {}
    wanted = [str(e).strip().lower() for e in (emails or []) if str(e).strip()]
    where = "email IS NOT NULL AND email <> ''"
    params: list = []
    if wanted:
        placeholders = ",".join("?" for _ in wanted)
        where += f" AND lower(email) IN ({placeholders})"
        params = list(wanted)
    cur = con.execute(
        "SELECT email, exit_country, exit_ip, fingerprint_json, traffic_rx, traffic_tx, "
        f"started_at FROM runs WHERE {where} ORDER BY started_at DESC",
        tuple(params),
    )
    for r in cur.fetchall():
        key = (r["email"] or "").strip().lower()
        if not key or key in out:
            continue
        version = ""
        try:
            version = (json.loads(r["fingerprint_json"] or "{}") or {}).get("impersonate", "")
        except Exception:
            version = ""
        out[key] = {
            "email": key,
            "country": (r["exit_country"] or "").upper(),
            "exit_ip": r["exit_ip"] or "",
            "version": version,
            "traffic_rx": int(r["traffic_rx"] or 0),
            "traffic_tx": int(r["traffic_tx"] or 0),
            "last_run_at": r["started_at"],
            "at_exp": 0,
        }
    reg_where = "1=1"
    if wanted:
        placeholders = ",".join("?" for _ in wanted)
        reg_where = f"lower(email) IN ({placeholders})"
    for r in con.execute(
        f"SELECT email, access_token FROM registered WHERE {reg_where}", tuple(params)
    ):
        key = (r["email"] or "").strip().lower()
        if not key:
            continue
        item = out.setdefault(key, {
            "email": key, "country": "", "exit_ip": "", "version": "",
            "traffic_rx": 0, "traffic_tx": 0, "last_run_at": None, "at_exp": 0,
        })
        item["at_exp"] = jwt_exp(r["access_token"] or "")
    return list(out.values())


def checkout_summary() -> dict:
    """聚合支付能力探测结论（存在 registered.extra_json 的 plus_check.checkout 里）。

    只返回计数，不带任何凭证字段；注册结果页顶部用它显示「全库 N 个可 0 元领」。
    口径与前端 checkoutLabel 一致：有 failure_type 算探测失败，
    支付方式里没有 upi 算无 UPI，金额为 0 才算可领。
    """
    con = _conn()
    total = free = probed = failed = no_upi = unchecked = 0
    # 只统计「完整凭证」的号：半成品（缺密码/2FA/AT）不是注册结果，
    # 不该进汇总口径（与结果页、导出保持一致）。
    # 此查询无别名，条件直接写列名（与 _COMPLETE_CRED_SQL 同义）。
    for row in con.execute(
        "SELECT extra_json FROM registered WHERE "
        "length(password) > 0 AND length(totp_secret) > 0 AND length(access_token) > 0"
    ):
        total += 1
        checkout = None
        if row["extra_json"]:
            try:
                plus = (json.loads(row["extra_json"]) or {}).get("plus_check")
                if isinstance(plus, dict):
                    checkout = plus.get("checkout")
            except Exception:
                checkout = None
        if not checkout:
            unchecked += 1
            continue
        probed += 1
        if checkout.get("failure_type"):
            failed += 1
            continue
        methods = [str(m).lower() for m in (checkout.get("payment_methods") or [])]
        amount = checkout.get("amount_minor")
        if methods and "upi" not in methods:
            no_upi += 1
        elif amount is not None and float(amount) == 0:
            free += 1
    return {
        "total": total,
        "free": free,
        "probed": probed,
        "failed": failed,
        "no_upi": no_upi,
        "unchecked": unchecked,
    }


def email_in_use(email: str, *, exclude: str = "") -> bool:
    """Return whether an email already exists in either local email table."""
    email = (email or "").strip().lower()
    exclude = (exclude or "").strip().lower()
    if not email:
        return False
    con = _conn()
    registered_sql = "SELECT 1 FROM registered WHERE email=?"
    registered_args = [email]
    if exclude:
        registered_sql += " AND email<>?"
        registered_args.append(exclude)
    if con.execute(registered_sql, registered_args).fetchone():
        return True
    pool_sql = "SELECT 1 FROM outlook_accounts WHERE email=?"
    pool_args = [email]
    if exclude:
        pool_sql += " AND email<>?"
        pool_args.append(exclude)
    return con.execute(pool_sql, pool_args).fetchone() is not None


def complete_email_rebind(
    source_email: str,
    target_email: str,
    *,
    credential_updates: Optional[Mapping[str, Any]] = None,
    metadata: Optional[Mapping[str, Any]] = None,
) -> None:
    """Atomically move a registered row to its new email address."""
    source_email = (source_email or "").strip().lower()
    target_email = (target_email or "").strip().lower()
    if not source_email or not target_email or source_email == target_email:
        raise ValueError("换绑邮箱参数无效")

    allowed = {
        "password", "access_token", "session_token", "refresh_token", "id_token",
        "device_id", "csrf_token", "cookie_header", "totp_secret", "totp_factor_id",
    }
    updates = dict(credential_updates or {})
    with _lock:
        con = _conn()
        source = con.execute("SELECT * FROM registered WHERE email=?", (source_email,)).fetchone()
        if not source:
            raise ValueError("源账号注册记录不存在")
        if con.execute("SELECT 1 FROM registered WHERE email=?", (target_email,)).fetchone():
            raise ValueError("目标邮箱已存在注册记录")
        if con.execute("SELECT 1 FROM outlook_accounts WHERE email=?", (target_email,)).fetchone():
            raise ValueError("目标邮箱已存在邮箱池记录")

        extra = {}
        if source["extra_json"]:
            try:
                extra = json.loads(source["extra_json"])
            except (TypeError, ValueError):
                extra = {}
        if not isinstance(extra, dict):
            extra = {}
        extra["email_rebind"] = dict(metadata or {})

        values = {key: source[key] for key in allowed}
        for key in allowed:
            value = updates.get(key)
            if value:
                values[key] = value
        con.execute(
            "UPDATE registered SET email=?, password=?, access_token=?, session_token=?, "
            "refresh_token=?, id_token=?, device_id=?, csrf_token=?, cookie_header=?, "
            "totp_secret=?, totp_factor_id=?, extra_json=? WHERE email=?",
            (
                target_email,
                values["password"] or "",
                values["access_token"] or "",
                values["session_token"] or "",
                values["refresh_token"] or "",
                values["id_token"] or "",
                values["device_id"] or "",
                values["csrf_token"] or "",
                values["cookie_header"] or "",
                values["totp_secret"] or "",
                values["totp_factor_id"] or "",
                json.dumps(extra, ensure_ascii=False),
                source_email,
            ),
        )
        con.commit()


def delete_registered(email: str) -> bool:
    with _lock:
        con = _conn()
        rc = con.execute("DELETE FROM registered WHERE email=?", (email.lower(),))
        con.commit()
        return rc.rowcount > 0


def delete_registered_by_emails(emails: list[str]) -> int:
    cleaned = [e.strip().lower() for e in (emails or []) if e and e.strip()]
    if not cleaned:
        return 0
    with _lock:
        con = _conn()
        placeholders = ",".join("?" * len(cleaned))
        rc = con.execute(
            f"DELETE FROM registered WHERE email IN ({placeholders})",
            cleaned,
        )
        con.commit()
        return rc.rowcount


def delete_all_registered() -> int:
    with _lock:
        con = _conn()
        rc = con.execute("DELETE FROM registered")
        con.commit()
        return rc.rowcount


# ──────────────────────── 运行记录 ────────────────────────


def _environment_values(environment: Mapping[str, Any]) -> dict[str, Any]:
    """Flatten the stable environment fields used by runs and the ledger."""
    fingerprint = environment.get("fingerprint")
    if not isinstance(fingerprint, Mapping):
        fingerprint = {}
    fingerprint_json = json.dumps(fingerprint, ensure_ascii=False, sort_keys=True)
    environment_json = json.dumps(environment, ensure_ascii=False, sort_keys=True, default=str)
    return {
        "allocation_id": str(
            environment.get("allocation_id")
            or f"{environment.get('run_id', '')}:{environment.get('fingerprint_id', '')}"
        ),
        "proxy": str(environment.get("proxy") or ""),
        "proxy_fingerprint": str(environment.get("proxy_fingerprint") or "direct"),
        "exit_ip": str(environment.get("exit_ip") or ""),
        "exit_country": str(environment.get("exit_country") or ""),
        "country_code": str(environment.get("country_code") or ""),
        "country_source": str(environment.get("country_source") or "default"),
        "browser_family": str(
            environment.get("browser_family") or fingerprint.get("browser_family") or ""
        ),
        "browser_engine": str(environment.get("browser_engine") or "auto"),
        "fingerprint_id": str(
            environment.get("fingerprint_id") or fingerprint.get("fingerprint_id") or ""
        ),
        "fingerprint_signature": str(environment.get("fingerprint_signature") or ""),
        "fingerprint_json": fingerprint_json,
        "environment_json": environment_json,
    }


def environment_seen(
    *,
    exit_ip: str = "",
    fingerprint_id: str = "",
    fingerprint_signature: str = "",
) -> bool:
    """Return whether a value has already been reserved in historical records.

    Unique-ness is enforced against both the environment ledger and historical
    run rows: a task that frees its ledger entry (manual cleanup / pool switch)
    must still never reuse an exit IP or fingerprint that any earlier run
    already touched.
    """
    checks: list[str] = []
    values: list[str] = []
    for column, value in (
        ("exit_ip", exit_ip),
        ("fingerprint_id", fingerprint_id),
        ("fingerprint_signature", fingerprint_signature),
    ):
        value = str(value or "").strip()
        if value:
            checks.append(f"{column}=?")
            values.append(value)
    if not checks:
        return False
    con = _conn()
    for table in ("environment_ledger", "runs"):
        row = con.execute(
            f"SELECT 1 FROM {table} WHERE {' OR '.join(checks)} LIMIT 1",
            values,
        ).fetchone()
        if row is not None:
            return True
    return False


def reserve_environment(run_id: str, environment: Mapping[str, Any]) -> bool:
    """Atomically reserve an environment; uniqueness races return False."""
    values = _environment_values(environment)
    values["run_id"] = run_id
    if not values["exit_ip"] or not values["fingerprint_id"] or not values["fingerprint_signature"]:
        raise ValueError("environment reservation requires exit_ip, fingerprint_id and fingerprint_signature")
    with _lock:
        con = _conn()
        try:
            con.execute(
                "INSERT INTO environment_ledger "
                "(allocation_id, run_id, proxy, proxy_fingerprint, exit_ip, exit_country, "
                "country_code, country_source, browser_family, browser_engine, fingerprint_id, "
                "fingerprint_signature, fingerprint_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    values["allocation_id"],
                    values["run_id"],
                    values["proxy"],
                    values["proxy_fingerprint"],
                    values["exit_ip"],
                    values["exit_country"],
                    values["country_code"],
                    values["country_source"],
                    values["browser_family"],
                    values["browser_engine"],
                    values["fingerprint_id"],
                    values["fingerprint_signature"],
                    values["fingerprint_json"],
                    time.time(),
                ),
            )
            con.commit()
            return True
        except sqlite3.IntegrityError:
            con.rollback()
            return False


def update_run_environment(run_id: str, environment: Mapping[str, Any]) -> None:
    """Persist the frozen expected environment on its run row."""
    values = _environment_values(environment)
    with _lock:
        con = _conn()
        con.execute(
            "UPDATE runs SET allocation_id=?, proxy=?, proxy_fingerprint=?, exit_ip=?, "
            "exit_country=?, country_code=?, country_source=?, browser_family=?, "
            "browser_engine=?, fingerprint_id=?, fingerprint_signature=?, fingerprint_json=?, "
            "environment_json=? WHERE run_id=?",
            (
                values["allocation_id"],
                values["proxy"],
                values["proxy_fingerprint"],
                values["exit_ip"],
                values["exit_country"],
                values["country_code"],
                values["country_source"],
                values["browser_family"],
                values["browser_engine"],
                values["fingerprint_id"],
                values["fingerprint_signature"],
                values["fingerprint_json"],
                values["environment_json"],
                run_id,
            ),
        )
        con.commit()


def rebind_environment_exit(
    run_id: str, environment: Mapping[str, Any], *, old_exit_ip: str
) -> bool:
    """把一次任务的冻结出口改绑到「稳定观察到的新出口」（只在预检阶段调用）。

    背景（2026-09-29 实测）：分配时探测到的出口 A，与任务真正建连后连续两次探测到的
    出口 B 不同 —— 厂商把粘性会话重分配了，而两次都拿到 B 说明那同样是一条稳定路径。
    此刻任务**还没向 OpenAI 发出任何请求**（预检只打 cloudflare trace），把台账与运行行
    一起改绑到 B，任务就能继续跑；不改绑就是整单作废、号被 release 回池、白等一轮
    （20 并发启动那一波实测丢了 3 个任务）。

    两条不变量继续守住：
      - 任务间唯一：B 若已在台账/历史任务里出现过，直接返回 False（调用方照旧中止）；
      - 任务内唯一：改绑之后任务只用 B。A 从未对 OpenAI 用过，释放它不会污染任何人。
    """
    values = _environment_values(environment)
    new_ip = str(values.get("exit_ip") or "").strip()
    old_ip = str(old_exit_ip or "").strip()
    if not run_id or not new_ip or not old_ip or new_ip == old_ip:
        return False
    # 唯一性先查一遍，把常见情况挡在事务外；并发竞争由下面的 UNIQUE 约束兜底。
    if environment_seen(exit_ip=new_ip):
        return False
    with _lock:
        con = _conn()
        try:
            cur = con.execute(
                "UPDATE environment_ledger SET exit_ip=?, exit_country=? "
                "WHERE run_id=? AND exit_ip=?",
                (new_ip, values["exit_country"], run_id, old_ip),
            )
            if cur.rowcount != 1:
                # 台账里没有这一行（run_id/旧 IP 对不上）→ 不敢改，按原逻辑中止。
                con.rollback()
                return False
            con.execute(
                "UPDATE runs SET exit_ip=?, exit_country=?, environment_json=? "
                "WHERE run_id=? AND exit_ip=?",
                (new_ip, values["exit_country"], values["environment_json"], run_id, old_ip),
            )
            con.commit()
            return True
        except sqlite3.IntegrityError:
            con.rollback()
            return False


def get_run_environment(run_id: str) -> dict:
    """Return the stable environment summary for a run."""
    con = _conn()
    row = con.execute(
        "SELECT allocation_id, proxy, proxy_fingerprint, exit_ip, exit_country, "
        "country_code, country_source, browser_family, browser_engine, fingerprint_id, "
        "fingerprint_signature, fingerprint_json, environment_json, "
        "runtime_observation_json, probe_json FROM runs WHERE run_id=?",
        (run_id,),
    ).fetchone()
    if not row:
        return {}
    item = dict(row)
    for raw_key, decoded_key in (
        ("environment_json", "environment"),
        ("runtime_observation_json", "runtime_observation"),
        ("fingerprint_json", "fingerprint"),
        ("probe_json", "probes"),
    ):
        raw = item.pop(raw_key, None)
        if raw:
            try:
                item[decoded_key] = json.loads(raw)
            except (TypeError, ValueError):
                item[decoded_key] = {}
        else:
            item[decoded_key] = {}
    return item


def record_run_observation(run_id: str, observation: Mapping[str, Any]) -> None:
    """Store runtime browser values alongside the frozen expected profile."""
    payload = json.dumps(observation, ensure_ascii=False, sort_keys=True, default=str)
    with _lock:
        con = _conn()
        con.execute(
            "UPDATE runs SET runtime_observation_json=? WHERE run_id=?",
            (payload, run_id),
        )
        con.commit()


def record_run_probe(run_id: str, event: Mapping[str, Any]) -> None:
    """Append one redacted structured probe event to a run."""
    with _lock:
        con = _conn()
        row = con.execute(
            "SELECT probe_json FROM runs WHERE run_id=?", (run_id,)
        ).fetchone()
        events: list[dict] = []
        if row and row["probe_json"]:
            try:
                loaded = json.loads(row["probe_json"])
                if isinstance(loaded, list):
                    events = [item for item in loaded if isinstance(item, dict)]
            except (TypeError, ValueError):
                events = []
        events.append(dict(event))
        # Bound the history so a long-running task cannot grow the database
        # without limit. The latest events contain the actionable failure.
        events = events[-300:]
        con.execute(
            "UPDATE runs SET probe_json=? WHERE run_id=?",
            (json.dumps(events, ensure_ascii=False, sort_keys=True, default=str), run_id),
        )
        con.commit()


def get_run_probes(run_id: str) -> list[dict]:
    """Return the structured probe history for one run."""
    con = _conn()
    row = con.execute("SELECT probe_json FROM runs WHERE run_id=?", (run_id,)).fetchone()
    if not row or not row["probe_json"]:
        return []
    try:
        value = json.loads(row["probe_json"])
    except (TypeError, ValueError):
        return []
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


def record_operation_probe(event: Mapping[str, Any]) -> None:
    """Persist one already-redacted probe for an operation outside a run."""
    details = event.get("details")
    with _lock:
        con = _conn()
        try:
            con.execute(
                "INSERT INTO operation_probes(operation, status, timestamp, duration_ms, "
                "error, error_category, details_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    str(event.get("operation") or ""),
                    str(event.get("status") or ""),
                    float(event.get("timestamp") or time.time()),
                    event.get("duration_ms"),
                    event.get("error"),
                    event.get("error_category"),
                    json.dumps(details, ensure_ascii=False, sort_keys=True, default=str)
                    if details is not None else None,
                ),
            )
            con.commit()
        finally:
            con.close()


def list_operation_probes(limit: int = 100, operation: str = "") -> list[dict]:
    """Read recent persisted operation probes, newest event last."""
    limit = max(1, min(int(limit or 100), 500))
    where = ""
    args: list[Any] = []
    wanted = str(operation or "").strip()
    if wanted:
        where = " WHERE operation=?"
        args.append(wanted)
    con = _conn()
    try:
        rows = con.execute(
            "SELECT probe_id, operation, status, timestamp, duration_ms, error, "
            "error_category, details_json FROM operation_probes"
            f"{where} ORDER BY timestamp DESC, probe_id DESC LIMIT ?",
            (*args, limit),
        ).fetchall()
    finally:
        con.close()

    items: list[dict] = []
    for row in reversed(rows):
        item = dict(row)
        item.pop("probe_id", None)
        raw_details = item.pop("details_json", None)
        if raw_details:
            try:
                details = json.loads(raw_details)
            except (TypeError, ValueError):
                details = {}
            if isinstance(details, dict):
                item["details"] = details
        items.append(item)
    return items


def list_environment_ledger(limit: int = 100) -> list[dict]:
    """Return recent historical allocations with decoded fingerprint profiles."""
    limit = max(1, min(int(limit or 100), 1000))
    con = _conn()
    rows = con.execute(
        "SELECT * FROM environment_ledger ORDER BY created_at DESC LIMIT ?", (limit,)
    ).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        try:
            item["fingerprint"] = json.loads(item.pop("fingerprint_json") or "{}")
        except (TypeError, ValueError):
            item["fingerprint"] = {}
            item.pop("fingerprint_json", None)
        out.append(item)
    return out


def create_run(
    run_id: str,
    email: str,
    log_path: str,
    environment: Optional[Mapping[str, Any]] = None,
) -> None:
    with _lock:
        con = _conn()
        con.execute(
            "INSERT INTO runs(run_id, email, status, started_at, log_path) "
            "VALUES (?, ?, 'running', ?, ?)",
            (run_id, email.lower(), time.time(), log_path),
        )
        con.commit()
    if environment:
        update_run_environment(run_id, environment)


def finish_run(run_id: str, status: str, error: str = "", category: str = "") -> None:
    with _lock:
        con = _conn()
        con.execute(
            "UPDATE runs SET status=?, finished_at=?, error=?, error_category=? WHERE run_id=?",
            (status, time.time(), (error or "")[:500], category or None, run_id),
        )
        con.commit()


def list_runs(limit: int = 50) -> list[dict]:
    limit = max(1, min(int(limit or 50), 1000))
    con = _conn()
    cur = con.execute(
        "SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (limit,),
    )
    rows = []
    for row in cur.fetchall():
        item = dict(row)
        for raw_key, decoded_key in (
            ("environment_json", "environment"),
            ("runtime_observation_json", "runtime_observation"),
            ("probe_json", "probes"),
        ):
            raw = item.pop(raw_key, None)
            if raw:
                try:
                    item[decoded_key] = json.loads(raw)
                except (TypeError, ValueError):
                    item[decoded_key] = {}
            else:
                item[decoded_key] = {}
        try:
            item["fingerprint"] = json.loads(item.pop("fingerprint_json") or "{}")
        except (TypeError, ValueError):
            item["fingerprint"] = {}
            item.pop("fingerprint_json", None)
        rows.append(item)
    return rows


# ──────────────────────── settings (KV) ────────────────────────


def get_setting(key: str, default: str = "") -> str:
    con = _conn()
    cur = con.execute("SELECT value FROM settings WHERE key=?", (key,))
    row = cur.fetchone()
    return row["value"] if row else default


def set_setting(key: str, value) -> None:
    with _lock:
        con = _conn()
        con.execute(
            "INSERT INTO settings(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )
        con.commit()


# ──────────────────────── 邮箱来源配置 ────────────────────────


def get_mail_config() -> dict:
    """返回邮箱来源配置（密码类字段隐藏明文）。

    provider 声明的配置项自动带出来 —— 加新邮箱时这里不用改，
    新 provider 的 config_fields 会自动出现在返回值里。
    """
    from mail_providers import list_providers

    out = {"mail_source": get_setting("mail_source", "outlook")}
    for p in list_providers():
        for f in p["config_fields"]:
            key = f["key"]
            if f.get("type") == "password":
                out[key] = "***" if get_setting(key) else ""
            else:
                out[key] = get_setting(key, "")
    return out


def save_mail_config(data: dict) -> None:
    """保存邮箱配置。password 类字段传 '***' 表示不修改。

    mail_source 校验改成查 mail_providers 注册表：
        以前是写死的白名单 ("outlook", "cf_temp")，选了别的会被
        **静默改回 outlook** —— 用户看到的是"保存成功但选择没生效"。
        现在未知来源直接抛错，问题当场暴露。
    """
    from mail_providers import get_provider_class, list_providers

    if "mail_source" in data:
        src = str(data["mail_source"]).strip().lower()
        get_provider_class(src)  # 未注册的 kind 会抛 MailProviderError
        set_setting("mail_source", src)

    # 按 provider 声明的字段保存，加新邮箱时这里零改动
    for p in list_providers():
        for f in p["config_fields"]:
            key = f["key"]
            if key not in data:
                continue
            val = data[key]
            if f.get("type") == "password":
                if not val or val == "***":
                    continue  # 没填 / 是掩码 → 保持原值
            set_setting(key, str(val).strip())


def get_secret_setting(key: str) -> str:
    """内部用：拿密码类配置的明文。"""
    return get_setting(key, "")


def get_mail_settings() -> dict:
    """内部用：给 create_mail_provider 的 settings（含明文密钥）。

    跟 get_mail_config 的区别：这个不打码，只在服务端构造 provider 时用，
    绝不能直接返回给前端。
    """
    from mail_providers import list_providers

    out = {"mail_source": get_setting("mail_source", "outlook")}
    for p in list_providers():
        for f in p["config_fields"]:
            out[f["key"]] = get_setting(f["key"], "")
    return out


def get_cf_admin_token() -> str:
    """内部用：拿明文 admin_token。"""
    return get_setting("cf_admin_token", "")


# ──────────────────────── SMS 接码配置 ────────────────────────


def get_sms_config() -> dict:
    """返回 SMS 接码配置（api_key 隐藏明文）。

    sms_enabled:        '0'/'1' 是否启用接码（命中 add-phone 时才会用）
    sms_provider:       smsbower
    sms_country:        国家代码或 ID（推荐 '52' = Thailand，OpenAI 走 SMS 的唯一稳定国家）
    sms_service:        服务代码（OpenAI = 'dr'）
    sms_max_price:      号码最高单价（SmsBower / SmsBower 用，单位平台货币；空 / -1 = 不限）
    sms_reuse_phone:    '0'/'1' 同号复用（SmsBower / SmsBower 支持，省钱）
    sms_phone_success_max: 同号最多复用几次（默认 3）
    sms_auto_country:   '0'/'1' 自动选最优国家（按价格 + 库存）
    sms_auto_min_stock: 自动选国家最低库存（默认 20）
    sms_auto_max_price: 自动选国家最高单价（默认 0 = 不限）
    """
    return {
        "sms_enabled":             get_setting("sms_enabled", "0"),
        "sms_provider":            get_setting("sms_provider", "smsbower"),
        "sms_api_key":             "***" if get_setting("sms_api_key") else "",
        "sms_country":             get_setting("sms_country", "52"),
        "sms_service":             get_setting("sms_service", "dr"),
        "sms_max_price":           get_setting("sms_max_price", ""),
        "sms_fixed_price":         get_setting("sms_fixed_price", ""),
        "sms_reuse_phone":         get_setting("sms_reuse_phone", "0"),
        "sms_phone_success_max":   get_setting("sms_phone_success_max", "3"),
        "sms_auto_country":        get_setting("sms_auto_country", "0"),
        "sms_strict_whitelist":    get_setting("sms_strict_whitelist", "0"),
        "sms_allowed_countries":   get_setting("sms_allowed_countries", ""),
        "sms_auto_min_stock":      get_setting("sms_auto_min_stock", "20"),
        "sms_auto_max_price":      get_setting("sms_auto_max_price", ""),
        "sms_max_phone_attempts":  get_setting("sms_max_phone_attempts", ""),
        "sms_per_phone_timeout":   get_setting("sms_per_phone_timeout", "80"),
    }


def save_sms_config(data: dict) -> None:
    """保存 SMS 配置。sms_api_key 传 '***' 表示不修改。"""
    # 校验 provider
    valid_providers = {"smsbower", "herosms"}
    if "sms_provider" in data:
        p = str(data["sms_provider"]).strip().lower()
        if p not in valid_providers:
            p = "smsbower"
        set_setting("sms_provider", p)
    # 字符串字段直接落
    for key in (
        "sms_country", "sms_service", "sms_max_price", "sms_fixed_price",
        "sms_phone_success_max", "sms_auto_min_stock", "sms_auto_max_price",
        "sms_max_phone_attempts", "sms_per_phone_timeout",
        "sms_allowed_countries",
    ):
        if key in data:
            set_setting(key, str(data[key]).strip())
    # 布尔字段（前端传 '0'/'1' 或 bool）
    for key in ("sms_enabled", "sms_reuse_phone", "sms_auto_country", "sms_strict_whitelist"):
        if key in data:
            v = data[key]
            if isinstance(v, bool):
                set_setting(key, "1" if v else "0")
            else:
                s = str(v).strip().lower()
                set_setting(key, "1" if s in ("1", "true", "yes", "on") else "0")
    # API key（'***' 不修改）
    if data.get("sms_api_key") and data["sms_api_key"] != "***":
        set_setting("sms_api_key", str(data["sms_api_key"]).strip())


def get_sms_internal_config() -> dict:
    """内部用：拿明文 sms_api_key,供 sms_provider 实例化使用。"""
    return {
        "sms_enabled":             get_setting("sms_enabled", "0") in ("1", "true"),
        "sms_provider":            get_setting("sms_provider", "smsbower"),
        "sms_api_key":             get_setting("sms_api_key", ""),
        "sms_country":             get_setting("sms_country", "52"),
        "sms_service":             get_setting("sms_service", "dr"),
        "sms_max_price":           get_setting("sms_max_price", ""),
        "sms_fixed_price":         get_setting("sms_fixed_price", ""),
        "sms_reuse_phone":         get_setting("sms_reuse_phone", "0") in ("1", "true"),
        "sms_phone_success_max":   get_setting("sms_phone_success_max", "3"),
        "sms_auto_country":        get_setting("sms_auto_country", "0") in ("1", "true"),
        "sms_strict_whitelist":    get_setting("sms_strict_whitelist", "0") in ("1", "true"),
        "sms_allowed_countries":   get_setting("sms_allowed_countries", ""),
        "sms_auto_min_stock":      get_setting("sms_auto_min_stock", "20"),
        "sms_auto_max_price":      get_setting("sms_auto_max_price", ""),
        "sms_max_phone_attempts":  get_setting("sms_max_phone_attempts", ""),
        "sms_per_phone_timeout":   get_setting("sms_per_phone_timeout", "80"),
    }


# ──────────────────────── 自动导出配置 (CPA / SUB2API) ────────────────────────


def get_export_config() -> dict:
    """返回导出配置（敏感字段做明文/'***' 占位）。

    给前端展示用：
      cpa_mgmt_key / sub2api_api_key 已设置时返回 '***'，未设置返回 ''。
      保存时传 '***' 代表不修改。
    """
    return {
        # CPA
        "cpa_enabled":     get_setting("export_cpa_enabled", "0"),
        "cpa_url":         get_setting("export_cpa_url", ""),
        "cpa_mgmt_key":    "***" if get_setting("export_cpa_mgmt_key") else "",
        "cpa_timeout":     get_setting("export_cpa_timeout", "30"),
        # SUB2API
        "sub2api_enabled":    get_setting("export_sub2api_enabled", "0"),
        "sub2api_url":        get_setting("export_sub2api_url", ""),
        "sub2api_api_key":    "***" if get_setting("export_sub2api_api_key") else "",
        "sub2api_group_ids":  get_setting("export_sub2api_group_ids", "2"),
        "sub2api_timeout":    get_setting("export_sub2api_timeout", "30"),
    }


def save_export_config(data: dict) -> None:
    """保存导出配置。密文字段传 '***' 表示不修改。"""
    # 布尔开关
    for key_in, key_out in (
        ("cpa_enabled",     "export_cpa_enabled"),
        ("sub2api_enabled", "export_sub2api_enabled"),
    ):
        if key_in in data:
            v = data[key_in]
            if isinstance(v, bool):
                set_setting(key_out, "1" if v else "0")
            else:
                s = str(v).strip().lower()
                set_setting(key_out, "1" if s in ("1", "true", "yes", "on") else "0")
    # 字符串字段（明文）
    for key_in, key_out in (
        ("cpa_url",            "export_cpa_url"),
        ("cpa_timeout",        "export_cpa_timeout"),
        ("sub2api_url",        "export_sub2api_url"),
        ("sub2api_group_ids",  "export_sub2api_group_ids"),
        ("sub2api_timeout",    "export_sub2api_timeout"),
    ):
        if key_in in data:
            set_setting(key_out, str(data[key_in] or "").strip())
    # 密文字段（'***' 不修改）
    if data.get("cpa_mgmt_key") and data["cpa_mgmt_key"] != "***":
        set_setting("export_cpa_mgmt_key", str(data["cpa_mgmt_key"]).strip())
    if data.get("sub2api_api_key") and data["sub2api_api_key"] != "***":
        set_setting("export_sub2api_api_key", str(data["sub2api_api_key"]).strip())


def get_export_internal_config() -> dict:
    """内部用：拿明文密钥 + 解析后的 enabled 布尔。供 registrar / app.test 调用。

    返回两个子配置 dict，可分别传给 exporter.export_to_cpa / export_to_sub2api。
    """
    cpa = {
        "enabled":      get_setting("export_cpa_enabled", "0") in ("1", "true"),
        "cpa_url":      get_setting("export_cpa_url", ""),
        "cpa_mgmt_key": get_setting("export_cpa_mgmt_key", ""),
        "cpa_timeout":  get_setting("export_cpa_timeout", "30"),
    }
    sub2api = {
        "enabled":            get_setting("export_sub2api_enabled", "0") in ("1", "true"),
        "sub2api_url":        get_setting("export_sub2api_url", ""),
        "sub2api_api_key":    get_setting("export_sub2api_api_key", ""),
        "sub2api_group_ids":  get_setting("export_sub2api_group_ids", "2"),
        "sub2api_timeout":    get_setting("export_sub2api_timeout", "30"),
    }
    return {"cpa": cpa, "sub2api": sub2api}


# 模块加载时自动建表
init_db()
