"""Keep imports and test probes away from the user's database and network."""
import importlib
import ipaddress
import socket
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest


# db initializes its schema at import time, before pytest fixtures can run.
# Keep all pytest-owned files under the system temp root.  The repository's
# ``tmp`` directory can inherit a restrictive Windows ACL, which makes pytest
# fail while cleaning its basetemp (WinError 5) and can also block SQLite WAL
# files.  The directory is unique per collection, so it never touches the
# application's runtime database or logs.
_TEST_TMP_DIR = Path(tempfile.gettempdir()) / f"gpt-reg-review-tests-{uuid4().hex}"
_TEST_TMP_DIR.mkdir(parents=True, exist_ok=True)


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config):
    # The repository's default cache directory may carry the same restricted
    # ACL as the old ``tmp`` tree.  Keep pytest's cache beside the isolated
    # writable test root unless the caller explicitly selected another path.
    if config.getini("cache_dir") == ".pytest_cache":
        config.option.cache_dir = str(_TEST_TMP_DIR / "pytest-cache")


@pytest.hookimpl(tryfirst=True)
def pytest_sessionstart(session):
    """Use a normal-ACL basetemp on Windows sandboxed runners.

    pytest creates its default ``pytest-of-*`` tree with mode ``0700``.  The
    managed Windows ACL turns that into a directory the test process cannot
    enumerate, so ``tmp_path`` fails during setup and session cleanup.  Seed
    the already-created test root directly; this leaves explicit ``--basetemp``
    choices untouched.
    """
    factory = getattr(session.config, "_tmp_path_factory", None)
    if factory is None or getattr(factory, "_given_basetemp", None) is not None:
        return
    basetemp = _TEST_TMP_DIR / "pytest-basetemp"
    basetemp.mkdir(parents=True, exist_ok=True)
    factory._basetemp = basetemp.resolve()


@pytest.fixture
def tmp_path():
    """Provide a writable test directory without pytest's restrictive mode=0700."""
    path = _TEST_TMP_DIR / f"case-{uuid4().hex}"
    path.mkdir(parents=True, exist_ok=True)
    return path


# ``TemporaryDirectory`` requests a restrictive Windows ACL in this workspace,
# which leaves SQLite unable to create its journal.  Create test directories
# through ``Path.mkdir`` so the current user keeps the inherited workspace ACL.
_collection_dir = _TEST_TMP_DIR / f"webui-tests-{uuid4().hex}"
_collection_dir.mkdir(parents=True, exist_ok=True)
_collection_db = _collection_dir / "collection.db"
_connect = sqlite3.connect


def _collection_connect(_database, *args, **kwargs):
    return _connect(str(_collection_db), *args, **kwargs)


with patch.object(sqlite3, "connect", _collection_connect):
    db = importlib.import_module("webui.db")
db.DB_PATH = _collection_db


@pytest.fixture(autouse=True)
def isolated_storage_and_network(tmp_path, monkeypatch):
    from webui import probes

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "webui.db")
    monkeypatch.setattr(probes, "_OPERATION_HISTORY", [])
    db.init_db()

    def no_network(*args, **kwargs):
        raise AssertionError("Unit tests must replace network boundaries with fixtures")

    # Windows asyncio uses a loopback socketpair for its wake-up pipe.
    def local_only(original):
        def connect(sock, address):
            if isinstance(address, tuple) and ipaddress.ip_address(address[0]).is_loopback:
                return original(sock, address)
            return no_network()
        return connect

    monkeypatch.setattr(socket.socket, "connect", local_only(socket.socket.connect))
    monkeypatch.setattr(socket.socket, "connect_ex", local_only(socket.socket.connect_ex))
    # curl_cffi opens sockets in native code, bypassing Python's socket module.
    from curl_cffi.requests import Session

    monkeypatch.setattr(Session, "request", no_network)
