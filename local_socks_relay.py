"""本地代理中继：把浏览器「不支持的 socks5 认证」问题移到本地解决。

背景：Playwright / Camoufox 的新版本都不支持 socks5 代理认证，而 cliproxy
的出口必须认证。这个中继在 127.0.0.1 上起一个**免认证**的 SOCKS5 服务，
它自己带上凭据去连上游的 cliproxy socks5（远端 DNS）。浏览器连本地中继
就像连一个无密码的本地代理 —— 认证发生在中继这一层。

这也是「自己免费改写」的一部分：浏览器 → 本地中继 → cliproxy 出口，
全程没有第三方服务。

用法（供 browser_checkout_probe 使用）：
    relay = LocalSocksRelay(upstream="socks5h://user:pass@sg2.cliproxy.io:443")
    relay.start()            # 后台线程监听 127.0.0.1:随机端口
    local_proxy = relay.url  # socks5://127.0.0.1:PORT
    ...
    relay.stop()
"""
from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Optional

import socks as pysocks

logger = logging.getLogger("local_socks_relay")

_BUFFER = 64 * 1024


class LocalSocksRelay:
    """单上游的本地 SOCKS5 中继。"""

    def __init__(self, upstream: str, bind: str = "127.0.0.1", port: int = 0):
        from urllib.parse import unquote, urlsplit

        self._upstream = upstream
        parts = urlsplit(upstream)
        self._up_host = parts.hostname or ""
        self._up_port = parts.port or 1080
        self._up_user = unquote(parts.username or "")
        self._up_pass = unquote(parts.password or "")
        self._bind = bind
        self._port = port
        self._server: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    @property
    def url(self) -> str:
        return f"socks5://{self._bind}:{self._port}"

    def start(self) -> str:
        """启动监听，返回 socks5://127.0.0.1:PORT。"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self._bind, self._port))
        server.listen(32)
        self._server = server
        self._port = server.getsockname()[1]
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True, name="local-socks-relay")
        self._thread.start()
        return self.url

    def stop(self) -> None:
        self._running = False
        try:
            if self._server is not None:
                self._server.close()
        except Exception:  # noqa: BLE001
            pass
        self._server = None

    def _accept_loop(self) -> None:
        server = self._server
        if server is None:
            return
        server.settimeout(1.0)
        while self._running:
            try:
                conn, _addr = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._handle, args=(conn,), daemon=True)
            t.start()

    def _handle(self, conn: socket.socket) -> None:
        upstream: Optional[socket.socket] = None
        try:
            # 解析 SOCKS5 握手（只支持免认证方式 —— 本地中继本来就不需要认证）
            conn.settimeout(15)
            greeting = conn.recv(2)
            if len(greeting) < 2:
                conn.close()
                return
            methods = conn.recv(greeting[1])
            conn.sendall(b"\x05\x00")  # 选「无需认证」

            request = self._recv_all(conn, 4)
            if len(request) < 4 or request[0] != 5:
                conn.close()
                return
            atyp = request[3]
            if atyp == 0x01:
                target = self._recv_all(conn, 4)
                host = socket.inet_ntoa(target)
            elif atyp == 0x03:
                length = self._recv_all(conn, 1)[0]
                host = self._recv_all(conn, length).decode("utf-8", errors="replace")
            else:  # 0x04 IPv6 等，不支持
                conn.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                conn.close()
                return
            port = int.from_bytes(self._recv_all(conn, 2), "big")

            # 连上游 cliproxy（带凭据、远端 DNS）
            upstream = pysocks.socksocket()
            upstream.set_proxy(
                pysocks.SOCKS5, self._up_host, self._up_port,
                username=self._up_user or None,
                password=self._up_pass or None,
                rdns=True,  # 远端解析：域名在出口侧解析
            )
            upstream.settimeout(30)
            upstream.connect((host, port))

            conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            conn.settimeout(300)
            upstream.settimeout(300)
            self._pump(conn, upstream)
        except Exception as exc:  # noqa: BLE001
            logger.debug("中继连接失败: %s", type(exc).__name__)
            try:
                conn.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            except Exception:  # noqa: BLE001
                pass
        finally:
            for sock in (conn, upstream):
                if sock is not None:
                    try:
                        sock.close()
                    except Exception:  # noqa: BLE001
                        pass

    @staticmethod
    def _recv_all(conn: socket.socket, size: int) -> bytes:
        buf = b""
        while len(buf) < size:
            chunk = conn.recv(size - len(buf))
            if not chunk:
                raise ConnectionError("SOCKS 握手被截断")
            buf += chunk
        return buf

    @staticmethod
    def _pump(a: socket.socket, b: socket.socket) -> None:
        """双向转发，直到一边关闭。"""
        def forward(src, dst):
            try:
                while True:
                    data = src.recv(_BUFFER)
                    if not data:
                        dst.shutdown(socket.SHUT_WR)
                        break
                    dst.sendall(data)
            except OSError:
                pass

        t = threading.Thread(target=forward, args=(a, b), daemon=True)
        t.start()
        forward(b, a)
        t.join(timeout=5)


__all__ = ["LocalSocksRelay"]
