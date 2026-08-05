from __future__ import annotations

import collections
import contextlib
import math
import struct
import sys

from collections.abc import AsyncIterator

import trio
import netlink
from netlink import generic, nl80211, route

from ldn.daemon_client import protocol

# from linux
AF_NETLINK = 16
AF_PACKET = 17
SOCK_DGRAM = 2
SOCK_RAW = 3
SOL_NETLINK = 270

def pack_sockaddr_nl(pid: int = 0, groups: int = 0) -> bytes:
    return struct.pack("<HHII", AF_NETLINK, 0, pid & 0xFFFFFFFF, groups & 0xFFFFFFFF)


def parse_sockaddr_nl(data: bytes) -> tuple[int, int]:
    if len(data) < 12:
        return (0, 0)
    _family, _pad, pid, groups = struct.unpack_from("<HHII", data, 0)
    return (pid, groups)


def pack_sockaddr_ll(eth_protocol: int, ifindex: int) -> bytes:
    return (
        struct.pack("<H", AF_PACKET) +        # sll_family
        struct.pack(">H", eth_protocol) +     # sll_protocol (network order)
        struct.pack("<i", ifindex) +          # sll_ifindex
        struct.pack("<HBB", 0, 0, 0) +        # sll_hatype, sll_pkttype, sll_halen
        b"\x00" * 8                           # sll_addr
    )

class WindowsPipeConnection:
    def __init__(self, handle: int):
        self._handle = handle

    @classmethod
    async def connect(cls, path: str) -> "WindowsPipeConnection":
        handle = await trio.to_thread.run_sync(cls._connect_sync, path)
        trio.lowlevel.register_with_iocp(handle)
        return cls(handle)

    @staticmethod
    def _connect_sync(path: str) -> int:
        import ctypes
        from ctypes import wintypes

        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.CreateFileW.restype = wintypes.HANDLE
        # k.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]

        GENERIC_READ = 0x80000000
        GENERIC_WRITE = 0x40000000
        OPEN_EXISTING = 3
        FILE_FLAG_OVERLAPPED = 0x40000000
        INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

        # k.WaitNamedPipeW(path, 5000)
        handle = k.CreateFileW(
            path, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED, None
        )
        if handle == INVALID_HANDLE_VALUE or handle is None:
            raise OSError(ctypes.get_last_error(),
                          "CreateFileW failed for %s" % path)
        return int(handle)

    async def sendall(self, data: bytes) -> None:
        buf = memoryview(data)
        off = 0
        while off < len(buf):
            try:
                n = await trio.lowlevel.write_overlapped(self._handle, buf[off:])
            except OSError as e:
                raise OSError(e.errno, "WriteFile failed") from e
            if n == 0:
                raise OSError(None, "WriteFile wrote 0 bytes")
            off += n

    async def recvn(self, n: int) -> bytes | None:
        buf = bytearray()
        while len(buf) < n:
            chunk = bytearray(n - len(buf))
            try:
                got = await trio.lowlevel.readinto_overlapped(self._handle, chunk)
            except OSError:
                return None
            if got == 0:
                return None
            buf += chunk[:got]
        return bytes(buf)

    async def close(self) -> None:
        import ctypes
        try:
            ctypes.windll.kernel32.CloseHandle(self._handle)
        except Exception:
            pass


async def _open_connection(path: str) -> WindowsPipeConnection:
    if sys.platform == "win32":
        return await WindowsPipeConnection.connect(path)
    raise NotImplementedError()


class _Waiter:
    __slots__ = ("event", "result")

    def __init__(self) -> None:
        self.event = trio.Event()
        self.result: tuple[int, bytes] | None = None


class PipeSocket:
    def __init__(self, conn: WindowsPipeConnection):
        self._conn = conn
        self._next_sid = 1
        self._pending: dict[int, collections.deque[_Waiter]] = {}
        self._data_senders: dict[int, trio.MemorySendChannel[bytes]] = {}
        self._out_send, self._out_recv = trio.open_memory_channel(math.inf)

    async def open(self, domain: int, type: int, proto: int) -> "PipeChannel":
        sid = self._next_sid
        self._next_sid += 1
        send_chan, recv_chan = trio.open_memory_channel(math.inf)
        self._data_senders[sid] = send_chan
        status, _ = await self._request(sid, protocol.OP_SOCKET, domain, type, proto)
        if status != protocol.ERROR_NONE:
            del self._data_senders[sid]
            raise protocol.DaemonError("socket()", status)
        return PipeChannel(self, sid, recv_chan)

    def _enqueue_frame(self, op: int, sid: int, a0: int = 0, a1: int = 0,
                        a2: int = 0, blob: bytes = b"") -> None:
        self._out_send.send_nowait(protocol.pack(op, sid, a0, a1, a2, len(blob), blob))

    async def _send_frame(self, op: int, sid: int, a0: int = 0, a1: int = 0,
                           a2: int = 0, blob: bytes = b"") -> None:
        await self._out_send.send(protocol.pack(op, sid, a0, a1, a2, len(blob), blob))

    def _push_waiter(self, sid: int) -> _Waiter:
        waiter = _Waiter()
        self._pending.setdefault(sid, collections.deque()).append(waiter)
        return waiter

    async def _request(self, sid: int, op: int, a0: int = 0, a1: int = 0,
                        a2: int = 0, blob: bytes = b"") -> tuple[int, bytes]:
        waiter = self._push_waiter(sid)
        self._enqueue_frame(op, sid, a0, a1, a2, blob)
        await waiter.event.wait()
        if waiter.result is None:
            raise ConnectionError("daemon closed the connection during setup")
        return waiter.result

    async def _close_channel(self, sid: int) -> None:
        self._enqueue_frame(protocol.OP_CLOSE, sid)
        sender = self._data_senders.pop(sid, None)
        if sender is not None:
            await sender.aclose()

    async def _read_loop(self) -> None:
        while True:
            header = await self._conn.recvn(protocol.HEADER.size)
            if header is None:
                await self._shutdown()
                return
            op, sid, a0, a1, a2, blob_len = protocol.parse_frame_header(header)
            body = await self._conn.recvn(blob_len)
            if body is None:
                await self._shutdown()
                return
            if op == protocol.OP_REPLY:
                queue = self._pending.get(sid)
                if queue:
                    waiter = queue.popleft()
                    waiter.result = (a0, body)
                    waiter.event.set()
                    if not queue:
                        del self._pending[sid]
            elif op == protocol.OP_DATA:
                sender = self._data_senders.get(sid)
                if sender is not None:
                    try:
                        sender.send_nowait(body)
                    except (trio.BrokenResourceError, trio.WouldBlock):
                        pass

    async def _writer_loop(self) -> None:
        async for data in self._out_recv:
            try:
                await self._conn.sendall(data)
            except OSError:
                pass

    async def _shutdown(self) -> None:
        for queue in list(self._pending.values()):
            for waiter in queue:
                waiter.event.set()
        for sender in list(self._data_senders.values()):
            await sender.aclose()
        await self._out_send.aclose()

    async def close(self) -> None:
        try:
            await self._conn.close()
        finally:
            await self._shutdown()


class PipeChannel:
    def __init__(
        self, conn: PipeSocket, sid: int,
        receiver: "trio.MemoryReceiveChannel[bytes]"
    ):
        self._conn = conn
        self._sid = sid
        self._receiver = receiver
        self._sockname = b""

    async def bind(self, addr: bytes) -> None:
        status, _ = await self._conn._request(self._sid, protocol.OP_BIND, blob=addr)
        if status != protocol.ERROR_NONE:
            raise protocol.DaemonError("bind()", status)

    async def fetch_sockname(self) -> bytes:
        status, blob = await self._conn._request(self._sid, protocol.OP_GETSOCKNAME)
        if status != protocol.ERROR_NONE:
            raise protocol.DaemonError("getsockname()", status)
        self._sockname = blob
        return blob

    async def startup(self) -> None:
        status, _ = await self._conn._request(self._sid, protocol.OP_START)
        if status != protocol.ERROR_NONE:
            raise protocol.DaemonError("start", status)

    def getsockname(self) -> tuple[int, int]:
        return parse_sockaddr_nl(self._sockname)

    def setsockopt(self, level: int, optname: int, value: int | bytes) -> None:
        if isinstance(value, bool):
            value = int(value)
        if isinstance(value, int):
            blob = struct.pack("<i", value)
        else:
            blob = bytes(value)
        self._conn._push_waiter(self._sid)
        self._conn._enqueue_frame(
            protocol.OP_SETSOCKOPT, self._sid, level, optname, 0, blob
        )

    async def send(self, data: bytes) -> None:
        await self._conn._send_frame(protocol.OP_SENDTO, self._sid, blob=data)

    async def recv(self, size: int = 65536) -> bytes:
        try:
            return await self._receiver.receive()
        except trio.EndOfChannel:
            raise ConnectionError("daemon closed the connection")

    async def close(self) -> None:
        await self._conn._close_channel(self._sid)

    async def __aenter__(self) -> "PipeChannel":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()


@contextlib.asynccontextmanager
async def daemon_connect(path: str) -> AsyncIterator[PipeSocket]:
    conn = await _open_connection(path)
    sock = PipeSocket(conn)
    async with trio.open_nursery() as nursery:
        nursery.start_soon(sock._read_loop)
        nursery.start_soon(sock._writer_loop)
        try:
            yield sock
        finally:
            await sock.close()
            nursery.cancel_scope.cancel()


@contextlib.asynccontextmanager
async def _pipe_connect(conn: PipeSocket, family: int):
    channel = await conn.open(AF_NETLINK, SOCK_DGRAM, family)
    channel.setsockopt(SOL_NETLINK, netlink.NETLINK_CAP_ACK, True)
    channel.setsockopt(SOL_NETLINK, netlink.NETLINK_EXT_ACK, True)
    await channel.bind(pack_sockaddr_nl(0, 0))
    await channel.fetch_sockname()
    await channel.startup()

    sock = netlink.NetlinkSocket(channel) # type: ignore
    async with trio.open_nursery() as nursery:
        nursery.start_soon(sock.start)
        try:
            yield sock
        finally:
            nursery.cancel_scope.cancel()
    await channel.close()


@contextlib.asynccontextmanager
async def route_connect(conn: PipeSocket):
    async with _pipe_connect(conn, netlink.NETLINK_ROUTE) as sock:
        yield route.RouteController(sock)


@contextlib.asynccontextmanager
async def nl80211_connect(conn: PipeSocket):
    family = generic.Family({
        generic.CTRL_ATTR_FAMILY_ID: generic.GENL_ID_CTRL,
        generic.CTRL_ATTR_FAMILY_NAME: "nlctrl",
        generic.CTRL_ATTR_VERSION: 2,
        generic.CTRL_ATTR_HDRSIZE: 0,
        generic.CTRL_ATTR_MAXATTR: max(generic.GenericNetlinkController.ATTRIBUTES),
    })
    async with _pipe_connect(conn, netlink.NETLINK_GENERIC) as sock:
        receiver = generic.GenericNetlinkReceiver(sock)
        controller = generic.GenericNetlinkController(receiver, family)
        yield await controller.get("nl80211", nl80211.NL80211)
