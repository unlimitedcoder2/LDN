from __future__ import annotations

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


class PipeSocket:
    def __init__(self, conn: WindowsPipeConnection):
        self._conn = conn
        self._next_sid = 1
        self._pending: dict[int, tuple[trio.Event, list]] = {}
        self._data_senders: dict[int, trio.MemorySendChannel[bytes]] = {}
        self._out_send, self._out_recv = trio.open_memory_channel(math.inf)

    async def open(self, domain: int, type: int, proto: int) -> "PipeChannel":
        sid = self._next_sid
        self._next_sid += 1
        send_chan, recv_chan = trio.open_memory_channel(math.inf)
        self._data_senders[sid] = send_chan
        ret, _ = await self._request(sid, protocol.OP_SOCKET, domain, type, proto)
        if ret < 0:
            del self._data_senders[sid]
            raise OSError(-ret, "daemon socket() failed")
        return PipeChannel(self, sid, recv_chan)

    def _enqueue_frame(self, op: int, sid: int, a0: int = 0, a1: int = 0,
                        a2: int = 0, blob: bytes = b"") -> None:
        self._out_send.send_nowait(protocol.pack(op, sid, a0, a1, a2, blob))

    async def _send_frame(self, op: int, sid: int, a0: int = 0, a1: int = 0,
                           a2: int = 0, blob: bytes = b"") -> None:
        await self._out_send.send(protocol.pack(op, sid, a0, a1, a2, blob))

    async def _request(self, sid: int, op: int, a0: int = 0, a1: int = 0,
                        a2: int = 0, blob: bytes = b"") -> tuple[int, bytes]:
        event = trio.Event()
        box: list = []
        self._pending[sid] = (event, box)
        try:
            await self._send_frame(op, sid, a0, a1, a2, blob)
            await event.wait()
        finally:
            del self._pending[sid]
        if not box:
            raise ConnectionError("daemon closed the connection during setup")
        return box[0]

    async def _close_channel(self, sid: int) -> None:
        self._enqueue_frame(protocol.OP_CLOSE, sid)
        sender = self._data_senders.pop(sid, None)
        if sender is not None:
            await sender.aclose()

    async def _read_loop(self) -> None:
        while True:
            header = await self._conn.recvn(4)
            if header is None:
                await self._shutdown()
                return
            (length,) = struct.unpack("<I", header)
            body = await self._conn.recvn(length)
            if body is None:
                await self._shutdown()
                return
            op, sid, a0, _a1, _a2, blob = protocol.parse_body(body)
            if op == protocol.OP_REPLY:
                pending = self._pending.get(sid)
                if pending is not None:
                    pending[1].append((protocol.to_signed(a0), blob))
                    pending[0].set()
            elif op == protocol.OP_DATA:
                sender = self._data_senders.get(sid)
                if sender is not None:
                    try:
                        sender.send_nowait(blob)
                    except (trio.BrokenResourceError, trio.WouldBlock):
                        pass

    async def _writer_loop(self) -> None:
        async for data in self._out_recv:
            try:
                await self._conn.sendall(data)
            except OSError:
                pass

    async def _shutdown(self) -> None:
        for event, box in list(self._pending.values()):
            event.set()
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
        ret, _ = await self._conn._request(self._sid, protocol.OP_BIND, blob=addr)
        if ret < 0:
            raise OSError(-ret, "daemon bind() failed")

    async def fetch_sockname(self) -> bytes:
        ret, blob = await self._conn._request(self._sid, protocol.OP_GETSOCKNAME)
        if ret < 0:
            raise OSError(-ret, "daemon getsockname() failed")
        self._sockname = blob
        return blob

    async def startup(self) -> None:
        ret, _ = await self._conn._request(self._sid, protocol.OP_START)
        if ret < 0:
            raise OSError(-ret, "daemon start failed")

    def getsockname(self) -> tuple[int, int]:
        return parse_sockaddr_nl(self._sockname)

    def setsockopt(self, level: int, optname: int, value: int | bytes) -> None:
        if isinstance(value, bool):
            value = int(value)
        if isinstance(value, int):
            blob = struct.pack("<i", value)
        else:
            blob = bytes(value)
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

    sock = netlink.NetlinkSocket(channel)
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
