"""
transport/fake.py
-----------------
Kênh vận tải giả lập trong bộ nhớ (In-memory Fake Transport) (G5).
Cung cấp giao diện `FakeConnection` và `FakeStream` hoàn toàn tương thích
với Transport thật nhưng chạy trên hàng đợi `asyncio.Queue`.
Giúp phát triển song song các tầng ứng dụng (Chat, UI, File) độc lập.
"""

import asyncio
from typing import Awaitable, Callable, Dict, Optional


class FakeStream:
    """Luồng truyền hai chiều trong bộ nhớ cho 1 stream_id."""

    def __init__(self, stream_id: int):
        self.stream_id = stream_id
        self._inbox: asyncio.Queue[bytes] = asyncio.Queue()
        self._peer_stream: Optional["FakeStream"] = None
        self._closed: bool = False

    def connect_peer(self, peer: "FakeStream") -> None:
        """Nối luồng với luồng của đối tác đầu bên kia."""
        self._peer_stream = peer

    async def send(self, data: bytes) -> None:
        """Gửi dữ liệu vào hộp thư của đầu bên kia."""
        if self._closed:
            raise ConnectionResetError("Stream đã bị đóng.")
        if not self._peer_stream or self._peer_stream._closed:
            raise ConnectionResetError("Đầu nhận đã ngắt kết nối.")
        await self._peer_stream._inbox.put(data)

    async def recv(self) -> bytes:
        """Nhận dữ liệu từ hộp thư đến (chờ đến khi có dữ liệu)."""
        if self._closed and self._inbox.empty():
            raise ConnectionResetError("Stream đã bị đóng.")
        data = await self._inbox.get()
        return data

    def close(self) -> None:
        """Đóng luồng này."""
        self._closed = True


class FakeConnection:
    """
    Đại diện cho 1 kết nối đa luồng (Multiplexed Connection) giả lập.
    Quản lý các luồng FakeStream theo stream_id.
    """

    def __init__(self, name: str = "endpoint"):
        self.name = name
        self._streams: Dict[int, FakeStream] = {}
        self._peer_conn: Optional["FakeConnection"] = None
        self._disconnect_cb: Optional[Callable[[], Awaitable[None]]] = None
        self._connected: bool = True

    def connect_peer(self, peer: "FakeConnection") -> None:
        """Nối kết nối giả lập với peer đối tác."""
        self._peer_conn = peer
        peer._peer_conn = self

    async def open_stream(self, stream_id: int) -> FakeStream:
        """Mở hoặc lấy lại luồng theo stream_id."""
        if stream_id not in self._streams:
            stream = FakeStream(stream_id)
            self._streams[stream_id] = stream

            # Nếu đã kết nối với peer, tự động liên kết với stream cùng ID của peer
            if self._peer_conn:
                if stream_id not in self._peer_conn._streams:
                    peer_stream = FakeStream(stream_id)
                    self._peer_conn._streams[stream_id] = peer_stream
                else:
                    peer_stream = self._peer_conn._streams[stream_id]

                stream.connect_peer(peer_stream)
                peer_stream.connect_peer(stream)

        return self._streams[stream_id]

    def on_disconnect(self, callback: Callable[[], Awaitable[None]]) -> None:
        """Đăng ký callback gọi khi kết nối bị ngắt."""
        self._disconnect_cb = callback

    async def simulate_disconnect(self) -> None:
        """Giả lập mất kết nối mạng để kiểm thử phản ứng của hệ thống."""
        self._connected = False
        for s in self._streams.values():
            s.close()
        if self._disconnect_cb:
            await self._disconnect_cb()
