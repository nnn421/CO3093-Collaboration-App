"""
transport/lossy.py
------------------
Bộ giả lập kênh truyền mạng chất lượng kém (Network Impairment Simulator) (C1).
Cho phép kiểm thử sức chịu đựng của giao thức UDP tin cậy trên các điều kiện khắc nghiệt:
  - Tỷ lệ rơi rớt gói tin (Packet Loss: 0 - 100%)
  - Độ trễ và biến thiên trễ (Latency + Jitter)
  - Nhân bản gói tin (Packet Duplication)
  - Xáo trộn thứ tự gói tin (Packet Reordering)
"""

import asyncio
import logging
import random
from typing import Callable, Optional

log = logging.getLogger("transport.lossy")


class LossyChannel:
    """
    Kênh truyền giả lập rớt gói và độ trễ 2 chiều giữa 2 endpoint A và B.
    """

    def __init__(
        self,
        loss_pct: float = 0.0,      # Tỷ lệ rớt gói (0 đến 100%)
        delay_ms: float = 0.0,      # Độ trễ mạng cơ sở (mili-giây)
        jitter_ms: float = 0.0,     # Biến thiên độ trễ ngẫu nhiên (± mili-giây)
        dup_pct: float = 0.0,       # Tỷ lệ nhân bản gói tin (0 đến 100%)
        reorder_pct: float = 0.0,   # Tỷ lệ xáo trộn thứ tự gói (0 đến 100%)
        deterministic: bool = True  # Chế độ kiểm soát rớt gói có chu kỳ chính xác (Deterministic)
    ):
        self.loss_pct = loss_pct
        self.delay_ms = delay_ms
        self.jitter_ms = jitter_ms
        self.dup_pct = dup_pct
        self.reorder_pct = reorder_pct
        self.deterministic = deterministic
        self._drop_counter: int = 0

        # Thống kê hiệu năng
        self.total_sent: int = 0
        self.total_dropped: int = 0
        self.total_duplicated: int = 0
        self.total_delivered: int = 0

    async def forward(self, packet_bytes: bytes, deliver_callback: Callable[[bytes], None]) -> None:
        """
        Tiếp nhận gói tin nhị phân và đưa qua môi trường giả lập mạng kém.
        """
        self.total_sent += 1

        # 1. Giả lập rơi rớt gói tin (Packet Loss)
        should_drop = False
        if self.loss_pct > 0:
            if self.deterministic:
                # Chế độ kiểm soát chính xác: 20% nghĩa là cứ 5 gói thì drop đúng 1 gói
                period = max(1, round(100.0 / self.loss_pct))
                self._drop_counter += 1
                if self._drop_counter % period == 0:
                    should_drop = True
            else:
                should_drop = (random.random() * 100.0) < self.loss_pct

        if should_drop:
            self.total_dropped += 1
            log.debug(f"[LossyChannel] DROP gói tin {len(packet_bytes)}B (Tỷ lệ drop: {self.loss_pct}%)")
            return

        # 2. Giả lập nhân bản gói tin (Duplication)
        should_dup = (self.dup_pct > 0) and ((random.random() * 100.0) < self.dup_pct)
        if should_dup:
            self.total_duplicated += 1

        # 3. Giả lập độ trễ và biến thiên độ trễ (Latency + Jitter)
        actual_delay_ms = self.delay_ms
        if self.jitter_ms > 0:
            actual_delay_ms += random.uniform(-self.jitter_ms, self.jitter_ms)
        actual_delay_ms = max(0.0, actual_delay_ms)

        # 4. Giả lập xáo trộn thứ tự (Reordering bằng cách hoãn ngẫu nhiên thêm một khoảng)
        if self.reorder_pct > 0 and (random.random() * 100.0) < self.reorder_pct:
            actual_delay_ms += random.uniform(20.0, 80.0)

        async def _deliver():
            if actual_delay_ms > 0:
                await asyncio.sleep(actual_delay_ms / 1000.0)
            deliver_callback(packet_bytes)
            self.total_delivered += 1

            if should_dup:
                # Gói nhân bản đến trễ sau 5-15ms
                await asyncio.sleep(random.uniform(5.0, 15.0) / 1000.0)
                deliver_callback(packet_bytes)
                self.total_delivered += 1

        # Chạy giao gói trong background task để không chặn sender
        asyncio.create_task(_deliver())

    def reset_stats(self) -> None:
        """Đặt lại bộ đếm thống kê."""
        self.total_sent = 0
        self.total_dropped = 0
        self.total_duplicated = 0
        self.total_delivered = 0
        self._drop_counter = 0
