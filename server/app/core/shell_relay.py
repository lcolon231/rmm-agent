# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded, memory-only relay for interactive shell frames.

The database stores lifecycle metadata and counters; command input and output
live only in these per-process queues.  Sequence numbers make retries
idempotent and reconnects explicit, while acknowledgement-based eviction keeps
the amount of sensitive material in memory bounded.
"""
from __future__ import annotations

import asyncio
import hashlib
from collections import deque
from dataclasses import dataclass


class RelayError(Exception):
    code = "shell_relay_error"


class SequenceConflict(RelayError):
    code = "shell_sequence_conflict"


class Backpressure(RelayError):
    code = "shell_backpressure"


class CursorExpired(RelayError):
    code = "shell_cursor_expired"


class RelayClosed(RelayError):
    code = "shell_relay_closed"


@dataclass(frozen=True, slots=True)
class RelayFrame:
    seq: int
    stream: str
    data_b64: str
    eof: bool
    byte_length: int

    @property
    def digest(self) -> bytes:
        value = f"{self.seq}\0{self.stream}\0{self.data_b64}\0{int(self.eof)}"
        return hashlib.sha256(value.encode()).digest()


class _Direction:
    def __init__(self, start_seq: int, max_bytes: int, max_frames: int) -> None:
        self.last_seq = start_seq
        self.sent_high_water = start_seq
        self.evicted_through = start_seq
        self.max_bytes = max_bytes
        self.max_frames = max_frames
        self.frames: deque[RelayFrame] = deque()
        self.buffered_bytes = 0
        self.recent_digests: dict[int, bytes] = {}

    def append(self, frame: RelayFrame) -> bool:
        """Append a frame. Returns False for an identical retry."""
        if frame.seq <= self.last_seq:
            if self.recent_digests.get(frame.seq) == frame.digest:
                return False
            raise SequenceConflict()
        if frame.seq != self.last_seq + 1:
            raise SequenceConflict()
        if (
            len(self.frames) >= self.max_frames
            or self.buffered_bytes + frame.byte_length > self.max_bytes
        ):
            raise Backpressure()
        self.frames.append(frame)
        self.buffered_bytes += frame.byte_length
        self.last_seq = frame.seq
        self.recent_digests[frame.seq] = frame.digest
        return True

    def acknowledge(self, ack: int) -> None:
        if ack < 0 or ack > self.sent_high_water:
            raise SequenceConflict()
        while self.frames and self.frames[0].seq <= ack:
            removed = self.frames.popleft()
            self.buffered_bytes -= removed.byte_length
            self.evicted_through = removed.seq
        # Keep a small retry window without retaining payload bytes.
        floor = max(0, ack - 32)
        for seq in tuple(self.recent_digests):
            if seq < floor:
                self.recent_digests.pop(seq, None)

    def after(self, cursor: int, limit: int) -> list[RelayFrame]:
        if cursor < 0 or cursor > self.last_seq:
            raise SequenceConflict()
        if cursor < self.evicted_through:
            raise CursorExpired()
        result = [frame for frame in self.frames if frame.seq > cursor][:limit]
        if result:
            self.sent_high_water = max(self.sent_high_water, result[-1].seq)
        return result


class SessionRelay:
    def __init__(
        self,
        *,
        input_seq: int,
        output_seq: int,
        max_input_bytes: int,
        max_output_bytes: int,
        max_frames: int,
    ) -> None:
        self.input = _Direction(input_seq, max_input_bytes, max_frames)
        self.output = _Direction(output_seq, max_output_bytes, max_frames)
        self.closed = False
        self.condition = asyncio.Condition()

    async def append(self, direction: str, frame: RelayFrame) -> bool:
        async with self.condition:
            if self.closed:
                raise RelayClosed()
            accepted = getattr(self, direction).append(frame)
            self.condition.notify_all()
            return accepted

    async def read(
        self,
        direction: str,
        *,
        after: int,
        ack: int,
        limit: int,
        timeout: float,
    ) -> list[RelayFrame]:
        queue: _Direction = getattr(self, direction)
        async with self.condition:
            queue.acknowledge(ack)
            result = queue.after(after, limit)
            if result or self.closed or timeout <= 0:
                return result
            try:
                await asyncio.wait_for(self.condition.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                return []
            return queue.after(after, limit)

    async def close(self) -> None:
        async with self.condition:
            self.closed = True
            self.condition.notify_all()


class RelayRegistry:
    def __init__(self) -> None:
        self._relays: dict[str, SessionRelay] = {}
        self._lock = asyncio.Lock()

    async def create(
        self,
        session_id: str,
        *,
        input_seq: int = 0,
        output_seq: int = 0,
        max_input_bytes: int,
        max_output_bytes: int,
        max_frames: int,
    ) -> SessionRelay:
        async with self._lock:
            relay = self._relays.get(session_id)
            if relay is None or relay.closed:
                relay = SessionRelay(
                    input_seq=input_seq,
                    output_seq=output_seq,
                    max_input_bytes=max_input_bytes,
                    max_output_bytes=max_output_bytes,
                    max_frames=max_frames,
                )
                self._relays[session_id] = relay
            return relay

    async def get(self, session_id: str) -> SessionRelay | None:
        async with self._lock:
            return self._relays.get(session_id)

    async def close(self, session_id: str) -> None:
        relay = await self.get(session_id)
        if relay is not None:
            await relay.close()

    async def reset_for_tests(self) -> None:
        async with self._lock:
            relays = list(self._relays.values())
            self._relays.clear()
        for relay in relays:
            await relay.close()


registry = RelayRegistry()
