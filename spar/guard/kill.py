"""Kill switch: a stop file or Ctrl-C revokes all active leases immediately."""

from __future__ import annotations

import signal
import threading
from pathlib import Path


class KillSwitch:
    def __init__(self, stop_file: Path):
        self.stop_file = Path(stop_file)
        self._tripped = threading.Event()
        self._prev_handler = None

    def install_signal(self) -> None:
        def handler(signum, frame):  # noqa: ANN001
            self._tripped.set()
            try:
                self.stop_file.write_text(f"signal {signum}\n", encoding="utf-8")
            except OSError:
                pass
            # Second Ctrl-C hard-exits.
            signal.signal(signal.SIGINT, signal.SIG_DFL)

        try:
            self._prev_handler = signal.signal(signal.SIGINT, handler)
        except ValueError:
            pass  # not on main thread

    def uninstall_signal(self) -> None:
        if self._prev_handler is not None:
            try:
                signal.signal(signal.SIGINT, self._prev_handler)
            except (ValueError, OSError):
                pass
            self._prev_handler = None

    def trip(self, reason: str) -> None:
        self._tripped.set()
        try:
            self.stop_file.write_text(reason + "\n", encoding="utf-8")
        except OSError:
            pass

    @property
    def tripped(self) -> bool:
        if self._tripped.is_set():
            return True
        if self.stop_file.exists():
            self._tripped.set()
            return True
        return False

    def check(self) -> None:
        if self.tripped:
            raise KeyboardInterrupt("spar kill switch tripped (stop file or Ctrl-C)")
