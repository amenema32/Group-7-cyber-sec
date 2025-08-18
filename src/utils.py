#UTILS_PY = r"""
import os
import time
from typing import IO


class RotatingTail:
   
    def __init__(self, path: str, poll_interval: float = 0.5):
        self.path = path
        self.poll = poll_interval
        self._fh: IO | None = None
        self._ino = None

    def _stat_sig(self):
        st = os.stat(self.path)
        # On Windows, st_ino may be 0; we still use size as a signal.
        return (getattr(st, "st_ino", None), st.st_size)

    def _open(self):
        if self._fh:
            self._fh.close()
        self._fh = open(self.path, "r", encoding="utf-8", errors="ignore")
        # Seek to end on start (follow new lines only)
        self._fh.seek(0, os.SEEK_END)
        self._ino, _ = self._stat_sig()

    def follow(self):
        self._open()
        last_size = 0
        while True:
            try:
                line = self._fh.readline()
                if line:
                    yield line
                    continue
                # No new line: check rotation/size
                time.sleep(self.poll)
                ino, size = self._stat_sig()
                rotated = False
                if ino is not None and self._ino is not None and ino != self._ino:
                    rotated = True
                elif size < self._fh.tell():
                    rotated = True
                if rotated:
                    self._open()
            except FileNotFoundError:
                # Wait until file appears
                time.sleep(self.poll)
                continue
