"""Resource sampling for measured runs (MASTER_PLAN section 7.3, cost/resources).

Two rules decide the shape of this module:

* CPU is reported as a percentage of **one core**, averaged over the sampled window
  (``top`` convention), and the window interval plus the host core count are recorded
  next to it so the number cannot be re-read as a whole-machine figure by mistake.
* A process that cannot be sampled yields no number at all. Sampling is only possible
  on Linux ``/proc``, so on any other platform - or for a layer that is not running in
  this config (agent, XDP) - the field is reported as unavailable with a status.

    sampler = Sampler(api_pid, interval_s=1.0)
    sampler.start()
    ...
    result = sampler.stop()      # {"app_cpu_pct": ..., "app_rss_mb": ..., "status": ...}
"""

from __future__ import annotations

import pathlib
import threading
import time

PROC = pathlib.Path("/proc")
CLOCK_TICKS = 100  # Linux USER_HZ; refined from os.sysconf when available


def _clock_ticks() -> int:
    try:
        return int(__import__("os").sysconf("SC_CLK_TCK"))
    except (AttributeError, ValueError, OSError):
        return CLOCK_TICKS


def supported() -> bool:
    return (PROC / "self" / "stat").is_file()


def sample_process(pid: int) -> dict | None:
    """Return cumulative CPU seconds and current RSS for ``pid``, or None."""
    stat = PROC / str(pid) / "stat"
    try:
        raw = stat.read_text(encoding="utf-8")
    except OSError:
        return None
    # The comm field may contain spaces and parentheses: split after the last ')'.
    try:
        fields = raw.rsplit(")", 1)[1].split()
        ticks = int(fields[11]) + int(fields[12])  # utime, stime
    except (IndexError, ValueError):
        return None
    rss_mb = 0.0
    try:
        for line in (PROC / str(pid) / "status").read_text(encoding="utf-8").splitlines():
            if line.startswith("VmRSS:"):
                rss_mb = int(line.split()[1]) / 1024.0
                break
    except (OSError, IndexError, ValueError):
        return None
    return {"cpu_s": ticks / _clock_ticks(), "rss_mb": rss_mb, "monotonic": time.monotonic()}


def summarise(samples: list[dict]) -> dict:
    """Turn raw samples into the manifest/result fields, or an explicit status."""
    usable = [s for s in samples if s.get("cpu_s") is not None and s.get("monotonic") is not None]
    if len(usable) < 2:
        return {"status": "insufficient_samples", "samples": len(samples),
                "cpu_pct": None, "rss_mb": None, "interval_s": None}
    first, last = usable[0], usable[-1]
    elapsed = float(last["monotonic"]) - float(first["monotonic"])
    if elapsed <= 0:
        return {"status": "insufficient_samples", "samples": len(samples),
                "cpu_pct": None, "rss_mb": None, "interval_s": None}
    cpu_pct = (float(last["cpu_s"]) - float(first["cpu_s"])) / elapsed * 100.0
    rss_values = [float(s["rss_mb"]) for s in usable if s.get("rss_mb") is not None]
    return {
        "status": "ok",
        "samples": len(usable),
        "interval_s": round(elapsed / (len(usable) - 1), 3),
        "cpu_pct": round(max(0.0, cpu_pct), 2),
        "rss_mb_peak": round(max(rss_values), 1) if rss_values else None,
    }


class Sampler:
    """Poll one process in a background thread for the duration of the measured phase."""

    def __init__(self, pid: int, interval_s: float = 1.0):
        self.pid = pid
        self.interval_s = interval_s
        self._samples: list[dict] = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if not supported():
            return
        self._thread = threading.Thread(target=self._loop, name="p20-sampler", daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.is_set():
            entry = sample_process(self.pid)
            if entry is not None:
                self._samples.append(entry)
            self._stop.wait(self.interval_s)

    def stop(self) -> dict:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2 * self.interval_s + 1)
        if not supported():
            return {"status": "proc_unavailable", "samples": 0,
                    "cpu_pct": None, "rss_mb_peak": None, "interval_s": None}
        return summarise(self._samples)
