"""Opt-in, privacy-safe ACP request/attempt stage tracing (issue #26).

Purpose: make it observable WHERE an ACP request spent time and WHY a turn
looked stalled, without ever recording conversation content. This is a
diagnostic surface, not a retry policy: it records only events the plugin or
the mux directly observes, and records ``unknown`` whenever the underlying
cause (vendor-side retries, capacity errors, queue position) is not exposed
on the public ACP protocol. Silence is never classified as a vendor 503.

Contract (one JSONL line per event)::

    {"t_mono": float, "stage": str, "req_key": str, "pid": int|null, "detail": {...}}

* ``t_mono``  — seconds (monotonic) since this tracer instance was created.
  Never wall-clock: no cross-machine joins, no clock-skew corruption.
* ``stage``   — fixed enum, see :data:`TRACE_STAGES`.
* ``req_key`` — ephemeral salted hash (``_opaque_permission_id`` domain).
  Per-attempt keys join the ACP lifecycle stages; the per-client-instance
  request key joins attempts of one logical request. Never a stable global
  identifier: keys are derived from fresh ``uuid4`` material per attempt.
* ``pid``     — the plugin's direct child pid. With the optional mux this is
  the mux process pid; the mux's own trace records ``mux_pid`` (join key)
  plus its ``child_pid`` and the lane fingerprint.
* ``detail``  — bounded, non-sensitive classification only (elapsed ms, byte
  counts, protocol method names, stopReason, exit code, salted hashes,
  classification enums, explicit ``unknown``). Values are sanitized at the
  emit boundary: scalars only, strings truncated, anything else redacted.

Privacy invariants (enforced structurally, not by convention):

* No prompt or response text, no OAuth/credential material, no raw native
  session UUIDs, no raw account labels, no filesystem paths, no unbounded
  request history. Callers pass only classification values; the sanitizer is
  a second line of defense, not the primary guarantee.

Bounds: at most ``max_events_per_request`` events (plus one truncation
marker) per ``req_key``; the trace file rotates at ``max_file_bytes`` into a
single ``.1`` sibling (the mux log's existing pattern, no ``fcntl``, so it
degrades identically on Windows); the per-key counter table is capped.

Cost when disabled: ``get_tracer()`` returns ``None`` after one env lookup;
every call site is a single ``is None`` check. No file is created.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable

TRACE_ENV = "HERMES_ANTIGRAVITY_ACP_TRACE"
TRACE_FILE_ENV = "HERMES_ANTIGRAVITY_ACP_TRACE_FILE"
TRACE_SILENCE_ENV = "HERMES_ANTIGRAVITY_ACP_TRACE_SILENCE_SECONDS"

# The eight lifecycle stages from the issue contract, plus the two bounded
# classification stages (local response rejection / observed retry decision)
# and ``unknown`` for explicitly-unobservable events (silence heartbeat,
# deadline with no protocol evidence).
TRACE_STAGES = frozenset(
    {
        "lane_bound",
        "initialize",
        "session_new_or_resume",
        "prompt_sent",
        "first_update",
        "prompt_response",
        "cancel_requested",
        "process_exit",
        "response_rejected",
        "retry_attempt",
        "unknown",
    }
)

DEFAULT_MAX_FILE_BYTES = 200_000
DEFAULT_MAX_EVENTS_PER_REQUEST = 64
DEFAULT_SILENCE_SECONDS = 60.0
_MAX_TRACKED_REQ_KEYS = 1024
_MAX_DETAIL_STRING = 160


def trace_enabled() -> bool:
    return os.environ.get(TRACE_ENV, "").strip() == "1"


def silence_seconds() -> float:
    raw = os.environ.get(TRACE_SILENCE_ENV, "").strip()
    if not raw:
        return DEFAULT_SILENCE_SECONDS
    try:
        value = float(raw)
    except ValueError:
        return DEFAULT_SILENCE_SECONDS
    return value if value > 0 else DEFAULT_SILENCE_SECONDS


def default_trace_path() -> Path:
    override = os.environ.get(TRACE_FILE_ENV, "").strip()
    if override:
        return Path(override).expanduser()
    from .hermes_compat import get_hermes_home
    from .native_limit_state import _profile_neutral_hermes_home

    return (
        _profile_neutral_hermes_home(get_hermes_home())
        / "logs"
        / "acp-stage-trace.jsonl"
    )


def _sanitize_scalar(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return round(value, 3)
    if isinstance(value, str):
        return value[:_MAX_DETAIL_STRING]
    # Anything structured (lists, dicts, objects) never belongs in detail.
    return "redacted"


def _sanitize_detail(detail: Any) -> dict[str, Any]:
    if not isinstance(detail, dict):
        return {}
    return {
        str(key)[:48]: _sanitize_scalar(value)
        for key, value in list(detail.items())[:16]
    }


class StageTracer:
    """Thread-safe, bounded JSONL stage-trace writer (see module docstring)."""

    def __init__(
        self,
        path: Path,
        *,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_events_per_request: int = DEFAULT_MAX_EVENTS_PER_REQUEST,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._path = Path(path)
        self._max_file_bytes = int(max_file_bytes)
        self._max_events_per_request = int(max_events_per_request)
        self._clock = clock
        self._t0 = clock()
        self._lock = threading.Lock()
        self._counts: dict[str, int] = {}
        self._failed = False

    def elapsed(self) -> float:
        return self._clock() - self._t0

    def emit(
        self,
        *,
        stage: str,
        req_key: str,
        pid: int | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        if self._failed:
            return
        stage = stage if stage in TRACE_STAGES else "unknown"
        req_key = str(req_key or "unknown")[:128]
        with self._lock:
            if self._failed:
                return
            count = self._counts.get(req_key, 0)
            if count >= self._max_events_per_request + 1:
                return
            self._counts[req_key] = count + 1
            if len(self._counts) > _MAX_TRACKED_REQ_KEYS:
                for stale in list(self._counts)[: _MAX_TRACKED_REQ_KEYS // 2]:
                    self._counts.pop(stale, None)
            if count == self._max_events_per_request:
                detail = {"classification": "trace_truncated"}
            record = {
                "t_mono": round(self.elapsed(), 3),
                "stage": stage,
                "req_key": req_key,
                "pid": int(pid) if isinstance(pid, (int,)) or (
                    isinstance(pid, float) and float(pid).is_integer()
                ) else None,
                "detail": _sanitize_detail(detail),
            }
            try:
                directory = self._path.parent
                directory.mkdir(parents=True, exist_ok=True)
                if (
                    self._path.exists()
                    and self._path.stat().st_size > self._max_file_bytes
                ):
                    os.replace(self._path, self._path.with_name(self._path.name + ".1"))
                with self._path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(record, ensure_ascii=True) + "\n")
            except OSError:
                # A trace must never take down or stall a request. One write
                # failure disables the tracer for the process lifetime.
                self._failed = True


_tracer: StageTracer | None = None
_tracer_lock = threading.Lock()


def get_tracer() -> StageTracer | None:
    """Return the process-wide tracer when tracing is enabled, else ``None``.

    The env var is read on every call, so a disabled process never allocates
    the tracer; once enabled, all callers share one writer (one lock, one
    rotation decision) so concurrent requests cannot interleave partial lines.
    """
    global _tracer
    if not trace_enabled():
        return None
    with _tracer_lock:
        if _tracer is None:
            _tracer = StageTracer(default_trace_path())
        return _tracer
