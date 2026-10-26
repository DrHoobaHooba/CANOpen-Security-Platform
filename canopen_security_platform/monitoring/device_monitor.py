"""Live device-response monitor for CANopen fuzzing.

Attaches a python-can :class:`can.Notifier` to the active bus and classifies
inbound CANopen frames (EMCY, heartbeat, boot-up) as device events or
anomalies via the :class:`~canopen_security_platform.monitoring.oracle.Oracle`.

This runs concurrently with the fuzzing stages so that genuine device
reactions are captured, rather than only the fuzz inputs we transmit. Without
it the oracle never sees any ``device_anomaly_detected`` events and the report
always shows zero device anomalies.

In addition to per-frame classification it performs two higher-level checks:

* **NMT state-regression detection** - flags a node that drops out of the
  OPERATIONAL state (to STOPPED or PRE-OPERATIONAL) unexpectedly, which usually
  means fuzzing disrupted the device.
* **Liveness watchdog** - learns each node's heartbeat interval and raises a
  communication-timeout anomaly if a previously-live node goes silent, which
  catches a device that has crashed or hung under load. Recovery (the node
  resuming heartbeats) is logged and re-arms the watchdog.

Note:
    The bus is opened with ``receive_own_messages`` disabled, so the frames we
    transmit while fuzzing (including spoofed EMCY/heartbeat frames) are not
    echoed back. Only genuine responses from devices on the bus are observed.
"""

import threading
import time
from typing import Dict, List, Optional

import can

from .oracle import Oracle
from ..utils.logging_utils import get_logger

logger = get_logger(__name__)

# CANopen pre-defined connection set COB-ID ranges (function code | node-id).
SYNC_COB_ID = 0x080
EMCY_COB_MIN = 0x081
EMCY_COB_MAX = 0x0FF
HEARTBEAT_COB_MIN = 0x701
HEARTBEAT_COB_MAX = 0x77F
NODE_ID_MASK = 0x7F

# NMT / error-control state bytes carried in a heartbeat frame.
BOOTUP_STATE = 0x00
STATE_STOPPED = 0x04
STATE_OPERATIONAL = 0x05
STATE_PRE_OPERATIONAL = 0x7F

# States considered a regression when a node leaves OPERATIONAL unexpectedly.
_REGRESSION_STATES = (STATE_STOPPED, STATE_PRE_OPERATIONAL)

_STATE_NAMES = {
    BOOTUP_STATE: "BOOT_UP",
    STATE_STOPPED: "STOPPED",
    STATE_OPERATIONAL: "OPERATIONAL",
    STATE_PRE_OPERATIONAL: "PRE_OPERATIONAL",
}


def _state_name(state: int) -> str:
    return _STATE_NAMES.get(state, f"0x{state:02X}")


class _DeviceResponseListener(can.Listener):
    """python-can listener that routes device frames to the oracle.

    Args:
        oracle: Oracle instance that records and classifies events.
        liveness_timeout_floor: Minimum silence (seconds) before a node is
            considered timed out, regardless of its learned interval.
        liveness_interval_factor: Multiplier applied to a node's learned
            heartbeat interval to decide the silence threshold.
    """

    def __init__(
        self,
        oracle: Oracle,
        liveness_timeout_floor: float = 2.0,
        liveness_interval_factor: float = 3.0,
    ) -> None:
        self.oracle = oracle
        self.frames_seen = 0
        self.emcy_seen = 0
        self.heartbeat_seen = 0
        self.bootup_seen = 0
        self.state_regressions = 0
        self.timeouts = 0
        self.recoveries = 0

        self._timeout_floor = liveness_timeout_floor
        self._interval_factor = liveness_interval_factor

        self._lock = threading.Lock()
        # Per-node tracking for state-regression and liveness detection.
        self._nmt_state: Dict[int, int] = {}
        self._last_seen: Dict[int, float] = {}
        self._interval: Dict[int, float] = {}
        self._hb_count: Dict[int, int] = {}
        self._timed_out: set = set()

    def on_message_received(self, msg: can.Message) -> None:
        try:
            if msg.is_extended_id or msg.is_error_frame or msg.is_remote_frame:
                return

            cob_id = msg.arbitration_id
            node_id = cob_id & NODE_ID_MASK
            data = bytes(msg.data)
            now = time.time()

            if EMCY_COB_MIN <= cob_id <= EMCY_COB_MAX:
                self.frames_seen += 1
                self.emcy_seen += 1
                self._note_alive(node_id, now, is_heartbeat=False)
                code = int.from_bytes(data[:2], "little") if len(data) >= 2 else 0
                additional = data[2:] if len(data) > 2 else b""
                self.oracle.on_emcy(node_id, code, additional)

            elif HEARTBEAT_COB_MIN <= cob_id <= HEARTBEAT_COB_MAX:
                self.frames_seen += 1
                state = (data[0] & NODE_ID_MASK) if data else 0
                self._note_alive(node_id, now, is_heartbeat=True)
                if state == BOOTUP_STATE:
                    # A boot-up frame during fuzzing means the device reset
                    # itself unexpectedly, which is a device anomaly.
                    self.bootup_seen += 1
                    with self._lock:
                        self._nmt_state[node_id] = BOOTUP_STATE
                    self.oracle.on_reboot(node_id)
                else:
                    self.heartbeat_seen += 1
                    self._check_state_regression(node_id, state)
                    self.oracle.on_heartbeat(node_id, state)

        except Exception:
            logger.exception("Error processing monitored frame")

    def _check_state_regression(self, node_id: int, state: int) -> None:
        """Flag an unexpected drop out of OPERATIONAL as an anomaly."""
        with self._lock:
            old = self._nmt_state.get(node_id)
            self._nmt_state[node_id] = state
        if old == STATE_OPERATIONAL and state in _REGRESSION_STATES:
            self.state_regressions += 1
            self.oracle.on_state_regression(
                node_id, _state_name(old), _state_name(state)
            )

    def _note_alive(self, node_id: int, now: float, is_heartbeat: bool) -> None:
        """Update liveness bookkeeping and emit recovery if a node returns."""
        recovered = False
        with self._lock:
            prev = self._last_seen.get(node_id)
            self._last_seen[node_id] = now
            if is_heartbeat:
                self._hb_count[node_id] = self._hb_count.get(node_id, 0) + 1
                if prev is not None:
                    delta = now - prev
                    if 0 < delta < 60:
                        old_i = self._interval.get(node_id)
                        # Exponential moving average of the heartbeat interval.
                        self._interval[node_id] = (
                            delta if old_i is None else (old_i * 0.7 + delta * 0.3)
                        )
            if node_id in self._timed_out:
                self._timed_out.discard(node_id)
                recovered = True
        if recovered:
            self.recoveries += 1
            logger.info("Node %d resumed communication after timeout", node_id)

    def scan_timeouts(self, now: Optional[float] = None) -> List[int]:
        """Raise a timeout anomaly for any node that has gone silent.

        A node is considered live once it has produced at least two heartbeats
        (so an interval can be learned). It times out after
        ``max(timeout_floor, interval * interval_factor)`` seconds of silence.
        Fires at most once per silence episode.
        """
        now = now if now is not None else time.time()
        newly_timed_out: List[int] = []
        with self._lock:
            for node_id, last in list(self._last_seen.items()):
                if node_id in self._timed_out:
                    continue
                if self._hb_count.get(node_id, 0) < 2:
                    continue
                interval = self._interval.get(node_id, self._timeout_floor)
                threshold = max(self._timeout_floor, interval * self._interval_factor)
                if now - last > threshold:
                    self._timed_out.add(node_id)
                    newly_timed_out.append(node_id)
        for node_id in newly_timed_out:
            self.timeouts += 1
            self.oracle.on_timeout(node_id)
        return newly_timed_out

    def on_error(self, exc: Exception) -> None:
        logger.debug("Device monitor listener error: %s", exc)


class DeviceMonitor:
    """Observe device responses on the bus and feed them to the oracle.

    Args:
        oracle: Oracle instance that records and classifies events.
        bus: Underlying python-can bus instance to listen on.
        liveness_timeout_floor: Minimum silence before a timeout is raised.
        liveness_interval_factor: Multiplier on the learned heartbeat interval.
        watchdog_period: How often (seconds) the liveness watchdog scans.
    """

    def __init__(
        self,
        oracle: Oracle,
        bus: Optional[can.BusABC],
        liveness_timeout_floor: float = 2.0,
        liveness_interval_factor: float = 3.0,
        watchdog_period: float = 0.5,
    ) -> None:
        self.oracle = oracle
        self.bus = bus
        self._listener = _DeviceResponseListener(
            oracle,
            liveness_timeout_floor=liveness_timeout_floor,
            liveness_interval_factor=liveness_interval_factor,
        )
        self._notifier: Optional[can.Notifier] = None
        self._watchdog_period = watchdog_period
        self._watchdog: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    @property
    def running(self) -> bool:
        """Return True while the monitor is actively listening."""
        return self._notifier is not None

    @property
    def frames_seen(self) -> int:
        """Total device frames observed (EMCY + heartbeat + boot-up)."""
        return self._listener.frames_seen

    @property
    def stats(self) -> dict:
        """Breakdown of observed frame types and derived anomalies."""
        return {
            "frames_seen": self._listener.frames_seen,
            "emcy_seen": self._listener.emcy_seen,
            "heartbeat_seen": self._listener.heartbeat_seen,
            "bootup_seen": self._listener.bootup_seen,
            "state_regressions": self._listener.state_regressions,
            "timeouts": self._listener.timeouts,
            "recoveries": self._listener.recoveries,
        }

    def _watchdog_loop(self) -> None:
        while not self._stop_event.wait(self._watchdog_period):
            try:
                self._listener.scan_timeouts()
            except Exception:
                logger.exception("Device monitor watchdog error")

    def start(self) -> bool:
        """Start listening. Returns True if the monitor was started."""
        if self._notifier is not None:
            return True
        if self.bus is None:
            logger.warning(
                "DeviceMonitor: no active bus available; anomaly monitoring disabled"
            )
            return False
        try:
            self._notifier = can.Notifier(self.bus, [self._listener], timeout=1.0)
        except Exception as e:
            logger.error("DeviceMonitor failed to start: %s", e)
            self._notifier = None
            return False
        self._stop_event.clear()
        self._watchdog = threading.Thread(
            target=self._watchdog_loop, name="device-monitor-watchdog", daemon=True
        )
        self._watchdog.start()
        logger.info(
            "DeviceMonitor started (EMCY/heartbeat/boot-up classification, "
            "state-regression + liveness watchdog)"
        )
        return True

    def stop(self) -> None:
        """Stop listening and release the notifier."""
        if self._notifier is None:
            return
        self._stop_event.set()
        if self._watchdog is not None:
            self._watchdog.join(timeout=2.0)
            self._watchdog = None
        try:
            self._notifier.stop(timeout=2.0)
        except Exception as e:
            logger.warning("DeviceMonitor stop error: %s", e)
        finally:
            self._notifier = None
        logger.info(
            "DeviceMonitor stopped (observed %d device frames: "
            "%d EMCY, %d heartbeat, %d boot-up, %d state-regression, %d timeout)",
            self._listener.frames_seen,
            self._listener.emcy_seen,
            self._listener.heartbeat_seen,
            self._listener.bootup_seen,
            self._listener.state_regressions,
            self._listener.timeouts,
        )
