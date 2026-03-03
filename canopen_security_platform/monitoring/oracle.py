import logging
from typing import Any, Callable, List, Dict, Optional
import time
import json
from pathlib import Path
from collections import defaultdict

from ..utils.logging_utils import get_logger

logger = get_logger(__name__)


class AlertRule:
    """Define conditions that trigger alerts."""

    def __init__(
        self,
        name: str,
        event_type: str,
        condition: Callable[[Dict[str, Any]], bool],
        severity: str = "warning",
    ) -> None:
        """Initialize alert rule.
        
        Args:
            name: Rule name
            event_type: Type of event (emcy, heartbeat, timeout, etc.)
            condition: Callable that returns True if alert should trigger
            severity: Alert severity (info, warning, critical)
        """
        self.name = name
        self.event_type = event_type
        self.condition = condition
        self.severity = severity
        self.matches = 0  # Counter of alerts triggered

    def check(self, event: Dict[str, Any]) -> bool:
        """Check if event matches this rule."""
        try:
            if self.condition(event):
                self.matches += 1
                return True
        except Exception as e:
            logger.debug("Alert rule %s check failed: %s", self.name, e)
        return False


class Oracle:
    """Track and analyze CANopen node behavior.
    
    Records events (EMCY, heartbeat, timeouts, reboots) and applies
    alert rules for anomaly detection. Can persist events to file/database.
    """

    def __init__(self, persist_dir: Optional[str] = None) -> None:
        """Initialize oracle.
        
        Args:
            persist_dir: Save events to this directory; None disables persistence
        """
        self.persist_dir = Path(persist_dir) if persist_dir else None
        if self.persist_dir:
            self.persist_dir.mkdir(parents=True, exist_ok=True)
        
        self.events: List[Dict[str, Any]] = []
        self.node_states: Dict[int, Dict[str, Any]] = {}
        self.emcy_history: Dict[int, list] = defaultdict(list)
        self.heartbeat_history: Dict[int, list] = defaultdict(list)
        self.alert_rules: List[AlertRule] = []
        self.triggered_alerts: List[Dict[str, Any]] = []
        self.start_time = time.time()

    def add_alert_rule(self, rule: AlertRule) -> None:
        """Register an alert rule."""
        self.alert_rules.append(rule)
        logger.debug("Registered alert rule: %s", rule.name)

    def on_emcy(
        self,
        node_id: int,
        code: int,
        additional: bytes,
    ) -> None:
        """Record EMCY event.
        
        Args:
            node_id: Node ID
            code: EMCY error code (0x0000-0xFFFF)
            additional: Additional 5 bytes of EMCY data
        """
        event = {
            "type": "emcy",
            "timestamp": time.time(),
            "node_id": node_id,
            "error_code": code,
            "additional_data": additional.hex() if additional else "00000000",
        }
        
        self._record_event(event)
        self.emcy_history[node_id].append(event)
        self.node_states.setdefault(node_id, {})["last_emcy"] = event
        
        # Decode common error codes
        error_desc = self._decode_emcy_code(code)
        logger.warning(
            "EMCY from node %d: code=0x%04X %s (data=%s)",
            node_id, code, error_desc, additional.hex() if additional else "(empty)"
        )
        
        self._check_alert_rules(event)

    def on_heartbeat(
        self,
        node_id: int,
        state: int,
    ) -> None:
        """Record heartbeat event.
        
        Args:
            node_id: Node ID
            state: NMT state byte
        """
        event = {
            "type": "heartbeat",
            "timestamp": time.time(),
            "node_id": node_id,
            "state": state,
            "state_name": self._nmt_state_name(state),
        }
        
        self._record_event(event)
        self.heartbeat_history[node_id].append(event)
        
        old_state = self.node_states.get(node_id, {}).get("nmt_state")
        self.node_states.setdefault(node_id, {})["nmt_state"] = state
        
        if old_state is not None and old_state != state:
            logger.debug(
                "Node %d state transition: %s -> %s",
                node_id, self._nmt_state_name(old_state), event["state_name"]
            )
        
        self._check_alert_rules(event)

    def on_state_change(
        self,
        node_id: int,
        old: Any,
        new: Any,
    ) -> None:
        """Record explicit state change."""
        event = {
            "type": "state_change",
            "timestamp": time.time(),
            "node_id": node_id,
            "old_state": str(old),
            "new_state": str(new),
        }
        
        self._record_event(event)
        logger.info(
            "State change on node %d: %s -> %s",
            node_id, old, new
        )
        self._check_alert_rules(event)

    def on_timeout(
        self,
        node_id: int,
    ) -> None:
        """Record communication timeout."""
        event = {
            "type": "timeout",
            "timestamp": time.time(),
            "node_id": node_id,
        }
        
        self._record_event(event)
        self.node_states.setdefault(node_id, {})["last_timeout"] = event
        
        logger.warning("Communication timeout on node %d", node_id)
        self._check_alert_rules(event)

    def on_reboot(
        self,
        node_id: int,
    ) -> None:
        """Record detected reboot."""
        event = {
            "type": "reboot",
            "timestamp": time.time(),
            "node_id": node_id,
        }
        
        self._record_event(event)
        self.node_states.setdefault(node_id, {})["reboots"] = (
            self.node_states[node_id].get("reboots", 0) + 1
        )
        
        logger.warning("Reboot detected on node %d", node_id)
        self._check_alert_rules(event)

    def _record_event(self, event: Dict[str, Any]) -> None:
        """Record event in memory and optionally persist."""
        self.events.append(event)
        
        # Persist if enabled
        if self.persist_dir:
            self._persist_event(event)

    def _persist_event(self, event: Dict[str, Any]) -> None:
        """Persist event to file."""
        try:
            # Append to events log
            log_file = self.persist_dir / "events.jsonl"
            with open(log_file, "a") as f:
                f.write(json.dumps(event) + "\n")
        except Exception as e:
            logger.error("Failed to persist event: %s", e)

    def _check_alert_rules(self, event: Dict[str, Any]) -> None:
        """Check if event triggers any alert rules."""
        for rule in self.alert_rules:
            if rule.event_type == event["type"] and rule.check(event):
                alert = {
                    "rule_name": rule.name,
                    "severity": rule.severity,
                    "event": event,
                    "triggered_at": time.time(),
                }
                self.triggered_alerts.append(alert)
                
                log_fn = {
                    "info": logger.info,
                    "warning": logger.warning,
                    "critical": logger.critical,
                }.get(rule.severity, logger.warning)
                
                log_fn(
                    "Alert triggered: %s (severity=%s) on node %d",
                    rule.name, rule.severity, event.get("node_id")
                )

    def get_node_summary(self, node_id: int) -> Dict[str, Any]:
        """Get behavior summary for a node."""
        return {
            "node_id": node_id,
            "current_state": self.node_states.get(node_id, {}),
            "emcy_count": len(self.emcy_history.get(node_id, [])),
            "heartbeat_count": len(self.heartbeat_history.get(node_id, [])),
            "timeout_count": sum(
                1 for e in self.events
                if e.get("type") == "timeout" and e.get("node_id") == node_id
            ),
            "reboot_count": self.node_states.get(node_id, {}).get("reboots", 0),
        }

    def get_event_log(self, node_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get event log filtered by optional node ID."""
        if node_id is None:
            return self.events
        return [e for e in self.events if e.get("node_id") == node_id]

    def get_triggered_alerts(self) -> List[Dict[str, Any]]:
        """Get all triggered alerts."""
        return self.triggered_alerts

    def export_report(self, output_path: str) -> str:
        """Export comprehensive report to JSON."""
        report = {
            "metadata": {
                "start_time": self.start_time,
                "export_time": time.time(),
                "duration_seconds": time.time() - self.start_time,
            },
            "statistics": {
                "total_events": len(self.events),
                "monitored_nodes": len(self.node_states),
                "total_alerts": len(self.triggered_alerts),
            },
            "node_summaries": {
                node_id: self.get_node_summary(node_id)
                for node_id in self.node_states.keys()
            },
            "recent_events": self.events[-100:],  # Last 100 events
            "triggered_alerts": self.triggered_alerts[-50:],  # Last 50 alerts
        }
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info("Report exported to %s", output_file)
        return str(output_file)

    @staticmethod
    def _decode_emcy_code(code: int) -> str:
        """Decode CANopen EMCY error codes."""
        if code == 0x0000:
            return "(no error / error reset)"
        elif code == 0x1000:
            return "(generic error)"
        elif code == 0x2000:
            return "(current)"
        elif code == 0x3000:
            return "(voltage)"
        elif code == 0x4000:
            return "(temperature)"
        elif code == 0x5000:
            return "(device hardware)"
        elif code == 0x6000:
            return "(device software)"
        elif code == 0x7000:
            return "(additional modules)"
        elif code == 0x8000:
            return "(monitoring)"
        elif code == 0x9000:
            return "(external error)"
        elif code == 0xF000:
            return "(device specific)"
        else:
            return "(unknown)"

    @staticmethod
    def _nmt_state_name(state: int) -> str:
        """Convert NMT state byte to name."""
        states = {
            0x00: "INITIALIZING",
            0x04: "STOPPED",
            0x05: "OPERATIONAL",
            0x7F: "PRE_OPERATIONAL",
        }
        return states.get(state, f"UNKNOWN(0x{state:02X})")
