import logging
from typing import Callable, Any, Optional, Dict
from queue import Queue
from threading import Thread
import time

import canopen

from .oracle import Oracle
from ..utils.logging_utils import get_logger

logger = get_logger(__name__)


class EventHandlers:
    """Attach CANopen event callbacks to oracle.
    
    Handles EMCY, heartbeat, and custom events with support for
    synchronous and asynchronous processing.
    """

    def __init__(self, oracle: Oracle, async_mode: bool = False) -> None:
        """Initialize event handlers.
        
        Args:
            oracle: Oracle instance for event recording
            async_mode: If True, process events asynchronously via queue
        """
        self.oracle = oracle
        self.async_mode = async_mode
        self.event_queue: Optional[Queue[Dict[str, Any]]] = None
        self.processing_thread: Optional[Thread] = None
        self.stop_processing = False
        
        if async_mode:
            self.event_queue = Queue(maxsize=1000)
            self._start_processing_thread()

    def attach(self, network: canopen.Network) -> None:
        """Attach event handlers to network.
        
        Args:
            network: CANopen network instance
        """
        logger.debug("Attaching event handlers to network")
        
        try:
            network.add_emcy_callback(self._on_emcy)
            logger.debug("EMCY callback attached")
        except Exception as e:
            logger.warning("Failed to attach EMCY callback: %s", e)
        
        try:
            network.add_heartbeat_callback(self._on_heartbeat)
            logger.debug("Heartbeat callback attached")
        except Exception as e:
            logger.warning("Failed to attach heartbeat callback: %s", e)
        
        try:
            network.add_sync_callback(self._on_sync)
            logger.debug("SYNC callback attached")
        except Exception as e:
            logger.debug("SYNC callback not available: %s", e)

    def _on_emcy(self, can_id: int, data: bytes) -> None:
        """Handle EMCY frame.
        
        EMCY frame format:
        - Bytes 0-1: Error code (little-endian)
        - Byte 2: Error register
        - Bytes 3-7: Manufacturer specific
        """
        try:
            node_id = can_id & 0x7F
            error_code = int.from_bytes(data[:2], byteorder="little")
            additional = data[2:] if len(data) > 2 else b"\x00\x00\x00\x00\x00"
            
            event = {
                "type": "emcy_callback",
                "timestamp": time.time(),
                "can_id": can_id,
                "node_id": node_id,
                "error_code": error_code,
                "error_register": additional[0] if additional else 0,
                "raw_data": data.hex(),
            }
            
            if self.async_mode and self.event_queue:
                try:
                    self.event_queue.put_nowait(event)
                except Exception as e:
                    logger.warning("Failed to queue EMCY event: %s", e)
                    self.oracle.on_emcy(node_id, error_code, additional)
            else:
                self.oracle.on_emcy(node_id, error_code, additional)
        
        except Exception as e:
            logger.error("Error processing EMCY frame: %s", e)

    def _on_heartbeat(self, can_id: int, data: bytes) -> None:
        """Handle heartbeat/boot-up frame.
        
        Boot-up/Heartbeat frame format:
        - Bit 7: 1=boot-up, 0=heartbeat
        - Bits 0-6: NMT state
        """
        try:
            node_id = can_id & 0x7F
            state_byte = data[0] if data else 0
            boot_up = (state_byte & 0x80) != 0
            nmt_state = state_byte & 0x7F
            
            event = {
                "type": "heartbeat_callback",
                "timestamp": time.time(),
                "can_id": can_id,
                "node_id": node_id,
                "state": nmt_state,
                "boot_up": boot_up,
            }
            
            if self.async_mode and self.event_queue:
                try:
                    self.event_queue.put_nowait(event)
                except Exception as e:
                    logger.warning("Failed to queue heartbeat event: %s", e)
                    self.oracle.on_heartbeat(node_id, nmt_state)
            else:
                self.oracle.on_heartbeat(node_id, nmt_state)
        
        except Exception as e:
            logger.error("Error processing heartbeat frame: %s", e)

    def _on_sync(self, can_id: int, data: bytes) -> None:
        """Handle SYNC frame."""
        try:
            event = {
                "type": "sync_callback",
                "timestamp": time.time(),
                "can_id": can_id,
            }
            
            if self.async_mode and self.event_queue:
                try:
                    self.event_queue.put_nowait(event)
                except Exception:
                    pass  # Skip sync events if queue full
        
        except Exception as e:
            logger.debug("Error processing SYNC frame: %s", e)

    def _start_processing_thread(self) -> None:
        """Start background event processing thread."""
        self.stop_processing = False
        self.processing_thread = Thread(
            target=self._process_event_queue,
            daemon=True,
            name="EventProcessor"
        )
        self.processing_thread.start()
        logger.debug("Event processing thread started")

    def _process_event_queue(self) -> None:
        """Process queued events from background thread."""
        while not self.stop_processing:
            try:
                if self.event_queue is None:
                    break
                
                # Get event with timeout
                event = self.event_queue.get(timeout=1.0)
                
                # Dispatch by type
                if event["type"] == "emcy_callback":
                    # Re-construct parameters for oracle
                    self.oracle.on_emcy(
                        node_id=event["node_id"],
                        code=event["error_code"],
                        additional=bytes.fromhex(event["raw_data"][4:])
                    )
                elif event["type"] == "heartbeat_callback":
                    self.oracle.on_heartbeat(
                        node_id=event["node_id"],
                        state=event["state"]
                    )
            
            except Exception as e:
                logger.debug("Event queue get timeout or error: %s", e)
                continue

    def stop(self) -> None:
        """Stop event processing and clean up."""
        logger.debug("Stopping event handlers")
        self.stop_processing = True
        
        if self.processing_thread and self.processing_thread.is_alive():
            self.processing_thread.join(timeout=5.0)
        
        logger.debug("Event handlers stopped")
