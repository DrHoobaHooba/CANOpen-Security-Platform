"""Active CANopen discovery via SDO probing.

Queries live nodes for standard device identification objects
to build comprehensive device profiles.
"""

import logging
from typing import Dict, Any, Optional, Set
import time

import canopen

from ..utils.logging_utils import get_logger

logger = get_logger(__name__)


class SDOProbe:
    """Active discovery via SDO ping with retry and timeout handling.

    Probes for standard CANopen device identification indices to
    verify node presence and collect device metadata.
    """

    # Standard CANopen indices for device identification (DS301)
    QUERY_INDICES = {
        0x1000: ("device_type", "u32", "Device type"),
        0x1001: ("error_register", "u8", "Error register"),
        0x1008: ("device_name", "string", "Device name"),
        0x1009: ("hardware_version", "string", "Hardware version"),
        0x100A: ("firmware_version", "string", "Firmware version"),
        0x100B: ("software_version", "string", "Software version"),
        0x1018: ("identity", "struct", "Identity object"),
    }

    def __init__(
        self,
        network: canopen.Network,
        timeout: float = 1.0,
        retries: int = 2,
    ) -> None:
        """Initialize SDO probe.

        Args:
            network: CANopen Network instance
            timeout: SDO timeout per query in seconds
            retries: Number of retry attempts per node

        Raises:
            TypeError: If network is not canopen.Network
            ValueError: If timeout or retries are invalid
        """
        if not isinstance(network, canopen.Network):
            raise TypeError(f"network must be canopen.Network, got {type(network)}")

        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError(f"timeout must be positive, got {timeout}")

        if not isinstance(retries, int) or retries < 0:
            raise ValueError(f"retries must be non-negative int, got {retries}")

        self.network = network
        self.default_timeout = timeout
        self.retries = retries
        self.results: Dict[int, Dict[str, Any]] = {}
        self.probe_times: Dict[int, float] = {}

    def probe(
        self,
        node_id: int,
        timeout: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        """Probe a single node and collect identification information.

        Args:
            node_id: CANopen node ID (1-127)
            timeout: SDO timeout in seconds; uses default if None

        Returns:
            Dictionary with node identification info or None if not responding

        Raises:
            ValueError: If node_id is invalid
        """
        if not isinstance(node_id, int) or not (1 <= node_id <= 127):
            raise ValueError(f"node_id must be 1-127, got {node_id}")

        timeout = timeout or self.default_timeout
        start_time = time.time()

        # Try to probe with retries
        for attempt in range(self.retries + 1):
            try:
                # Create/get remote node
                try:
                    node = canopen.RemoteNode(node_id, None)
                except Exception as e:
                    logger.debug("Failed to create remote node %d: %s", node_id, e)
                    if attempt < self.retries:
                        time.sleep(0.1)
                        continue
                    return None

                try:
                    self.network.add_node(node)
                except Exception as e:
                    logger.debug("Failed to register remote node %d in network: %s", node_id, e)

                # Configure SDO timeout
                node.sdo.timeout = timeout

                # Try basic ping on 0x1000 (device type)
                try:
                    device_type = node.sdo.upload(0x1000, 0)
                except (canopen.SdoAbortedError, TimeoutError, OSError, RuntimeError) as e:
                    logger.debug(
                        "Node %d probe attempt %d/%-1d failed: %s",
                        node_id, attempt + 1, self.retries + 1, str(e)
                    )
                    if attempt < self.retries:
                        time.sleep(0.1 * (attempt + 1))
                        continue
                    return None

                # Node is responsive; gather info
                info: Dict[str, Any] = {
                    "node_id": node_id,
                    "device_type": device_type,
                    "indices_available": {},
                    "identity": {},
                }

                logger.debug("Node %d responded to SDO probe", node_id)

                # Query all standard indices
                for idx, (name, dtype, description) in self.QUERY_INDICES.items():
                    if idx == 0x1000:  # Already queried
                        info["indices_available"][name] = device_type
                        continue

                    try:
                        if idx == 0x1018:
                            # Identity is a structure with subindices
                            identity = self._query_identity_object(node)
                            info["identity"] = identity
                            if identity:
                                info["indices_available"][name] = True
                        else:
                            value = node.sdo.upload(idx, 0)
                            info["indices_available"][name] = value
                            logger.debug(
                                "Node %d: 0x%04X (%s) = %s",
                                node_id, idx, name, value
                            )
                    except (canopen.SdoAbortedError, TimeoutError, OSError, RuntimeError) as e:
                        info["indices_available"][name] = None
                        logger.debug(
                            "Node %d: 0x%04X (%s) unavailable: %s",
                            node_id, idx, name, str(e)[:50]
                        )
                    except Exception as e:
                        logger.debug(
                            "Node %d: 0x%04X (%s) error: %s",
                            node_id, idx, name, type(e).__name__
                        )
                        info["indices_available"][name] = None

                elapsed = time.time() - start_time
                self.results[node_id] = info
                self.probe_times[node_id] = elapsed

                logger.info(
                    "Successfully probed node %d (%.1f seconds)",
                    node_id, elapsed
                )
                return info

            except Exception as e:
                logger.error(
                    "Unexpected error probing node %d on attempt %d: %s",
                    node_id, attempt + 1, type(e).__name__
                )
                if attempt < self.retries:
                    time.sleep(0.1)

        return None

    def _query_identity_object(self, node: canopen.RemoteNode) -> Dict[str, Any]:
        """Query the identity object (0x1018) subindices.

        Identity object structure (DS301 §6.4.11):
        - Subindex 0: Number of entries
        - Subindex 1: Vendor ID (u32)
        - Subindex 2: Product Code (u32)
        - Subindex 3: Revision Number (u32)
        - Subindex 4: Serial Number (u32)

        Args:
            node: RemoteNode instance

        Returns:
            Dictionary with identity information
        """
        identity: Dict[str, Any] = {}

        try:
            # Get number of entries
            num_entries = node.sdo.upload(0x1018, 0)
            identity["num_entries"] = num_entries

            # Query subindices
            subindex_names = {
                1: "vendor_id",
                2: "product_code",
                3: "revision_number",
                4: "serial_number",
            }

            for sub_idx in range(1, min(5, num_entries + 1)):
                try:
                    value = node.sdo.upload(0x1018, sub_idx)
                    name = subindex_names.get(sub_idx, f"unknown_{sub_idx}")
                    identity[name] = value
                    logger.debug(
                        "Identity 0x1018:%d (%s) = 0x%X",
                        sub_idx, name, value if isinstance(value, int) else 0
                    )
                except (canopen.SdoAbortedError, TimeoutError) as e:
                    logger.debug("Failed to read 0x1018:%d: %s", sub_idx, str(e)[:50])

        except (canopen.SdoAbortedError, TimeoutError) as e:
            logger.debug("Failed to read identity object 0x1018: %s", str(e)[:50])

        return identity

    def scan(
        self,
        start: int = 1,
        end: int = 127,
        timeout: Optional[float] = None,
    ) -> Dict[int, Dict[str, Any]]:
        """Scan a range of node IDs sequentially.

        Args:
            start: Starting node ID (default: 1)
            end: Ending node ID inclusive (default: 127)
            timeout: Optional override for SDO timeout

        Returns:
            Dictionary of results keyed by node ID

        Raises:
            ValueError: If start/end are invalid
        """
        if not isinstance(start, int) or not (1 <= start <= 127):
            raise ValueError(f"start must be 1-127, got {start}")

        if not isinstance(end, int) or not (1 <= end <= 127):
            raise ValueError(f"end must be 1-127, got {end}")

        if start > end:
            raise ValueError(f"start ({start}) must be <= end ({end})")

        logger.info(
            "Starting SDO scan from node %d to %d",
            start, end
        )
        start_time = time.time()

        for node_id in range(start, end + 1):
            self.probe(node_id, timeout=timeout)

        elapsed = time.time() - start_time
        found = len(self.results)

        logger.info(
            "SDO scan complete: found %d responsive nodes in %.1f seconds",
            found, elapsed
        )

        return self.results

    def get_probed_nodes(self) -> Set[int]:
        """Get set of successfully probed node IDs.

        Returns:
            Set of node IDs that responded to probing
        """
        return set(self.results.keys())

    def get_probe_result(self, node_id: int) -> Optional[Dict[str, Any]]:
        """Get probe result for specific node.

        Args:
            node_id: Node ID

        Returns:
            Probe result or None if node was not probed
        """
        return self.results.get(node_id)

    def get_statistics(self) -> Dict[str, Any]:
        """Get probing session statistics.

        Returns:
            Dictionary with probe statistics
        """
        total_time = sum(self.probe_times.values())
        avg_time = total_time / len(self.probe_times) if self.probe_times else 0.0

        return {
            "nodes_probed": len(self.results),
            "total_probe_time": total_time,
            "average_probe_time": avg_time,
            "probe_results": {nid: self.results[nid] for nid in sorted(self.results.keys())},
        }
