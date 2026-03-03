import logging
from typing import Set, Dict, Any, List, Optional
import time

import can
import canopen

from .passive import PassiveDiscovery, NMTState
from .sdo_probe import SDOProbe
from .lss_scan import LSSScanner, Identity
from ..utils.logging_utils import get_logger

logger = get_logger(__name__)


class NodeEnumerator:
    """Unified CANopen discovery interface.
    
    Coordinates passive listening, active SDO probing, and LSS scanning
    to build a comprehensive network inventory.
    """

    def __init__(
        self,
        bus: Optional[can.Bus] = None,
        network: Optional[canopen.Network] = None,
        passive_timeout: float = 5.0,
        sdo_timeout: float = 1.0,
        lss_timeout: float = 10.0,
    ) -> None:
        self.bus = bus
        self.network = network or canopen.Network()
        self.passive_timeout = passive_timeout
        self.sdo_timeout = sdo_timeout
        self.lss_timeout = lss_timeout
        
        self.passive = PassiveDiscovery(self.bus) if self.bus else None
        self.sdo = SDOProbe(self.network, timeout=sdo_timeout)
        self.lss = LSSScanner(self.network)
        
        self.inventory: Dict[str, Any] = {
            "discovery_methods": {},
            "nodes": {},
            "summary": {},
        }

    def discover_passive(self, timeout: Optional[float] = None) -> Set[int]:
        """Run passive discovery (listen for heartbeat/boot-up/EMCY).
        
        Args:
            timeout: Listening timeout; uses instance default if None
            
        Returns:
            Set of discovered node IDs
        """
        if not self.passive:
            raise RuntimeError("Bus not provided for passive discovery")
        
        timeout = timeout or self.passive_timeout
        logger.info("Starting passive discovery (timeout=%.1fs)", timeout)
        start = time.time()
        
        nodes = self.passive.run(timeout)
        elapsed = time.time() - start
        
        self.inventory["discovery_methods"]["passive"] = {
            "status": "completed",
            "duration": elapsed,
            "node_count": len(nodes),
        }
        
        # Merge passive results into node inventory
        for node_id in nodes:
            if node_id not in self.inventory["nodes"]:
                self.inventory["nodes"][node_id] = {"id": node_id}
            
            node_info = self.passive.get_node_info(node_id)
            if node_info:
                self.inventory["nodes"][node_id].update({
                    "discovered_by": "passive",
                    "nmt_state": node_info.get("nmt_state"),
                    "nmt_state_name": (
                        node_info.get("nmt_state").name
                        if node_info.get("nmt_state")
                        else None
                    ),
                    "first_seen": node_info.get("first_seen"),
                    "observed_cobs": node_info.get("frames", []),
                })
        
        logger.info("Passive discovery found %d nodes in %.1f seconds", len(nodes), elapsed)
        return nodes

    def discover_sdo(
        self,
        nodes: Optional[Set[int]] = None,
        timeout: Optional[float] = None,
    ) -> Dict[int, Dict[str, Any]]:
        """Run active SDO probing on specified or all nodes.
        
        Args:
            nodes: Set of node IDs to probe; if None, probes full range (1-127)
            timeout: SDO timeout override
            
        Returns:
            Dictionary of probed node info keyed by node ID
        """
        timeout = timeout or self.sdo_timeout
        logger.info("Starting SDO discovery probe")
        start = time.time()
        
        if nodes:
            # Probe specific nodes
            for node_id in sorted(nodes):
                self.sdo.probe(node_id, timeout=timeout)
            count_probed = len(nodes)
        else:
            # Full range scan
            self.sdo.scan(timeout=timeout)
            count_probed = 127
        
        elapsed = time.time() - start
        found = len(self.sdo.results)
        
        self.inventory["discovery_methods"]["sdo"] = {
            "status": "completed",
            "duration": elapsed,
            "probed_range": f"1-{count_probed}",
            "node_count": found,
        }
        
        # Merge SDO results into node inventory
        for node_id, sdo_info in self.sdo.results.items():
            if node_id not in self.inventory["nodes"]:
                self.inventory["nodes"][node_id] = {"id": node_id}
            
            self.inventory["nodes"][node_id].update({
                "discovered_by": "sdo",
                "sdo_data": sdo_info,
            })
        
        logger.info(
            "SDO discovery found %d responsive nodes (%.1f seconds)",
            found, elapsed
        )
        return self.sdo.results

    def discover_lss(self, timeout: Optional[float] = None) -> List[Identity]:
        """Run LSS fast scan to discover unconfigured nodes.
        
        Args:
            timeout: LSS scan timeout override
            
        Returns:
            List of discovered identities
        """
        timeout = timeout or self.lss_timeout
        logger.info("Starting LSS discovery")
        start = time.time()
        
        results = self.lss.fast_scan(timeout=timeout)
        elapsed = time.time() - start
        
        self.inventory["discovery_methods"]["lss"] = {
            "status": "completed",
            "duration": elapsed,
            "device_count": len(results),
        }
        
        logger.info(
            "LSS discovery found %d unconfigured devices (%.1f seconds)",
            len(results), elapsed
        )
        return results

    def discover_all(
        self,
        passive: bool = True,
        sdo: bool = True,
        lss: bool = True,
    ) -> None:
        """Run full discovery sequence combining all methods.
        
        Args:
            passive: Whether to run passive discovery
            sdo: Whether to run SDO probing
            lss: Whether to run LSS scanning
        """
        logger.info("Starting full discovery sequence")
        start = time.time()
        
        if passive and self.passive:
            try:
                passive_nodes = self.discover_passive()
            except Exception as e:
                logger.error("Passive discovery failed: %s", e)
        
        if sdo:
            try:
                # If passive found nodes, probe those first; otherwise full scan
                if passive and self.passive:
                    passive_nodes = self.passive.nodes
                    self.discover_sdo(nodes=passive_nodes)
                else:
                    self.discover_sdo()
            except Exception as e:
                logger.error("SDO discovery failed: %s", e)
        
        if lss:
            try:
                self.discover_lss()
            except Exception as e:
                logger.error("LSS discovery failed: %s", e)
        
        elapsed = time.time() - start
        self.inventory["summary"]["total_duration"] = elapsed
        self.inventory["summary"]["active_discovery_methods"] = {
            "passive": passive,
            "sdo": sdo,
            "lss": lss,
        }
        
        logger.info(
            "Full discovery sequence completed in %.1f seconds; "
            "found %d unique nodes",
            elapsed, len(self.inventory["nodes"])
        )

    def get_inventory(self) -> Dict[str, Any]:
        """Get complete discovery inventory."""
        # Update node count in summary
        self.inventory["summary"]["unique_nodes"] = len(self.inventory["nodes"])
        self.inventory["summary"]["node_ids"] = sorted(self.inventory["nodes"].keys())
        return self.inventory

    def get_node_info(self, node_id: int) -> Optional[Dict[str, Any]]:
        """Get aggregated info for a single node."""
        return self.inventory["nodes"].get(node_id)

    def get_discovered_nodes(self) -> List[int]:
        """Get sorted list of all discovered node IDs."""
        return sorted(self.inventory["nodes"].keys())
