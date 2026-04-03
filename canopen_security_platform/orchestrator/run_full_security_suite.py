"""CANopen Security Testing Platform - Full Automation Suite.

Orchestrates the complete security testing workflow:
- PCAN connectivity check
- Passive discovery (boot-up, heartbeat, EMCY)
- Active SDO discovery
- LSS fastscan discovery
- EDS/XDD/XDC loading with auto-conversion
- Object Dictionary building
- Hidden OD scanning
- SDO fuzzing
- PDO fuzzing
- NMT fuzzing
- EMCY/Heartbeat monitoring
- Comprehensive HTML reporting

Usage:
    python -m canopen_security_platform.orchestrator.run_full_security_suite
    python -m canopen_security_platform.orchestrator.run_full_security_suite --config custom_config.yaml
"""

import argparse
import logging
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Set, Optional
import yaml
import json

import canopen

from ..hal.bus_pcan import BusInterface, CANConfigError
from ..discovery.passive import PassiveDiscovery
from ..discovery.sdo_probe import SDOProbe
from ..discovery.lss_scan import LSSScanner
from ..od.eds_loader import EDSLoader
from ..od.xdd_converter import XDDConverter
from ..od.runtime_od import RuntimeObjectDictionary
from ..od.hidden_scanner import HiddenObjectScanner
from ..fuzzing.sdo_fuzzer import SDOFuzzer
from ..fuzzing.pdo_fuzzer import PDOFuzzer
from ..fuzzing.nmt_fuzzer import NMTFuzzer
from ..fuzzing.emcy_fuzzer import EMCYFuzzer
from ..fuzzing.sync_fuzzer import SYNCFuzzer
from ..fuzzing.concurrent_fuzzer import ConcurrentFuzzer
from ..monitoring.oracle import Oracle
from ..utils.logging_utils import get_logger

logger = get_logger(__name__)


@dataclass
class TestResults:
    """Container for all test results collected during the suite run."""
    
    # Timing
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    
    # Configuration
    config: Dict[str, Any] = field(default_factory=dict)
    
    # Discovery results
    passive_nodes: Set[int] = field(default_factory=set)
    active_nodes: Set[int] = field(default_factory=set)
    lss_nodes: List[Dict[str, Any]] = field(default_factory=list)
    node_details: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    
    # OD loading
    loaded_ods: Dict[int, str] = field(default_factory=dict)  # node_id -> file path
    loaded_od_objects: Dict[int, 'RuntimeObjectDictionary'] = field(default_factory=dict)  # node_id -> OD object
    od_errors: List[str] = field(default_factory=list)
    
    # Hidden OD scanning
    hidden_objects: Dict[int, List[Dict[str, Any]]] = field(default_factory=dict)
    
    # Fuzzing results
    sdo_fuzzing_results: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    pdo_fuzzing_results: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    nmt_fuzzing_results: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    
    # Monitoring
    emcy_events: List[Dict[str, Any]] = field(default_factory=list)
    heartbeat_anomalies: List[Dict[str, Any]] = field(default_factory=list)
    oracle_alerts: List[Dict[str, Any]] = field(default_factory=list)
    
    # Issues and warnings
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    # Stage completion tracking
    completed_stages: List[str] = field(default_factory=list)
    failed_stages: List[str] = field(default_factory=list)
    
    def add_warning(self, message: str) -> None:
        """Add a warning message."""
        self.warnings.append(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
        logger.warning(message)
    
    def add_error(self, message: str) -> None:
        """Add an error message."""
        self.errors.append(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
        logger.error(message)
    
    def mark_stage_completed(self, stage_name: str) -> None:
        """Mark a stage as successfully completed."""
        self.completed_stages.append(stage_name)
        logger.info(f"✓ Stage completed: {stage_name}")
    
    def mark_stage_failed(self, stage_name: str, error: str = "") -> None:
        """Mark a stage as failed."""
        self.failed_stages.append(stage_name)
        if error:
            self.add_error(f"Stage '{stage_name}' failed: {error}")
        else:
            self.add_error(f"Stage '{stage_name}' failed")


class SecurityTestSuite:
    """Main orchestrator for the complete CANopen security testing suite.
    
    Coordinates all discovery, fuzzing, and monitoring activities with
    comprehensive error handling and progress reporting.
    """
    
    DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.yaml"
    
    def __init__(self, config_path: Optional[Path] = None):
        """Initialize the security test suite.
        
        Args:
            config_path: Path to YAML configuration file
        """
        self.config = self._load_config(config_path)
        self.results = TestResults(config=self.config)
        
        # Components initialized during run
        self.bus: Optional[BusInterface] = None
        self.network: Optional[canopen.Network] = None
        self.oracle: Optional[Oracle] = None
        
    def _load_config(self, config_path: Optional[Path] = None) -> Dict[str, Any]:
        """Load configuration from YAML file.
        
        Args:
            config_path: Path to config file, or None to use default
            
        Returns:
            Configuration dictionary
        """
        if config_path is None:
            config_path = self.DEFAULT_CONFIG_PATH
        
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            logger.info(f"Loaded configuration from {config_path}")
            return config
        except FileNotFoundError:
            logger.warning(f"Config file not found: {config_path}, using defaults")
            return self._default_config()
        except Exception as e:
            logger.error(f"Failed to load config: {e}, using defaults")
            return self._default_config()
    
    def _default_config(self) -> Dict[str, Any]:
        """Return default configuration."""
        return {
            'bus': {
                'interface': 'pcan',
                'channel': 'PCAN_USBBUS1',
                'bitrate': 250000,
            },
            'tests': {
                'passive_discovery': True,
                'active_discovery': True,
                'lss_discovery': True,
                'od_load': True,
                'hidden_od_scan': True,
                'fuzz_sdo': True,
                'fuzz_pdo': False,
                'fuzz_nmt': True,
                'fuzz_emcy': True,         # NEW - Tier 1
                'fuzz_sync': True,         # NEW - Tier 1
                'fuzz_concurrent': True,   # NEW - Tier 1
                'monitor_emcy': True,
                'monitor_heartbeat': True,
            },
            'discovery': {
                'passive_timeout': 10,
                'sdo_timeout': 2.0,
                'sdo_retry': 1,
                'node_range': [1, 127],
                'lss_timeout': 5.0,
            },
            'object_dictionary': {
                'device_descriptions_dir': 'device_descriptions',
                'auto_convert_xdd': True,
                'prefer_format': 'eds',
                'cache_dir': '.od_cache',
            },
            'hidden_scanner': {
                'enabled': True,
                'scan_ranges': [[0x1000, 0x1FFF], [0x2000, 0x5FFF]],
                'max_workers': 4,
                'request_delay_ms': 10,
                'timeout': 1.0,
            },
            'fuzzing_sdo': {
                'iterations': 100,
                'strategies': ['mutate_cs', 'wrong_length', 'overflow'],
                'target_nodes': 'discovered',
                'delay_between_tests_ms': 50,
                'skip_critical_objects': True,
            },
            'fuzzing_pdo': {
                'iterations': 50,
                'strategies': ['corrupt_cob_id', 'invalid_length'],
                'target_nodes': 'discovered',
                'delay_between_tests_ms': 100,
            },
            'fuzzing_nmt': {
                'iterations': 50,
                'strategies': ['invalid_cs', 'wrong_node_id'],
                'target_nodes': 'discovered',
                'delay_between_tests_ms': 200,
                'monitor_recovery': True,
            },
            'monitoring': {
                'emcy_severity_threshold': 'warning',
                'heartbeat_timeout_warning': 3.0,
                'track_state_changes': True,
                'anomaly_detection': True,
            },
            'reporting': {
                'output_dir': 'reports',
                'html_report': True,
                'json_export': True,
                'embed_logs': True,
                'include_raw_frames': False,
            },
        }
    
    def _print_header(self) -> None:
        """Print suite header with configuration info."""
        header = """
╔══════════════════════════════════════════════════════════════════════╗
║         CANopen Security Testing Platform - Full Suite              ║
║                    Automated Security Assessment                     ║
╚══════════════════════════════════════════════════════════════════════╝
"""
        print(header)
        print(f"Start Time: {self.results.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Configuration: {len([k for k, v in self.config.get('tests', {}).items() if v])} tests enabled")
        print("─" * 72)
        print()
    
    def _print_stage_header(self, stage_name: str, description: str = "") -> None:
        """Print a stage header."""
        print(f"\n{'═' * 72}")
        print(f"  {stage_name}")
        if description:
            print(f"  {description}")
        print(f"{'═' * 72}\n")
    
    def _print_summary(self) -> None:
        """Print final test summary."""
        duration = (self.results.end_time - self.results.start_time).total_seconds()
        
        print(f"\n\n{'═' * 72}")
        print("  TEST SUITE SUMMARY")
        print(f"{'═' * 72}\n")
        
        print(f"Total Duration: {duration:.1f} seconds")
        print(f"Stages Completed: {len(self.results.completed_stages)}")
        print(f"Stages Failed: {len(self.results.failed_stages)}")
        print()
        
        print(f"Discovery Results:")
        print(f"  • Passive Discovery: {len(self.results.passive_nodes)} nodes")
        print(f"  • Active SDO Discovery: {len(self.results.active_nodes)} nodes")
        print(f"  • LSS Discovery: {len(self.results.lss_nodes)} nodes")
        print()
        
        all_nodes = self.results.passive_nodes | self.results.active_nodes
        if all_nodes:
            print(f"Discovered Nodes: {sorted(all_nodes)}")
            print()
        
        if self.results.hidden_objects:
            total_hidden = sum(len(objs) for objs in self.results.hidden_objects.values())
            print(f"Hidden Objects Found: {total_hidden} across {len(self.results.hidden_objects)} nodes")
            print()
        
        if self.results.emcy_events:
            print(f"⚠  EMCY Events Detected: {len(self.results.emcy_events)}")
        
        if self.results.heartbeat_anomalies:
            print(f"⚠  Heartbeat Anomalies: {len(self.results.heartbeat_anomalies)}")
        
        if self.results.oracle_alerts:
            print(f"⚠  Oracle Alerts: {len(self.results.oracle_alerts)}")
        
        if self.results.warnings:
            print(f"\n⚠  Warnings: {len(self.results.warnings)}")
        
        if self.results.errors:
            print(f"✗  Errors: {len(self.results.errors)}")
            for error in self.results.errors[:5]:  # Show first 5
                print(f"     {error}")
            if len(self.results.errors) > 5:
                print(f"     ... and {len(self.results.errors) - 5} more")
        
        print(f"\n{'═' * 72}\n")
    
    def run(self) -> TestResults:
        """Execute the complete security test suite.
        
        Returns:
            TestResults containing all collected data and findings
        """
        self._print_header()
        
        try:
            # Stage 1: Connect to PCAN bus
            if not self._stage_connect_pcan():
                return self.results
            
            # Stage 2: Initialize Oracle for monitoring
            self._stage_initialize_oracle()
            
            # Stage 3: Passive discovery
            if self.config['tests'].get('passive_discovery', True):
                self._stage_passive_discovery()
            
            # Stage 4: Active SDO discovery
            if self.config['tests'].get('active_discovery', True):
                self._stage_active_discovery()
            
            # Stage 5: LSS discovery
            if self.config['tests'].get('lss_discovery', True):
                self._stage_lss_discovery()
            
            # Stage 6: Load Object Dictionaries
            if self.config['tests'].get('od_load', True):
                self._stage_load_object_dictionaries()
            
            # Stage 7: Hidden OD scanning
            if self.config['tests'].get('hidden_od_scan', True):
                self._stage_hidden_od_scan()
            
            # Stage 8: SDO fuzzing
            if self.config['tests'].get('fuzz_sdo', True):
                self._stage_sdo_fuzzing()
            
            # Stage 9: PDO fuzzing
            if self.config['tests'].get('fuzz_pdo', False):
                self._stage_pdo_fuzzing()
            
            # Stage 10: NMT fuzzing
            if self.config['tests'].get('fuzz_nmt', True):
                self._stage_nmt_fuzzing()
            
            # Stage 11: EMCY fuzzing (NEW - Tier 1)
            if self.config['tests'].get('fuzz_emcy', True):
                self._stage_emcy_fuzzing()
            
            # Stage 12: SYNC fuzzing (NEW - Tier 1)
            if self.config['tests'].get('fuzz_sync', True):
                self._stage_sync_fuzzing()
            
            # Stage 13: Concurrent message fuzzing (NEW - Tier 1)
            if self.config['tests'].get('fuzz_concurrent', True):
                self._stage_concurrent_fuzzing()
            
            # Stage 14: Collect oracle results
            self._stage_collect_oracle_results()
            
            # Stage 15: Generate reports
            self._stage_generate_reports()
            
        except KeyboardInterrupt:
            logger.warning("Test suite interrupted by user")
            self.results.add_warning("Suite interrupted by user (Ctrl+C)")
        except Exception as e:
            logger.exception("Unexpected error during test suite execution")
            self.results.add_error(f"Critical error: {e}")
        finally:
            self._cleanup()
            self.results.end_time = datetime.now()
        
        self._print_summary()
        
        return self.results
    
    def _stage_connect_pcan(self) -> bool:
        """Stage 1: Connect to PCAN interface.
        
        Returns:
            True if connection successful, False otherwise
        """
        self._print_stage_header("STAGE 1: PCAN Bus Connection", "Establishing connection to CAN bus")
        
        try:
            bus_config = self.config.get('bus', {})
            interface = bus_config.get('interface', 'pcan')
            channel = bus_config.get('channel', 'PCAN_USBBUS1')
            bitrate = bus_config.get('bitrate', 250000)
            
            print(f"Interface: {interface}")
            print(f"Channel: {channel}")
            print(f"Bitrate: {bitrate} bps")
            print()
            
            self.bus = BusInterface(config={
                "interface": interface,
                "channel": channel,
                "bitrate": bitrate,
            })
            
            # Test connection
            stats = self.bus.get_statistics()
            print(f"✓ Bus connected successfully")
            print(f"  Status: Open={stats['is_open']}, TX={stats['frames_transmitted']}, RX={stats['frames_received']}")
            
            # Initialize canopen network with the underlying python-can Bus
            self.network = canopen.Network()
            self.network.bus = self.bus.get_raw_bus()
            
            self.results.mark_stage_completed("PCAN Connection")
            return True
            
        except CANConfigError as e:
            self.results.mark_stage_failed("PCAN Connection", str(e))
            print(f"✗ Failed to connect to PCAN: {e}")
            print("\nPlease ensure:")
            print("  1. PCAN hardware is connected")
            print("  2. PCAN drivers are installed")
            print("  3. No other application is using the interface")
            return False
        except Exception as e:
            self.results.mark_stage_failed("PCAN Connection", str(e))
            logger.exception("Unexpected error connecting to PCAN")
            return False
    
    def _stage_initialize_oracle(self) -> None:
        """Stage 2: Initialize monitoring oracle."""
        self._print_stage_header("STAGE 2: Initialize Monitoring", "Setting up anomaly detection and event tracking")
        
        try:
            self.oracle = Oracle()
            
            # Add standard alert rules
            if self.config['monitoring'].get('anomaly_detection', True):
                from ..monitoring.oracle import AlertRule
                
                self.oracle.add_alert_rule(
                    AlertRule(
                        name="EMCY_Critical",
                        event_type="emcy",
                        condition=lambda e: e.get('severity', 0) >= 0x10,
                        severity="critical",
                    )
                )
                
                self.oracle.add_alert_rule(
                    AlertRule(
                        name="Heartbeat_Lost",
                        event_type="heartbeat",
                        condition=lambda e: e.get('state') == 'timeout',
                        severity="warning",
                    )
                )
            
            print("✓ Oracle initialized with anomaly detection")
            self.results.mark_stage_completed("Initialize Oracle")
            
        except Exception as e:
            self.results.mark_stage_failed("Initialize Oracle", str(e))
            logger.exception("Failed to initialize oracle")
    
    def _stage_passive_discovery(self) -> None:
        """Stage 3: Passive network discovery."""
        self._print_stage_header("STAGE 3: Passive Discovery", "Listening for boot-up, heartbeat, and EMCY frames")
        
        try:
            timeout = self.config['discovery'].get('passive_timeout', 10)
            print(f"Listening for {timeout} seconds...")
            print()
            
            discovery = PassiveDiscovery(self.bus)
            nodes = discovery.run(timeout=timeout)
            
            self.results.passive_nodes = nodes
            
            print(f"✓ Discovered {len(nodes)} nodes: {sorted(nodes)}")
            
            # Get node details
            for node_id in nodes:
                state = discovery.get_node_info(node_id)
                self.results.node_details[node_id] = {
                    'passive_state': str(state) if state else 'Unknown',
                    'first_seen': 'passive_discovery',
                }
                print(f"  Node {node_id:3d}: State = {state}")
            
            self.results.mark_stage_completed("Passive Discovery")
            
        except Exception as e:
            self.results.mark_stage_failed("Passive Discovery", str(e))
            logger.exception("Passive discovery failed")
    
    def _stage_active_discovery(self) -> None:
        """Stage 4: Active SDO discovery."""
        self._print_stage_header("STAGE 4: Active SDO Discovery", "Probing nodes for device identification")
        
        try:
            # Determine which nodes to probe
            node_range = self.config['discovery'].get('node_range', [1, 127])
            probe_nodes = set(range(node_range[0], node_range[1] + 1))
            
            # If we have passive discovery results, focus on those
            if self.results.passive_nodes:
                probe_nodes = self.results.passive_nodes
                print(f"Probing {len(probe_nodes)} nodes from passive discovery")
            else:
                print(f"Probing node range {node_range[0]}-{node_range[1]}")
            print()
            
            timeout = self.config['discovery'].get('sdo_timeout', 2.0)
            retries = self.config['discovery'].get('sdo_retry', 1)
            
            probe = SDOProbe(self.network, timeout=timeout, retries=retries)
            
            discovered = {}
            for node_id in sorted(probe_nodes):
                print(f"  Probing node {node_id}...", end=" ", flush=True)
                
                info = probe.probe(node_id)
                if info:
                    discovered[node_id] = info
                    self.results.active_nodes.add(node_id)
                    
                    # Update node details
                    if node_id not in self.results.node_details:
                        self.results.node_details[node_id] = {}
                    self.results.node_details[node_id].update(info)
                    
                    device_type = info.get('device_type', 'Unknown')
                    device_name = info.get('device_name', 'Unknown')
                    print(f"✓ {device_name} (Type: 0x{device_type:08X})")
                else:
                    print("✗ No response")
            
            print()
            print(f"✓ Active discovery complete: {len(discovered)} nodes responded")
            self.results.mark_stage_completed("Active SDO Discovery")
            
        except Exception as e:
            self.results.mark_stage_failed("Active SDO Discovery", str(e))
            logger.exception("Active SDO discovery failed")
    
    def _stage_lss_discovery(self) -> None:
        """Stage 5: LSS fastscan discovery."""
        self._print_stage_header("STAGE 5: LSS Discovery", "Scanning for unconfigured nodes via LSS")
        
        try:
            print("Initiating LSS fastscan (binary search)...")
            print()
            
            scanner = LSSScanner(self.network)
            identities = scanner.fast_scan()
            
            self.results.lss_nodes = [
                {
                    'vendor_id': vendor,
                    'product_code': product,
                    'revision': revision,
                    'serial': serial,
                }
                for vendor, product, revision, serial in identities
            ]
            
            if identities:
                print(f"✓ Found {len(identities)} unconfigured nodes:")
                for vendor, product, revision, serial in identities:
                    print(f"  Vendor: 0x{vendor:08X}, Product: 0x{product:08X}, "
                          f"Rev: 0x{revision:08X}, Serial: 0x{serial:08X}")
            else:
                print("No unconfigured LSS nodes found")
            
            self.results.mark_stage_completed("LSS Discovery")
            
        except Exception as e:
            self.results.mark_stage_failed("LSS Discovery", str(e))
            logger.exception("LSS discovery failed")
            self.results.add_warning("LSS discovery failed - this is normal if all nodes are configured")
    
    def _stage_load_object_dictionaries(self) -> None:
        """Stage 6: Load and process EDS/XDD/XDC files."""
        self._print_stage_header("STAGE 6: Object Dictionary Loading", "Loading device descriptions (EDS/XDD/XDC)")
        
        try:
            od_config = self.config.get('object_dictionary', {})
            od_dir = Path(od_config.get('device_descriptions_dir', 'device_descriptions'))
            
            if not od_dir.exists():
                self.results.add_warning(f"Device descriptions directory not found: {od_dir}")
                print(f"⚠  Directory not found: {od_dir}")
                print("   Skipping OD loading")
                return
            
            print(f"Searching for device descriptions in: {od_dir}")
            print()
            
            # Find all OD files
            eds_files = list(od_dir.glob("*.eds"))
            xdd_files = list(od_dir.glob("*.xdd"))
            xdc_files = list(od_dir.glob("*.xdc"))
            
            print(f"Found: {len(eds_files)} EDS, {len(xdd_files)} XDD, {len(xdc_files)} XDC files")
            
            # Auto-convert XDD/XDC if enabled
            if od_config.get('auto_convert_xdd', True) and (xdd_files or xdc_files):
                print("\nAttempting XDD/XDC conversion...")
                converter = XDDConverter()
                
                if converter.is_available():
                    for xdd_file in xdd_files + xdc_files:
                        eds_out = od_dir / f"{xdd_file.stem}.eds"
                        if not eds_out.exists():
                            print(f"  Converting {xdd_file.name}...", end=" ")
                            try:
                                converter.convert(str(xdd_file), str(eds_out))
                                eds_files.append(eds_out)
                                print("✓")
                            except Exception as e:
                                print(f"✗ {e}")
                                self.results.od_errors.append(f"Conversion failed: {xdd_file.name}: {e}")
                else:
                    print("  ⚠  XDD converter not available, skipping conversion")
            
            # Load EDS files
            if eds_files:
                print(f"\nLoading {len(eds_files)} EDS files...")
                cache_dir = od_config.get('cache_dir', '.od_cache')
                loader = EDSLoader(cache_dir=cache_dir)
                
                for eds_file in eds_files:
                    print(f"  Loading {eds_file.name}...", end=" ")
                    try:
                        od = loader.load(str(eds_file))
                        
                        # Try to match to discovered nodes based on device type
                        # This is a simple heuristic - in practice you'd match more carefully
                        matched = False
                        for node_id, details in self.results.node_details.items():
                            if node_id not in self.results.loaded_ods:
                                # Simple matching - could be enhanced
                                self.results.loaded_ods[node_id] = str(eds_file)
                                self.results.loaded_od_objects[node_id] = od  # Store the actual OD object
                                matched = True
                                print(f"✓ (matched to node {node_id})")
                                break
                        
                        if not matched:
                            print("✓ (loaded, not matched to node)")
                        
                    except Exception as e:
                        print(f"✗ {e}")
                        self.results.od_errors.append(f"Load failed: {eds_file.name}: {e}")
            
            print()
            print(f"✓ OD loading complete: {len(self.results.loaded_ods)} nodes have ODs")
            if self.results.od_errors:
                print(f"  {len(self.results.od_errors)} errors occurred")
            
            self.results.mark_stage_completed("OD Loading")
            
        except Exception as e:
            self.results.mark_stage_failed("OD Loading", str(e))
            logger.exception("OD loading failed")
    
    def _stage_hidden_od_scan(self) -> None:
        """Stage 7: Scan for hidden/undocumented objects."""
        self._print_stage_header("STAGE 7: Hidden Object Scanning", "Brute-force scan for undocumented OD indices")
        
        # Scan nodes from active discovery, fall back to passive discovery
        target_nodes = self.results.active_nodes if self.results.active_nodes else self.results.passive_nodes
        if not target_nodes:
            print("⚠  No nodes to scan, skipping")
            return
        
        try:
            scanner_config = self.config.get('hidden_scanner', {})
            scan_ranges = scanner_config.get('scan_ranges', [[0x1000, 0x1FFF]])
            max_workers = scanner_config.get('max_workers', 4)
            timeout = scanner_config.get('timeout', 1.0)
            
            print(f"Scanning {len(target_nodes)} nodes")
            print(f"Ranges: {scan_ranges}")
            print(f"Workers: {max_workers}, Timeout: {timeout}s")
            print()
            
            for node_id in sorted(target_nodes):
                print(f"  Scanning node {node_id}...")
                
                try:
                    # Get loaded OD for this node, or create empty one
                    node_od = self.results.loaded_od_objects.get(node_id)
                    if not node_od:
                        node_od = RuntimeObjectDictionary()
                    
                    # Create scanner with network
                    scanner = HiddenObjectScanner(
                        network=self.network,
                        max_workers=max_workers,
                        sdo_timeout=timeout,
                    )
                    
                    # Scan node for each range
                    hidden = {}
                    for start, end in scan_ranges:
                        range_results = scanner.scan_node(node_id, index_range=(start, end))
                        if range_results:
                            hidden.update(range_results)
                    
                    if hidden:
                        self.results.hidden_objects[node_id] = hidden
                        print(f"    ✓ Found {len(hidden)} hidden objects")
                        
                        # Show first few indices
                        shown = 0
                        for idx, subidx_dict in hidden.items():
                            if shown >= 5:
                                break
                            print(f"      0x{idx:04X}: {len(subidx_dict)} subindices")
                            shown += 1
                        
                        if len(hidden) > 5:
                            print(f"      ... and {len(hidden) - 5} more indices")
                    else:
                        print(f"    No hidden objects found")
                    
                except Exception as e:
                    print(f"    ✗ Scan failed: {e}")
                    logger.debug(f"Hidden scan error for node {node_id}: {e}")
            
            total_hidden = sum(len(objs) for objs in self.results.hidden_objects.values())
            print()
            print(f"✓ Hidden object scanning complete: {total_hidden} objects across {len(self.results.hidden_objects)} nodes")
            self.results.mark_stage_completed("Hidden OD Scan")
            
        except Exception as e:
            self.results.mark_stage_failed("Hidden OD Scan", str(e))
            logger.exception("Hidden OD scan failed")
    
    def _stage_sdo_fuzzing(self) -> None:
        """Stage 8: SDO protocol fuzzing."""
        self._print_stage_header("STAGE 8: SDO Fuzzing", "Testing SDO protocol robustness")
        
        target_nodes = self._get_fuzzing_targets('fuzzing_sdo')
        if not target_nodes:
            print("⚠  No nodes to fuzz, skipping")
            return
        
        try:
            fuzz_config = self.config.get('fuzzing_sdo', {})
            
            print(f"Target nodes: {sorted(target_nodes)}")
            print()
            
            # Create oracle callback
            anomalies = []
            def oracle_callback(event: Dict[str, Any]) -> None:
                anomalies.append(event)
                if self.oracle:
                    self.oracle.record_event(event)
            
            for node_id in sorted(target_nodes):
                print(f"  Fuzzing node {node_id}...")
                
                try:
                    # Use loaded OD if available, otherwise create empty one
                    od = self.results.loaded_od_objects.get(node_id)
                    if not od:
                        od = RuntimeObjectDictionary()
                    
                    fuzzer = SDOFuzzer(
                        bus=self.bus,
                        node_id=node_id,
                        od=od,
                        oracle=oracle_callback,
                    )
                    
                    # Execute full fuzzing suite
                    fuzzer.execute()
                    
                    self.results.sdo_fuzzing_results[node_id] = {
                        'total_tests': fuzzer.fuzzed_count,
                        'anomalies': [],
                    }
                    print(f"    ✓ Sent {fuzzer.fuzzed_count} malformed SDO requests")
                    
                except Exception as e:
                    print(f"    ✗ Failed: {e}")
                    logger.debug(f"SDO fuzzing error for node {node_id}: {e}")
            
            total_anomalies = len(anomalies)
            print()
            print(f"✓ SDO fuzzing complete: {total_anomalies} anomalies detected")
            self.results.mark_stage_completed("SDO Fuzzing")
            
        except Exception as e:
            self.results.mark_stage_failed("SDO Fuzzing", str(e))
            logger.exception("SDO fuzzing failed")
    
    def _stage_pdo_fuzzing(self) -> None:
        """Stage 9: PDO protocol fuzzing."""
        self._print_stage_header("STAGE 9: PDO Fuzzing", "Testing PDO configuration and transmission")
        
        target_nodes = self._get_fuzzing_targets('fuzzing_pdo')
        if not target_nodes:
            print("⚠  No nodes to fuzz, skipping")
            return
        
        try:
            fuzz_config = self.config.get('fuzzing_pdo', {})
            iterations = fuzz_config.get('iterations', 50)
            strategies = fuzz_config.get('strategies', ['corrupt_cob_id', 'invalid_length'])
            
            print(f"Target nodes: {sorted(target_nodes)}")
            print(f"Iterations per strategy: {iterations}")
            print("⚠  WARNING: PDO fuzzing may disrupt network operations")
            print()
            
            # Create oracle callback
            anomalies = []
            def oracle_callback(event: Dict[str, Any]) -> None:
                anomalies.append(event)
                if self.oracle:
                    self.oracle.record_event(event)
            
            for node_id in sorted(target_nodes):
                print(f"  Fuzzing node {node_id}...")
                
                try:
                    # Use loaded OD if available, otherwise create empty one
                    od = self.results.loaded_od_objects.get(node_id)
                    if not od:
                        od = RuntimeObjectDictionary()
                    
                    fuzzer = PDOFuzzer(
                        bus=self.bus,
                        node_id=node_id,
                        od=od,
                        oracle=oracle_callback,
                    )
                    
                    # Execute full PDO fuzzing suite
                    fuzzer.execute()
                    
                    self.results.pdo_fuzzing_results[node_id] = {
                        'total_tests': fuzzer.fuzzed_count,
                        'anomalies': [],
                    }
                    print(f"    ✓ Sent {fuzzer.fuzzed_count} malformed PDO requests")
                    
                except Exception as e:
                    print(f"    ✗ Failed: {e}")
                    logger.debug(f"PDO fuzzing error for node {node_id}: {e}")
            
            total_anomalies = len(anomalies)
            print()
            print(f"✓ PDO fuzzing complete: {total_anomalies} anomalies detected")
            self.results.mark_stage_completed("PDO Fuzzing")
            
        except Exception as e:
            self.results.mark_stage_failed("PDO Fuzzing", str(e))
            logger.exception("PDO fuzzing failed")
    
    def _stage_nmt_fuzzing(self) -> None:
        """Stage 10: NMT protocol fuzzing."""
        self._print_stage_header("STAGE 10: NMT Fuzzing", "Testing NMT state machine robustness")
        
        target_nodes = self._get_fuzzing_targets('fuzzing_nmt')
        if not target_nodes:
            print("⚠  No nodes to fuzz, skipping")
            return
        
        try:
            fuzz_config = self.config.get('fuzzing_nmt', {})
            iterations = fuzz_config.get('iterations', 50)
            strategies = fuzz_config.get('strategies', ['invalid_cs', 'wrong_node_id'])
            
            print(f"Target nodes: {sorted(target_nodes)}")
            print("⚠  WARNING: NMT fuzzing will change node states")
            print()
            
            # Create oracle callback
            anomalies = []
            def oracle_callback(event: Dict[str, Any]) -> None:
                anomalies.append(event)
                if self.oracle:
                    self.oracle.record_event(event)
            
            for node_id in sorted(target_nodes):
                print(f"  Fuzzing node {node_id}...")
                
                try:
                    # Use loaded OD if available, otherwise create empty one
                    od = self.results.loaded_od_objects.get(node_id)
                    if not od:
                        od = RuntimeObjectDictionary()
                    
                    fuzzer = NMTFuzzer(
                        bus=self.bus,
                        node_id=node_id,
                        od=od,
                        oracle=oracle_callback,
                    )
                    
                    # Execute full NMT fuzzing suite
                    fuzzer.execute()
                    
                    self.results.nmt_fuzzing_results[node_id] = {
                        'total_tests': fuzzer.fuzzed_count,
                        'anomalies': [],
                    }
                    print(f"    ✓ Sent {fuzzer.fuzzed_count} malformed NMT commands")
                    
                except Exception as e:
                    print(f"    ✗ Failed: {e}")
                    logger.debug(f"NMT fuzzing error for node {node_id}: {e}")
            
            total_anomalies = len(anomalies)
            print()
            print(f"✓ NMT fuzzing complete: {total_anomalies} anomalies detected")
            self.results.mark_stage_completed("NMT Fuzzing")
            
        except Exception as e:
            self.results.mark_stage_failed("NMT Fuzzing", str(e))
            logger.exception("NMT fuzzing failed")
    
    def _stage_emcy_fuzzing(self) -> None:
        """Stage 11: EMCY (Emergency) message fuzzing (NEW - Tier 1)."""
        self._print_stage_header("STAGE 11: EMCY Fuzzing", "Testing emergency message handling")
        
        if not hasattr(self, 'emcy_results'):
            self.emcy_results = {}
        
        try:
            fuzz_config = self.config.get('fuzzing_emcy', {})
            if not fuzz_config.get('enabled', True):
                print("⚠  EMCY fuzzing disabled in config")
                return
            
            iterations = fuzz_config.get('iterations', 30)
            target_nodes = self._get_fuzzing_targets('fuzzing_emcy')
            
            if not target_nodes:
                print("⚠  No nodes to fuzz, skipping")
                return
            
            print(f"Target nodes: {sorted(target_nodes)}")
            print()
            
            anomalies = []
            def oracle_callback(event: Dict[str, Any]) -> None:
                anomalies.append(event)
                if self.oracle:
                    self.oracle.record_event(event)
            
            for node_id in sorted(target_nodes):
                print(f"  Fuzzing EMCY for node {node_id}...")
                
                try:
                    od = self.results.loaded_od_objects.get(node_id)
                    if not od:
                        od = RuntimeObjectDictionary()
                    
                    fuzzer = EMCYFuzzer(
                        bus=self.bus,
                        node_id=node_id,
                        od=od,
                        oracle=oracle_callback,
                    )
                    
                    fuzzer.run_all_strategies(iterations=iterations)
                    
                    self.emcy_results[node_id] = {
                        'total_tests': fuzzer.fuzzed_count,
                    }
                    print(f"    ✓ Sent {fuzzer.fuzzed_count} EMCY messages")
                    
                except Exception as e:
                    print(f"    ✗ Failed: {e}")
                    logger.debug(f"EMCY fuzzing error for node {node_id}: {e}")
            
            print()
            print(f"✓ EMCY fuzzing complete: {len(anomalies)} anomalies detected")
            self.results.mark_stage_completed("EMCY Fuzzing")
            
        except Exception as e:
            self.results.mark_stage_failed("EMCY Fuzzing", str(e))
            logger.exception("EMCY fuzzing failed")
    
    def _stage_sync_fuzzing(self) -> None:
        """Stage 12: SYNC message fuzzing (NEW - Tier 1)."""
        self._print_stage_header("STAGE 12: SYNC Fuzzing", "Testing synchronization robustness")
        
        if not hasattr(self, 'sync_results'):
            self.sync_results = {}
        
        try:
            fuzz_config = self.config.get('fuzzing_sync', {})
            if not fuzz_config.get('enabled', True):
                print("⚠  SYNC fuzzing disabled in config")
                return
            
            iterations = fuzz_config.get('iterations', 20)
            
            print("⚠  WARNING: SYNC fuzzing may disrupt PD synchronization")
            print()
            print(f"  Running SYNC fuzzing ({iterations} iteration(s))...")
            
            anomalies = []
            def oracle_callback(event: Dict[str, Any]) -> None:
                anomalies.append(event)
                if self.oracle:
                    self.oracle.record_event(event)
            
            try:
                # SYNC is broadcast (no node_id specific)
                od = RuntimeObjectDictionary()
                
                fuzzer = SYNCFuzzer(
                    bus=self.bus,
                    od=od,
                    oracle=oracle_callback,
                )
                
                fuzzer.run_all_strategies(iterations=iterations)
                
                self.sync_results = {
                    'total_tests': fuzzer.fuzzed_count,
                }
                print(f"    ✓ Sent {fuzzer.fuzzed_count} SYNC messages")
                
            except Exception as e:
                print(f"    ✗ Failed: {e}")
                logger.debug(f"SYNC fuzzing error: {e}")
            
            print()
            print(f"✓ SYNC fuzzing complete: {len(anomalies)} anomalies detected")
            self.results.mark_stage_completed("SYNC Fuzzing")
            
        except Exception as e:
            self.results.mark_stage_failed("SYNC Fuzzing", str(e))
            logger.exception("SYNC fuzzing failed")
    
    def _stage_concurrent_fuzzing(self) -> None:
        """Stage 13: Concurrent message fuzzing (NEW - Tier 1)."""
        self._print_stage_header("STAGE 13: Concurrent Fuzzing", "Testing race conditions and interleaving")
        
        target_nodes = self._get_fuzzing_targets('fuzzing_concurrent')
        if not target_nodes:
            print("⚠  No nodes to fuzz, skipping")
            return
        
        if not hasattr(self, 'concurrent_results'):
            self.concurrent_results = {}
        
        try:
            fuzz_config = self.config.get('fuzzing_concurrent', {})
            if not fuzz_config.get('enabled', True):
                print("⚠  Concurrent fuzzing disabled in config")
                return
            
            iterations = fuzz_config.get('iterations', 15)
            
            print(f"Target nodes: {sorted(target_nodes)}")
            print("⚠  WARNING: Concurrent fuzzing tests race conditions and may cause state confusion")
            print()
            
            anomalies = []
            def oracle_callback(event: Dict[str, Any]) -> None:
                anomalies.append(event)
                if self.oracle:
                    self.oracle.record_event(event)
            
            for node_id in sorted(target_nodes):
                print(f"  Fuzzing concurrent messages for node {node_id}...")
                
                try:
                    od = self.results.loaded_od_objects.get(node_id)
                    if not od:
                        od = RuntimeObjectDictionary()
                    
                    fuzzer = ConcurrentFuzzer(
                        bus=self.bus,
                        node_id=node_id,
                        od=od,
                        oracle=oracle_callback,
                    )
                    
                    fuzzer.run_all_strategies(iterations=iterations)
                    
                    self.concurrent_results[node_id] = {
                        'total_tests': fuzzer.fuzzed_count,
                    }
                    print(f"    ✓ Sent {fuzzer.fuzzed_count} concurrent messages")
                    
                except Exception as e:
                    print(f"    ✗ Failed: {e}")
                    logger.debug(f"Concurrent fuzzing error for node {node_id}: {e}")
            
            print()
            print(f"✓ Concurrent fuzzing complete: {len(anomalies)} anomalies detected")
            self.results.mark_stage_completed("Concurrent Fuzzing")
            
        except Exception as e:
            self.results.mark_stage_failed("Concurrent Fuzzing", str(e))
            logger.exception("Concurrent fuzzing failed")
    
    def _stage_collect_oracle_results(self) -> None:
        """Stage 11: Collect and summarize oracle monitoring results."""
        self._print_stage_header("STAGE 11: Monitoring Results", "Collecting EMCY, heartbeat, and anomaly data")
        
        if not self.oracle:
            print("⚠  Oracle not initialized, skipping")
            return
        
        try:
            # Get alerts from oracle
            alerts = self.oracle.get_triggered_alerts()
            self.results.oracle_alerts = alerts
            
            # Categorize events
            for event in self.oracle.get_event_log():
                event_type = event.get('type', 'unknown')
                
                if event_type == 'emcy':
                    self.results.emcy_events.append(event)
                elif event_type == 'heartbeat':
                    if event.get('anomaly', False):
                        self.results.heartbeat_anomalies.append(event)
            
            print(f"Oracle Events:")
            print(f"  • Total Alerts: {len(alerts)}")
            print(f"  • EMCY Events: {len(self.results.emcy_events)}")
            print(f"  • Heartbeat Anomalies: {len(self.results.heartbeat_anomalies)}")
            
            if alerts:
                print("\nTop Alerts:")
                for alert in alerts[:10]:
                    severity = alert.get('severity', 'info')
                    rule = alert.get('rule', 'unknown')
                    timestamp = alert.get('timestamp', 'unknown')
                    print(f"  [{severity.upper()}] {rule} at {timestamp}")
            
            print()
            print("✓ Monitoring results collected")
            self.results.mark_stage_completed("Monitoring Collection")
            
        except Exception as e:
            self.results.mark_stage_failed("Monitoring Collection", str(e))
            logger.exception("Failed to collect oracle results")
    
    def _stage_generate_reports(self) -> None:
        """Stage 12: Generate HTML and JSON reports."""
        self._print_stage_header("STAGE 12: Report Generation", "Creating comprehensive test reports")
        
        try:
            report_config = self.config.get('reporting', {})
            output_dir = Path(report_config.get('output_dir', 'reports'))
            output_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            # Generate JSON export
            if report_config.get('json_export', True):
                json_path = output_dir / f"results_{timestamp}.json"
                self._export_json(json_path)
                print(f"✓ JSON report: {json_path}")
            
            # Generate HTML report
            if report_config.get('html_report', True):
                html_path = output_dir / f"report_{timestamp}.html"
                self._generate_html_report(html_path)
                print(f"✓ HTML report: {html_path}")
            
            print()
            print(f"✓ Reports generated in: {output_dir}")
            self.results.mark_stage_completed("Report Generation")
            
        except Exception as e:
            self.results.mark_stage_failed("Report Generation", str(e))
            logger.exception("Report generation failed")
    
    def _export_json(self, path: Path) -> None:
        """Export results as JSON.
        
        Args:
            path: Output file path
        """
        data = {
            'timestamp': self.results.start_time.isoformat(),
            'duration': (self.results.end_time - self.results.start_time).total_seconds() if self.results.end_time else 0,
            'config': self.config,
            'discovery': {
                'passive_nodes': list(self.results.passive_nodes),
                'active_nodes': list(self.results.active_nodes),
                'lss_nodes': self.results.lss_nodes,
                'node_details': self.results.node_details,
            },
            'object_dictionaries': {
                'loaded': self.results.loaded_ods,
                'errors': self.results.od_errors,
            },
            'hidden_objects': self.results.hidden_objects,
            'fuzzing': {
                'sdo': self.results.sdo_fuzzing_results,
                'pdo': self.results.pdo_fuzzing_results,
                'nmt': self.results.nmt_fuzzing_results,
            },
            'monitoring': {
                'emcy_events': self.results.emcy_events,
                'heartbeat_anomalies': self.results.heartbeat_anomalies,
                'oracle_alerts': self.results.oracle_alerts,
            },
            'summary': {
                'warnings': self.results.warnings,
                'errors': self.results.errors,
                'completed_stages': self.results.completed_stages,
                'failed_stages': self.results.failed_stages,
            },
        }
        
        with open(path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
    
    def _generate_html_report(self, path: Path) -> None:
        """Generate HTML report (basic version for now).
        
        Args:
            path: Output file path
        """
        # For now, generate a simple HTML report
        # This can be enhanced with a proper HTML reporter module later
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>CANopen Security Test Report - {self.results.start_time.strftime('%Y-%m-%d %H:%M:%S')}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; border-bottom: 2px solid #ecf0f1; padding-bottom: 8px; }}
        h3 {{ color: #7f8c8d; }}
        .summary {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .success {{ color: #27ae60; }}
        .warning {{ color: #f39c12; }}
        .error {{ color: #e74c3c; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #34495e; color: white; }}
        tr:hover {{ background: #f8f9fa; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 0.9em; }}
        .badge-success {{ background: #27ae60; color: white; }}
        .badge-warning {{ background: #f39c12; color: white; }}
        .badge-error {{ background: #e74c3c; color: white; }}
        .badge-info {{ background: #3498db; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>CANopen Security Test Report</h1>
        
        <div class="summary">
            <p><strong>Start Time:</strong> {self.results.start_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Duration:</strong> N/A (report generated before completion)</p>
            <p><strong>Completed Stages:</strong> <span class="success">{len(self.results.completed_stages)}</span></p>
            <p><strong>Failed Stages:</strong> <span class="error">{len(self.results.failed_stages)}</span></p>
        </div>
        
        <h2>Discovery Results</h2>
        <table>
            <tr>
                <th>Discovery Method</th>
                <th>Nodes Found</th>
            </tr>
            <tr>
                <td>Passive Discovery</td>
                <td>{len(self.results.passive_nodes)} nodes: {sorted(self.results.passive_nodes)}</td>
            </tr>
            <tr>
                <td>Active SDO Discovery</td>
                <td>{len(self.results.active_nodes)} nodes: {sorted(self.results.active_nodes)}</td>
            </tr>
            <tr>
                <td>LSS Discovery</td>
                <td>{len(self.results.lss_nodes)} nodes</td>
            </tr>
        </table>
        
        <h2>Node Inventory</h2>
        <table>
            <tr>
                <th>Node ID</th>
                <th>Device Type</th>
                <th>Device Name</th>
                <th>State</th>
            </tr>
"""
        
        all_nodes = self.results.passive_nodes | self.results.active_nodes
        for node_id in sorted(all_nodes):
            details = self.results.node_details.get(node_id, {})
            device_type = details.get('device_type', 'Unknown')
            device_name = details.get('device_name', 'Unknown')
            state = details.get('passive_state', 'Unknown')
            
            # Format device type as hex if it's an integer
            device_type_str = f"0x{device_type:08X}" if isinstance(device_type, int) else str(device_type)
            
            html += f"""
            <tr>
                <td>{node_id}</td>
                <td>{device_type_str}</td>
                <td>{device_name}</td>
                <td>{state}</td>
            </tr>
"""
        
        html += """
        </table>
        
        <h2>Hidden Objects</h2>
"""
        
        if self.results.hidden_objects:
            total_hidden = sum(len(objs) for objs in self.results.hidden_objects.values())
            html += f"<p>Found <strong>{total_hidden}</strong> hidden objects across <strong>{len(self.results.hidden_objects)}</strong> nodes</p>"
            
            for node_id, objects in self.results.hidden_objects.items():
                html += f"<h3>Node {node_id}: {len(objects)} hidden objects</h3>"
                html += "<table><tr><th>Index</th><th>Subindex</th><th>Access</th></tr>"
                for obj in objects[:20]:  # Limit display
                    idx = obj.get('index', 0)
                    subidx = obj.get('subindex', 0)
                    access = obj.get('access', 'unknown')
                    html += f"<tr><td>0x{idx:04X}</td><td>{subidx}</td><td>{access}</td></tr>"
                if len(objects) > 20:
                    html += f"<tr><td colspan='3'>... and {len(objects) - 20} more</td></tr>"
                html += "</table>"
        else:
            html += "<p>No hidden objects found</p>"
        
        html += """
        <h2>Fuzzing Results</h2>
"""
        
        # SDO Fuzzing
        if self.results.sdo_fuzzing_results:
            html += "<h3>SDO Fuzzing</h3><table><tr><th>Node</th><th>Total Tests</th><th>Anomalies</th></tr>"
            for node_id, result in self.results.sdo_fuzzing_results.items():
                total = result.get('total_tests', 0)
                anomalies = result.get('anomalies', [])
                anomaly_count = sum(a.get('anomalies', 0) for a in anomalies)
                html += f"<tr><td>{node_id}</td><td>{total}</td><td class='{'error' if anomaly_count > 0 else 'success'}'>{anomaly_count}</td></tr>"
            html += "</table>"
        
        # Monitoring
        html += f"""
        <h2>Monitoring Events</h2>
        <table>
            <tr>
                <th>Event Type</th>
                <th>Count</th>
            </tr>
            <tr>
                <td>EMCY Events</td>
                <td class="{'error' if len(self.results.emcy_events) > 0 else 'success'}">{len(self.results.emcy_events)}</td>
            </tr>
            <tr>
                <td>Heartbeat Anomalies</td>
                <td class="{'warning' if len(self.results.heartbeat_anomalies) > 0 else 'success'}">{len(self.results.heartbeat_anomalies)}</td>
            </tr>
            <tr>
                <td>Oracle Alerts</td>
                <td class="{'warning' if len(self.results.oracle_alerts) > 0 else 'success'}">{len(self.results.oracle_alerts)}</td>
            </tr>
        </table>
        
        <h2>Issues and Warnings</h2>
"""
        
        if self.results.errors:
            html += f"<h3 class='error'>Errors ({len(self.results.errors)})</h3><ul>"
            for error in self.results.errors:
                html += f"<li>{error}</li>"
            html += "</ul>"
        
        if self.results.warnings:
            html += f"<h3 class='warning'>Warnings ({len(self.results.warnings)})</h3><ul>"
            for warning in self.results.warnings:
                html += f"<li>{warning}</li>"
            html += "</ul>"
        
        html += """
    </div>
</body>
</html>
"""
        
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def _get_fuzzing_targets(self, fuzzer_key: str) -> Set[int]:
        """Get target nodes for fuzzing based on config.
        
        Args:
            fuzzer_key: Configuration key for the fuzzer
            
        Returns:
            Set of node IDs to target
        """
        config = self.config.get(fuzzer_key, {})
        target_spec = config.get('target_nodes', 'discovered')
        
        if target_spec == 'discovered':
            # Use active nodes if available, otherwise fall back to passive nodes
            if self.results.active_nodes:
                return self.results.active_nodes
            else:
                return self.results.passive_nodes
        elif target_spec == 'all':
            node_range = self.config['discovery'].get('node_range', [1, 127])
            return set(range(node_range[0], node_range[1] + 1))
        elif isinstance(target_spec, list):
            return set(target_spec)
        else:
            # Default: use active nodes, fall back to passive
            if self.results.active_nodes:
                return self.results.active_nodes
            else:
                return self.results.passive_nodes
    
    def _cleanup(self) -> None:
        """Clean up resources."""
        try:
            if self.bus:
                self.bus.close()
                logger.info("Bus connection closed")
        except Exception as e:
            logger.debug(f"Error during cleanup: {e}")


def main() -> int:
    """Main entry point for the security test suite.
    
    Returns:
        Exit code (0 for success, 1 for failure)
    """
    parser = argparse.ArgumentParser(
        description='CANopen Security Testing Platform - Full Automation Suite',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with default config
  python -m canopen_security_platform.orchestrator.run_full_security_suite
  
  # Run with custom config
  python -m canopen_security_platform.orchestrator.run_full_security_suite --config my_config.yaml
  
  # Adjust log level
  python -m canopen_security_platform.orchestrator.run_full_security_suite --log-level DEBUG
        """
    )
    
    parser.add_argument(
        '--config',
        type=Path,
        help='Path to YAML configuration file (default: orchestrator/config.yaml)',
    )
    
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Logging level (default: INFO)',
    )
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    )
    
    # Run the suite
    try:
        suite = SecurityTestSuite(config_path=args.config)
        results = suite.run()
        
        # Return success if no failed stages
        return 0 if not results.failed_stages else 1
        
    except KeyboardInterrupt:
        print("\n\nTest suite interrupted by user")
        return 130
    except Exception as e:
        logger.exception("Fatal error running test suite")
        print(f"\n✗ Fatal error: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
