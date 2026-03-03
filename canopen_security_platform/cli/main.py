"""CANopen Security Platform CLI.

Command-line interface for network discovery, object scanning,
and security testing of CANopen devices.
"""

import argparse
import logging
import sys
import json
from pathlib import Path
from typing import Optional, Tuple

import canopen

from ..utils.logging_utils import configure_logging, get_logger, enable_debug
from ..hal.bus_pcan import BusInterface
from ..discovery.enumerator import NodeEnumerator
from ..discovery.passive import PassiveDiscovery
from ..od.hidden_scanner import HiddenObjectScanner
from ..od.eds_loader import EDSLoader
from ..od.runtime_od import RuntimeObjectDictionary
from ..fuzzing.sdo_fuzzer import SDOFuzzer
from ..fuzzing.pdo_fuzzer import PDOFuzzer
from ..fuzzing.nmt_fuzzer import NMTFuzzer
from ..fuzzing.lss_fuzzer import LSSFuzzer
from ..monitoring.oracle import Oracle, AlertRule

logger = get_logger(__name__)


def _discover_and_load_default_reference_od() -> Tuple[Optional[canopen.ObjectDictionary], Optional[Path]]:
    """Load default reference OD from well-known folders if available."""
    loader = EDSLoader()
    od_file = loader.discover_default_od_file()
    if not od_file:
        return None, None

    try:
        od = loader.load_auto(str(od_file))
        return od, od_file
    except Exception as e:
        logger.warning("Failed to load default reference OD from %s: %s", od_file, e)
        return None, None


def _load_default_reference_od() -> Optional[canopen.ObjectDictionary]:
    """Compatibility helper that returns only the loaded OD object."""
    od, od_file = _discover_and_load_default_reference_od()
    if od is not None and od_file is not None:
        logger.info("Loaded reference OD from %s", od_file)
    return od


def _build_runtime_od_with_reference(
    node_id: int,
) -> RuntimeObjectDictionary:
    """Create RuntimeObjectDictionary and seed it from default OD if available."""
    runtime_od = RuntimeObjectDictionary()
    reference_od, od_file = _discover_and_load_default_reference_od()

    if reference_od is not None and od_file is not None:
        runtime_od.nodes[node_id] = reference_od
        runtime_od.node_values.setdefault(node_id, {})
        runtime_od.modifications.setdefault(node_id, [])
        logger.info("Loaded reference OD from %s for node %d", od_file, node_id)

    return runtime_od


def main() -> int:
    """Main CLI entry point.

    Returns:
        Exit code (0=success, 1=error)
    """
    parser = argparse.ArgumentParser(
        prog="cansec",
        description="CANopen Security Platform - Discovery, Enumeration & Fuzzing",
    )

    # Global options
    parser.add_argument(
        "--bitrate",
        type=int,
        default=250000,
        help="CAN bus bitrate in bps (default: 250000)",
    )
    parser.add_argument(
        "--channel",
        type=str,
        default="PCAN_USBBUS1",
        help="CAN bus channel (default: PCAN_USBBUS1)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose/debug output",
    )
    parser.add_argument(
        "--detect",
        action="store_true",
        help="Detect available CAN interfaces and exit",
    )

    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Enumerate command
    enum_parser = subparsers.add_parser(
        "enumerate",
        help="Run full network discovery (passive, SDO, LSS)",
    )
    enum_parser.add_argument(
        "--passive-only",
        action="store_true",
        help="Only run passive discovery",
    )
    enum_parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Passive discovery timeout (seconds)",
    )
    enum_parser.add_argument(
        "--output",
        type=str,
        help="Save inventory to JSON file",
    )

    # OD dump command
    od_dump = subparsers.add_parser(
        "od-dump",
        help="Dump object dictionary for a node",
    )
    od_dump.add_argument("node", type=int, help="Node ID to query")
    od_dump.add_argument(
        "--output",
        type=str,
        help="Save OD to file",
    )

    # Hidden object scan command
    scan_hidden = subparsers.add_parser(
        "scan-hidden",
        help="Scan node for hidden/undocumented objects",
    )
    scan_hidden.add_argument("node", type=int, help="Node ID to scan")
    scan_hidden.add_argument(
        "--range",
        type=str,
        help="Index range to scan (format: START-END hex)",
    )
    scan_hidden.add_argument(
        "--parallel",
        action="store_true",
        default=True,
        help="Use parallel probing (default)",
    )
    scan_hidden.add_argument(
        "--output",
        type=str,
        help="Save scan results to JSON file",
    )

    # Fuzzing commands
    fuzz_sdo = subparsers.add_parser(
        "fuzz-sdo",
        help="Run SDO fuzzing attack on node",
    )
    fuzz_sdo.add_argument("node", type=int, help="Node ID to fuzz")

    fuzz_pdo = subparsers.add_parser(
        "fuzz-pdo",
        help="Run PDO fuzzing attack on node",
    )
    fuzz_pdo.add_argument("node", type=int, help="Node ID to fuzz")

    fuzz_nmt = subparsers.add_parser(
        "fuzz-nmt",
        help="Run NMT fuzzing attack on node",
    )
    fuzz_nmt.add_argument("node", type=int, help="Node ID to fuzz")

    fuzz_lss = subparsers.add_parser(
        "fuzz-lss",
        help="Run LSS fuzzing attack",
    )

    # Help command
    subparsers.add_parser(
        "help",
        help="Show this help message",
    )

    args = parser.parse_args()

    # Configure logging
    if args.verbose:
        enable_debug()
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    configure_logging(level=log_level)

    logger.info("CANopen Security Platform v1.0")

    # Handle detect command
    if args.detect:
        logger.info("Detecting available CAN interfaces...")
        configs = BusInterface.detect_available_configs()
        for i, config in enumerate(configs, 1):
            logger.info(
                "%d. %s @ %d bps",
                i,
                config.get("channel", config.get("interface", "unknown")),
                config.get("bitrate", 0)
            )
        return 0

    # Default command
    if not args.command:
        parser.print_help()
        return 0

    try:
        # Open CAN bus
        bus_config = {
            "interface": "pcan",
            "channel": args.channel,
            "bitrate": args.bitrate,
        }

        bus = BusInterface(config=bus_config)
        network = canopen.Network()

        if args.command == "enumerate":
            return cmd_enumerate(bus, network, args)

        elif args.command == "od-dump":
            return cmd_od_dump(bus, network, args)

        elif args.command == "scan-hidden":
            return cmd_scan_hidden(bus, network, args)

        elif args.command == "fuzz-sdo":
            return cmd_fuzz_sdo(bus, network, args)

        elif args.command == "fuzz-pdo":
            return cmd_fuzz_pdo(bus, network, args)

        elif args.command == "fuzz-nmt":
            return cmd_fuzz_nmt(bus, network, args)

        elif args.command == "fuzz-lss":
            return cmd_fuzz_lss(bus, network, args)

        elif args.command == "help":
            parser.print_help()
            return 0

        else:
            parser.print_help()
            return 1

    except Exception as e:
        logger.error("Fatal error: %s", e, exc_info=args.verbose)
        return 1

    finally:
        bus.close()


def cmd_enumerate(bus: BusInterface, network: canopen.Network, args) -> int:
    """Run network enumeration."""
    try:
        logger.info("Starting network enumeration")

        network.connect(bustype="pcan", channel=args.channel, bitrate=args.bitrate)
        enumerator = NodeEnumerator(bus=network.bus, network=network)

        if args.passive_only:
            logger.info("Running passive discovery only")
            nodes = enumerator.discover_passive(timeout=args.timeout)
        else:
            logger.info("Running full discovery sequence")
            enumerator.discover_all()
            nodes = enumerator.get_discovered_nodes()

        inventory = enumerator.get_inventory()

        logger.info("Discovery complete: found %d nodes", len(nodes))
        logger.info("Node IDs: %s", sorted(nodes))

        if args.output:
            output_file = Path(args.output)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, 'w') as f:
                json.dump(inventory, f, indent=2, default=str)
            logger.info("Inventory saved to %s", output_file)

        return 0

    except Exception as e:
        logger.error("Enumeration failed: %s", e, exc_info=args.verbose)
        return 1
    finally:
        try:
            network.disconnect()
        except Exception:
            pass


def cmd_od_dump(bus: BusInterface, network: canopen.Network, args) -> int:
    """Dump object dictionary for a node."""
    try:
        logger.info("Reading object dictionary for node %d", args.node)

        network.connect(bustype="pcan", channel=args.channel, bitrate=args.bitrate)
        node = canopen.RemoteNode(args.node, None)
        network.add_node(node)

        # Try to read device type
        try:
            device_type = node.sdo.upload(0x1000, 0)
            if isinstance(device_type, (bytes, bytearray)):
                device_type = int.from_bytes(device_type, byteorder="little", signed=False)
            logger.info("Device type: 0x%08X", device_type)
        except Exception as e:
            logger.warning("Could not read device type: %s", e)

        # List objects
        od = node.object_dictionary
        logger.info("Object dictionary contains %d entries", len(od))

        for idx in sorted(od.indices)[:20]:  # Show first 20
            try:
                obj = od[idx]
                logger.info("  0x%04X: %s", idx, getattr(obj, 'name', 'unknown'))
            except Exception as e:
                logger.debug("  0x%04X: error: %s", idx, e)

        # If live OD is empty, fall back to default reference OD from od_files/... folders
        if len(od) == 0:
            reference_od, od_file = _discover_and_load_default_reference_od()
            if reference_od is not None and od_file is not None:
                logger.info(
                    "Using default reference OD from %s (%d entries)",
                    od_file,
                    len(reference_od),
                )
                for idx in sorted(reference_od.indices)[:20]:
                    try:
                        obj = reference_od[idx]
                        logger.info("  0x%04X: %s", idx, getattr(obj, 'name', 'unknown'))
                    except Exception as e:
                        logger.debug("  0x%04X: error: %s", idx, e)

        if args.output:
            output_file = Path(args.output)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            logger.info("OD dump not implemented for file output")

        return 0

    except Exception as e:
        logger.error("OD dump failed: %s", e, exc_info=args.verbose)
        return 1
    finally:
        try:
            network.disconnect()
        except Exception:
            pass


def cmd_scan_hidden(bus: BusInterface, network: canopen.Network, args) -> int:
    """Scan for hidden objects."""
    try:
        logger.info("Scanning node %d for hidden objects", args.node)

        network.connect(bustype="pcan", channel=args.channel, bitrate=args.bitrate)
        scanner = HiddenObjectScanner(network)

        # Parse range if provided
        index_range = None
        if args.range:
            parts = args.range.split('-')
            if len(parts) == 2:
                start = int(parts[0], 16)
                end = int(parts[1], 16)
                index_range = (start, end)
                logger.info("Scanning range 0x%04X-0x%04X", start, end)

        results = scanner.scan_node(
            args.node,
            index_range=index_range,
            parallel=args.parallel
        )

        logger.info("Scan complete: found %d objects", len(results))

        reference_od = _load_default_reference_od()
        if reference_od is not None:
            diffs = scanner.diff_with_eds(args.node, reference_od)
            logger.info(
                "Reference OD diff: hidden=%d missing=%d subindex_diffs=%d",
                len(diffs["hidden"]),
                len(diffs["missing"]),
                len(diffs["subindex_diffs"]),
            )

        if args.output:
            scanner.export_report(args.node, args.output)
            logger.info("Results saved to %s", args.output)

        return 0

    except Exception as e:
        logger.error("Hidden scan failed: %s", e, exc_info=args.verbose)
        return 1
    finally:
        try:
            network.disconnect()
        except Exception:
            pass


def cmd_fuzz_sdo(bus: BusInterface, network: canopen.Network, args) -> int:
    """Run SDO fuzzing."""
    try:
        logger.info("Starting SDO fuzzing on node %d", args.node)

        od = _build_runtime_od_with_reference(args.node)
        oracle_callback = lambda x: logger.debug("Oracle event: %s", x)

        with bus.open_context():
            fuzzer = SDOFuzzer(bus, od, args.node, oracle_callback)
            fuzzer.execute()
            results = fuzzer.get_results()

            logger.info(
                "Fuzzing complete: %d mutations, %d strategies",
                results["total_mutations"], results["strategies_used"]
            )

            return 0

    except Exception as e:
        logger.error("SDO fuzzing failed: %s", e, exc_info=args.verbose)
        return 1


def cmd_fuzz_pdo(bus: BusInterface, network: canopen.Network, args) -> int:
    """Run PDO fuzzing."""
    try:
        logger.info("Starting PDO fuzzing on node %d", args.node)

        od = _build_runtime_od_with_reference(args.node)
        oracle_callback = lambda x: logger.debug("Oracle event: %s", x)

        with bus.open_context():
            fuzzer = PDOFuzzer(bus, od, args.node, oracle_callback)
            fuzzer.execute()
            results = fuzzer.get_results()

            logger.info(
                "Fuzzing complete: %d mutations, %d strategies",
                results["total_mutations"], results["strategies_used"]
            )

            return 0

    except Exception as e:
        logger.error("PDO fuzzing failed: %s", e, exc_info=args.verbose)
        return 1


def cmd_fuzz_nmt(bus: BusInterface, network: canopen.Network, args) -> int:
    """Run NMT fuzzing."""
    try:
        logger.info("Starting NMT fuzzing on node %d", args.node)

        od = _build_runtime_od_with_reference(args.node)
        oracle_callback = lambda x: logger.debug("Oracle event: %s", x)

        with bus.open_context():
            fuzzer = NMTFuzzer(bus, od, args.node, oracle_callback)
            fuzzer.execute()
            results = fuzzer.get_results()

            logger.info(
                "Fuzzing complete: %d mutations, %d strategies",
                results["total_mutations"], results["strategies_used"]
            )

            return 0

    except Exception as e:
        logger.error("NMT fuzzing failed: %s", e, exc_info=args.verbose)
        return 1


def cmd_fuzz_lss(bus: BusInterface, network: canopen.Network, args) -> int:
    """Run LSS fuzzing."""
    try:
        logger.info("Starting LSS fuzzing")

        od = _build_runtime_od_with_reference(0)
        oracle_callback = lambda x: logger.debug("Oracle event: %s", x)

        with bus.open_context():
            # LSS affects network, so use node 0
            fuzzer = LSSFuzzer(bus, od, 0, oracle_callback)
            fuzzer.execute()
            results = fuzzer.get_results()

            logger.info(
                "Fuzzing complete: %d mutations, %d strategies",
                results["total_mutations"], results["strategies_used"]
            )

            return 0

    except Exception as e:
        logger.error("LSS fuzzing failed: %s", e, exc_info=args.verbose)
        return 1


if __name__ == "__main__":
    sys.exit(main())
