"""Command line interface for the tinc route analyzer."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional, Tuple

from . import reporter
from .analyzer import analyze_files
from .parser import DEFAULT_YEAR

_FORMATS = ["summary", "nodes", "pairs", "flows", "routes", "subnets",
            "csv", "json", "dot"]


def _parse_kv(values: Optional[List[str]], what: str) -> dict:
    out = {}
    for item in values or []:
        if "=" not in item:
            raise SystemExit(f"error: --{what} expects NAME=VALUE, got '{item}'")
        key, val = item.split("=", 1)
        out[key.strip()] = val.strip()
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tinc-route-analyzer",
        description=(
            "Analyse tinc VPN logs to discover which nodes exchange traffic, "
            "the route/relay path used, and the subnets each node owns — the "
            "inputs needed to migrate to an NSX VPN."
        ),
        epilog=(
            "examples:\n"
            "  tinc-route-analyzer samples/*.log\n"
            "  tinc-route-analyzer --node branch2=windows_branch2.log linux_*.log\n"
            "  tinc-route-analyzer -f json -o report.json samples/*.log\n"
            "  tinc-route-analyzer -f dot samples/*.log | dot -Tpng -o graph.png\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("logs", nargs="*", metavar="LOGFILE",
                   help="tinc log files (node name inferred from hostname/filename)")
    p.add_argument("--node", action="append", metavar="NAME=FILE",
                   help="map a log FILE to its tinc node NAME (for logs without a "
                        "syslog hostname, e.g. Windows console output); repeatable")
    p.add_argument("--host-map", action="append", metavar="OSHOST=NODE",
                   help="translate an OS hostname to its tinc node name; repeatable")
    p.add_argument("--subnets-dump", action="append", metavar="FILE",
                   help="authoritative 'tinc dump subnets' output for subnet->owner "
                        "mapping; repeatable")
    p.add_argument("-f", "--format", choices=_FORMATS, default="summary",
                   help="output format (default: summary)")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="write the report to FILE instead of stdout")
    p.add_argument("--top", type=int, default=None, metavar="N",
                   help="limit pair/flow tables to the top N rows")
    p.add_argument("--year", type=int, default=DEFAULT_YEAR,
                   help=f"year for syslog timestamps without one (default: {DEFAULT_YEAR})")
    return p


def _collect_file_specs(args) -> List[Tuple[str, Optional[str]]]:
    specs: List[Tuple[str, Optional[str]]] = []
    node_map = _parse_kv(args.node, "node")
    for name, path in node_map.items():
        specs.append((path, name))
    for path in args.logs:
        # Allow "NAME=FILE" directly as a positional too.
        if "=" in path:
            name, real = path.split("=", 1)
            specs.append((real.strip(), name.strip()))
        else:
            specs.append((path, None))
    return specs


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    specs = _collect_file_specs(args)
    if not specs:
        build_parser().print_help(sys.stderr)
        print("\nerror: no log files given", file=sys.stderr)
        return 2

    host_map = _parse_kv(args.host_map, "host-map")
    analysis, stats = analyze_files(
        specs,
        host_map=host_map or None,
        year=args.year,
        subnet_dumps=args.subnets_dump,
    )

    fmt = args.format
    if fmt == "summary":
        text = reporter.render_summary(analysis, stats, top=args.top)
    elif fmt == "nodes":
        text = reporter.render_nodes(analysis)
    elif fmt == "pairs":
        text = reporter.render_pairs(analysis, top=args.top)
    elif fmt == "flows":
        text = reporter.render_flows(analysis, top=args.top)
    elif fmt == "routes":
        text = reporter.render_routes(analysis)
    elif fmt == "subnets":
        text = reporter.render_subnets(analysis)
    elif fmt == "csv":
        text = reporter.render_csv(analysis)
    elif fmt == "json":
        text = reporter.render_json(analysis, stats)
    elif fmt == "dot":
        text = reporter.render_dot(analysis)
    else:  # pragma: no cover - argparse restricts choices
        raise SystemExit(f"unknown format {fmt}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote {fmt} report to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
