# Engineering guidance for this repo (read first)

VPN migration toolkit: analyse current traffic (tinc logs and/or tshark packet
captures) and produce the facts needed to rebuild connectivity and firewall
policy on **NSX**.

## Working principles (non-negotiable)

1. **Fact-based, never guess.** Every number and label must trace to observed
   data or a documented standard. When something is inferred, mark it as
   inferred and cite its basis; when the evidence is not decisive, output
   "undetermined" rather than a guess.
   - Example: the server/listening port of a flow is decided from **IANA RFC
     6335 port ranges** (system <=1023, registered, dynamic >=49152) plus OS
     ephemeral ranges (Linux 32768-60999). If both ports are in the same class
     we cannot know the initiator from addressing alone (no TCP flags in the
     capture), so `_service_port` returns `None` and no policy is fabricated.
   - Service detection is corroborated with evidence: the count of distinct
     client hosts seen connecting to `server:port`.
   - Stronger still: if `tcp.flags` is captured, the TCP 3-way handshake gives
     the server side as a fact (SYN -> dst is server; SYN-ACK -> src is server),
     overriding the port-range inference. Each service records its `basis`
     (`handshake` vs `port-range`).
2. **Measure, don't estimate.** Back performance/scale claims with a real run
   (generate data, time it, read peak RSS). Do not state throughput numbers
   from memory.
3. **Build it well.** Clear modules, tests for every behaviour, no dead code.

## Scale requirement (tens of GB captures)

The real input is tshark CSV that can be **tens of GB**. Design consequences:

- **Streaming, single pass.** Never load a whole capture into memory. Parsing
  is line-iterable based (`flowcsv.iter_flow_records`).
- **Memory bounded by network cardinality**, not packet count — aggregation
  keys are hosts / conversation pairs / (server,proto,port) services / subnet
  pairs. (Measured: ~13-22 MB RSS for 3M packets.)
- **Heavy work runs in the CLI**, where the data lives:
  `tinc-flow-analyzer` (`python -m tinc_route_analyzer.flowcsv`). It supports
  `.gz`, globs, `-j/--workers` (exact line-boundary chunking + merge, verified
  bit-identical to sequential), `--no-time`, and `--progress`.
- **The web portal visualises the small aggregated `report.json`** produced by
  the CLI. Direct browser CSV upload is capped (64 MB) and otherwise redirects
  the user to the CLI. The portal must never be the heavy processor.

## Live capture (near-real-time)

- The toolkit does **not** sniff packets itself (stdlib only). Live = pipe
  `tshark -l` output in: CLI `--stdin --live` (refreshing dashboard) or the
  portal's live view (`--enable-capture`, server runs tshark in a thread,
  browser polls `/api/live/status`).
- "End-to-end IP" depends on the capture point: VPN iface (`tun0`) shows inner
  overlay endpoints; physical NIC shows tunnel endpoints; NAT rewrites them.
  State this; never claim true end-to-end from a single mid-path capture.
- Capture is **opt-in and validated**: disabled by default (403), interface
  name whitelisted by regex, tshark spawned without a shell (argv list).

## Layout

- `tinc_route_analyzer/flowcsv.py` — tshark CSV: streaming parse, conversation
  (A<->B deduped) / host / service / subnet aggregation, parallel engine,
  reports (summary/csv/json/dot), CLI.
- `tinc_route_analyzer/{parser,analyzer,reporter,cli}.py` — tinc log analyzer.
- `tinc_route_analyzer/web/` — portal (stdlib http.server, no CDN). Auto-detects
  input: aggregated flow JSON, tshark CSV, or tinc logs.
- `samples/network.csv` — real-format packet-capture sample. `tests/` — run
  with `python -m unittest discover -s tests`.

## Conventions

- Standard library only (no third-party runtime deps); must run air-gapped.
- **Target Python 3.6+** (enterprise RHEL boxes ship 3.6). Do NOT use 3.7+ only
  features: no `from __future__ import annotations`, no `dataclasses`, no
  `datetime.fromisoformat`, no `re.Pattern`, no `subprocess` `text=`/
  `capture_output=`, no PEP 585 generics in evaluated annotations (use
  `typing.List/Dict/Set` or `# type:` comments). `ThreadingHTTPServer` is
  defined locally (ThreadingMixIn + HTTPServer).
- A->B and B->A are the **same conversation** (dedup), always with a
  per-direction breakdown kept alongside the merged total.
