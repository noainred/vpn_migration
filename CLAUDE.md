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
  portal's live view (`--enable-capture`).
- **Scan and portal are separate processes.** The portal spawns the scan
  backend (`tinc_route_analyzer.scan`, a detached `start_new_session` process)
  which runs tshark + aggregation and writes `portal_data/live.json` (atomic,
  with heartbeat/pid). The portal only reads that file, so **restarting/
  upgrading the portal does NOT stop the scan** — `ScanController` reconnects by
  reading live.json. Control via signals: SIGTERM=stop, SIGUSR1=reset. Portal
  shutdown must never stop the scan.
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
- `tinc_route_analyzer/job.py` — **detached analysis-job backend** (same engine
  as the CLI; `start_new_session`). Lets the portal analyse big server-side
  captures or `--merge` several servers' `portal_data` dirs without blocking;
  writes `job.json`/`job_report.json` (atomic, heartbeat/pid) that the portal
  reads via `JobController`. SIGTERM cancels. Endpoints `/api/job/{start,status,
  result,cancel}`. **Re-analysis exclusion filter** (`flowcsv.FlowFilter`,
  `filter_analysis`): exclude by source/destination IP or subnet, protocol, and
  port + top-N row limit. Applied per-packet for raw CSV (`filter_basis=packet`)
  and at conversation/service level for merge (`aggregate`). Last-used options
  persist in `analysis_filter.json` (`/api/analysis/filter`); named **presets**
  in `analysis_presets.json` (`/api/analysis/presets`); **default analysis
  paths** preset in ⚙ Settings (`analysis_paths.json`, `/api/analysis/paths`;
  hides the path box on the analysis screen). The portal also has a client-side
  **chained drill-down** (1차→2차→… include/exclude stages re-derived from the
  shown result, no re-run). Analysis of a directory path auto-expands to its
  `*.csv`/`*.gz` captures (never crashes on "Is a directory").
- `tinc_route_analyzer/web/` — portal (stdlib http.server, no CDN). Auto-detects
  input: aggregated flow JSON (one or many -> merged/deduped), tshark CSV, or
  tinc logs. `static/topology.html` = full-page force-layout topology (pan/zoom).
  **Two role workspaces** (top-bar toggle, persisted in localStorage): 수집서버
  (`body.mode-collect` → file upload + live capture) and 분석 서버
  (`body.mode-analyze` → server-side direct analysis/merge). System dashboard
  (`#sysmon`) and results (`#results`) are shared by both; ⚙ 설정 is a common overlay.
- `tinc_route_analyzer/web/persistence.py` — minute/hour/day snapshot scheduler
  + `system_stats()` (CPU via `resource`, RSS via `/proc/self/status`, disk via
  `shutil.disk_usage`; no psutil). Endpoints: `/api/sysstatus`,
  `/api/persist/config`, `/api/live/reset`, `/api/last`.
- Flow analysis extras: per-host hour-of-week **activity histogram** (bounded to
  168 slots/host -> idle-window/migration detection) and
  `analysis_from_report`/`merge_reports` for multi-server consolidation
  (dedupe by conversation pair / (server,proto,port) service).
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

## Workflow

- **Always open/update a pull request when work is finished** (base: `main`,
  head: the feature branch). A PR already exists for the current feature
  branch, so further pushes to it update that PR automatically; for a new
  feature branch, open a fresh PR into `main` once the work is committed.
- **Bump `__version__` (`tinc_route_analyzer/__init__.py`) every time work is
  finished**, then report the **final version** to the user after the PR is
  updated: semver + the build/commit from `version_info()` (e.g.
  `v1.5.0 · ab12cd3`). Minor bump for features, patch for fixes. This is a
  standing rule — do it on every completed change, not only when asked.
- **After every completed task, publish a versioned release bundle and report
  to the user in this exact order:** (1) the **commit** (short SHA + subject),
  then (2) the **version-named `.zip` download link**. The bundle is built into
  `download/` (`tinc_route_analyzer-<ver>.zip` + matching `.tar.gz`, package at
  top level, no `__pycache__`) and `versions.json` `latest` is bumped to the new
  version, so the download link is:
  `https://github.com/noainred/vpn_migration/raw/<branch>/download/tinc_route_analyzer-<ver>.zip`
  Standing rule — do this every time, not only when asked. (The updater accepts
  `.zip`, so this keeps auto-update working too.)

