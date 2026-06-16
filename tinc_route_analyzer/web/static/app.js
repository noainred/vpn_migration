"use strict";

// ---- state ----------------------------------------------------------------
const state = { files: [], result: null };

const $ = (sel) => document.querySelector(sel);
const els = {
  drop: $("#dropzone"),
  input: $("#fileInput"),
  list: $("#fileList"),
  subnetDump: $("#subnetDump"),
  hostMap: $("#hostMap"),
  year: $("#year"),
  msg: $("#msg"),
  results: $("#results"),
  overview: $("#overview"),
};

// ---- helpers --------------------------------------------------------------
function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function fmtBytes(n) {
  n = Number(n) || 0;
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return i === 0 ? `${n}B` : `${n.toFixed(1)}${u[i]}`;
}
function guessNode(name) {
  let stem = name.replace(/\.[^.]+$/, "");
  for (const p of ["linux_", "windows_", "macos_", "darwin_", "bsd_", "tinc_", "tincd_"]) {
    if (stem.startsWith(p)) return stem.slice(p.length);
  }
  return stem;
}
function setMsg(text, kind) {
  els.msg.textContent = text || "";
  els.msg.className = "msg" + (kind ? " " + kind : "");
}
function readFile(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result || ""));
    r.onerror = () => reject(r.error);
    r.readAsText(file);
  });
}
function download(filename, text, type) {
  const blob = new Blob([text], { type: type || "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}

// ---- file intake ----------------------------------------------------------
async function addFiles(fileList) {
  const arr = Array.from(fileList || []);
  for (const f of arr) {
    try {
      const content = await readFile(f);
      state.files.push({ name: f.name, node: guessNode(f.name), content });
    } catch (e) {
      setMsg(`'${f.name}' 읽기 실패: ${e}`, "err");
    }
  }
  renderFileList();
}
function renderFileList() {
  els.list.innerHTML = state.files.map((f, i) => {
    const lines = f.content ? f.content.split(/\r?\n/).length : 0;
    return `<li>
      <div>
        <div class="fname" title="${esc(f.name)}">${esc(f.name)}</div>
        <div class="fmeta">${lines.toLocaleString()} 줄</div>
      </div>
      <input data-i="${i}" class="nodeInput" value="${esc(f.node)}" placeholder="노드명" title="이 로그를 기록한 tinc 노드명" />
      <button class="rm" data-i="${i}" title="제거">✕</button>
    </li>`;
  }).join("");
  els.list.querySelectorAll(".nodeInput").forEach((inp) => {
    inp.addEventListener("input", (e) => {
      state.files[+e.target.dataset.i].node = e.target.value;
    });
  });
  els.list.querySelectorAll(".rm").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      state.files.splice(+e.target.dataset.i, 1);
      renderFileList();
    });
  });
}

// ---- analyze --------------------------------------------------------------
function parseHostMap() {
  const map = {};
  (els.hostMap.value || "").split(/\r?\n/).forEach((line) => {
    const i = line.indexOf("=");
    if (i > 0) map[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  });
  return map;
}

async function analyze() {
  if (!state.files.length) { setMsg("로그 파일을 먼저 추가하세요.", "err"); return; }
  setMsg("분석 중…");
  const payload = {
    files: state.files.map((f) => ({ name: f.name, node: f.node, content: f.content })),
    subnetDump: els.subnetDump.value || "",
    hostMap: parseHostMap(),
    year: Number(els.year.value) || 2026,
  };
  try {
    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const json = await res.json();
    if (!json.ok) { setMsg("분석 실패: " + (json.error || "unknown"), "err"); return; }
    state.result = json;
    renderAll(json);
    const ev = json.data.flows.length;
    setMsg(`완료 — 노드 ${json.data.nodes.length}개, 정책 ${json.data.communication_pairs.length}건, 플로우 ${ev}개`, "ok");
    els.results.classList.remove("hidden");
    els.results.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (e) {
    setMsg("요청 실패: " + e, "err");
  }
}

async function loadSample() {
  setMsg("예제 로딩 중…");
  try {
    const res = await fetch("/api/sample");
    const json = await res.json();
    const s = (json.samples || [])[0];
    if (!s) { setMsg("예제를 찾을 수 없습니다.", "err"); return; }
    state.files = s.files.map((f) => ({ name: f.name, node: guessNode(f.name), content: f.content }));
    els.subnetDump.value = s.subnetDump || "";
    renderFileList();
    await analyze();
  } catch (e) {
    setMsg("예제 로드 실패: " + e, "err");
  }
}

function clearAll() {
  state.files = []; state.result = null;
  els.subnetDump.value = ""; els.hostMap.value = "";
  renderFileList();
  els.results.classList.add("hidden");
  setMsg("");
}

// ---- rendering ------------------------------------------------------------
function renderAll(json) {
  const d = json.data;
  renderOverview(d);
  renderStatus(d);
  renderHosts(d);
  renderPolicies(d);
  renderRouting(d);
  renderGraph(d);
}

function card(k, v, sub) {
  return `<div class="card"><div class="k">${esc(k)}</div>
    <div class="v">${v}${sub ? ` <small>${esc(sub)}</small>` : ""}</div></div>`;
}
function renderOverview(d) {
  const logged = d.nodes.filter((n) => n.has_log).length;
  const relayed = d.communication_pairs.filter((p) => p.via.length || p.forwarded_packets).length;
  els.overview.innerHTML = [
    card("노드", d.nodes.length, `로그 ${logged}`),
    card("정책(통신쌍)", d.communication_pairs.length),
    card("라우팅(중계)", relayed),
    card("서브넷", Object.keys(d.subnets).length),
    card("플로우", d.flows.length),
  ].join("");
}

function table(headers, rows) {
  if (!rows.length) return `<p class="muted">데이터가 없습니다.</p>`;
  return `<table class="grid"><thead><tr>${
    headers.map((h) => `<th>${esc(h)}</th>`).join("")
  }</tr></thead><tbody>${
    rows.map((r) => `<tr>${r.join("")}</tr>`).join("")
  }</tbody></table>`;
}
const td = (v) => `<td>${v == null ? "" : v}</td>`;
const tdn = (v) => `<td class="num">${v == null ? "" : v}</td>`;

function pathBadge(p) {
  if (p.direct_link && !p.via.length) return `<span class="badge direct">직접</span>`;
  if (p.via.length) return `<span class="badge relay">중계 via ${esc(p.via.join(", "))}</span>`;
  return `<span class="badge indirect">간접</span>`;
}

function renderStatus(d) {
  const sources = (d.meta.stats && d.meta.stats.sources) || [];
  const srcRows = sources.map((s) => [
    td(`<code>${esc(s.name)}</code>`), td(esc(s.node || "-")),
    tdn((s.lines || 0).toLocaleString()), tdn((s.events || 0).toLocaleString()),
  ]);
  const peerOnly = d.nodes.filter((n) => !n.has_log).map((n) => n.name);
  const span = (d.meta.first_seen && d.meta.first_seen !== "-")
    ? `${esc(d.meta.first_seen)} ~ ${esc(d.meta.last_seen)}` : "타임스탬프 없음";
  let html = `<div class="section-title">수집 파일별 현황</div>`;
  html += table(["파일", "노드", "라인", "인식 이벤트"], srcRows);
  html += `<div class="section-title" style="margin-top:18px">수집 요약</div>`;
  html += `<table class="grid"><tbody>
    <tr><th>관측 기간</th><td>${span}</td></tr>
    <tr><th>총 라인 / 인식 이벤트</th><td>${(d.meta.stats.lines||0).toLocaleString()} 줄 → ${(d.meta.stats.events||0).toLocaleString()} 이벤트</td></tr>
    <tr><th>로그 수집 노드</th><td>${d.nodes.filter(n=>n.has_log).length} / ${d.nodes.length}</td></tr>
    <tr><th>피어로만 관측된 노드</th><td>${peerOnly.length ? esc(peerOnly.join(", ")) : "<span class='muted'>없음</span>"}</td></tr>
  </tbody></table>`;
  if (d.meta.events_without_local) {
    html += `<div class="notice">패킷 ${d.meta.events_without_local}건은 기록 노드를 식별하지 못했습니다.
      해당 로그 파일에 노드명을 지정하면(파일 목록의 노드명 입력) 방향이 정확해집니다.</div>`;
  }
  $("#tab-status").innerHTML = html;
}

function renderHosts(d) {
  const rows = d.nodes.map((n) => [
    td(`<strong>${esc(n.name)}</strong>`),
    td(n.has_log ? `<span class="badge yes">수집됨</span>` : `<span class="badge no">피어관측</span>`),
    td(`<span class="mono">${esc(n.real_addresses.join(", ") || "-")}</span>`),
    td(`<span class="mono">${esc(n.subnets.join(", ") || "-")}</span>`),
    tdn(n.peers.length),
    td(esc(n.direct_links.join(", ") || "-")),
    tdn(fmtBytes(n.sent_bytes)),
    tdn(fmtBytes(n.recv_bytes)),
  ]);
  let html = `<div class="section-title">호스트 / 노드 정보 (물리주소 = NSX 터널 엔드포인트)</div>`;
  html += table(["노드", "수집상태", "물리주소", "소유 서브넷", "피어", "직접연결", "송신", "수신"], rows);
  const subRows = Object.entries(d.subnets).sort((a, b) => a[1].localeCompare(b[1]))
    .map(([s, o]) => [td(`<code>${esc(s)}</code>`), td(esc(o))]);
  html += `<div class="section-title" style="margin-top:18px">서브넷 소유 (NSX IP Set/Group)</div>`;
  html += table(["서브넷", "소유 노드"], subRows);
  $("#tab-hosts").innerHTML = html;
}

function renderPolicies(d) {
  const rows = (d.policies || []).map((p) => [
    td(`<code>${esc(p.name)}</code>`),
    td(`<strong>${esc(p.a)}</strong> ⟷ <strong>${esc(p.b)}</strong>`),
    td(`<span class="mono">${esc(p.a_subnets.join(", ") || "-")}</span>`),
    td(`<span class="mono">${esc(p.b_subnets.join(", ") || "-")}</span>`),
    td(`<span class="badge yes">${esc(p.action)}</span>`),
    tdn((p.packets || 0).toLocaleString()),
    tdn(fmtBytes(p.bytes)),
    td(p.relayed ? `<span class="badge relay">${esc(p.path)}</span>` : `<span class="badge direct">${esc(p.path)}</span>`),
  ]);
  let html = `<div class="section-title">수집된 정책 — 관측된 통신을 NSX 허용 규칙 후보로 변환</div>`;
  html += table(["정책명", "연결", "A 서브넷", "B 서브넷", "동작", "패킷", "바이트", "경로"], rows);
  html += `<div class="notice">각 행은 실제로 트래픽이 관측된 노드 쌍입니다. NSX 분산 방화벽/게이트웨이에서
    해당 IP Set 간 통신을 허용하는 규칙으로 매핑하세요. '정책 CSV' 로 내보낼 수 있습니다.</div>`;
  $("#tab-policies").innerHTML = html;
}

function renderRouting(d) {
  const directSet = new Set((d.direct_links || []).map((p) => p.slice().sort().join("|")));
  const routed = d.flows.filter((f) => f.via.length || f.forwarded_packets);
  let html = `<div class="section-title">라우팅 / 중계 경로 (tinc가 자동 라우팅한 멀티홉)</div>`;
  if (!routed.length) {
    html += `<p class="muted">중계(멀티홉) 트래픽이 없습니다 — 모든 트래픽이 직접 연결입니다.</p>`;
  } else {
    const rows = routed.map((f) => {
      const noTunnel = !directSet.has([f.src, f.dst].sort().join("|"));
      const path = `${esc(f.src)} → ${esc(f.via.join(" / ") || "?")} → ${esc(f.dst)}`;
      return [
        td(`<span class="mono">${path}</span>`),
        tdn(f.forwarded_packets || f.packets),
        td(noTunnel ? `<span class="badge indirect">직접 터널 없음</span>` : `<span class="badge direct">직접 터널 있음</span>`),
      ];
    });
    html += table(["경로", "패킷", "비고"], rows);
    // relay summary
    const relayRows = Object.entries(d.relays || {}).map(([relay, pairs]) => [
      td(`<strong>${esc(relay)}</strong>`),
      tdn(Object.keys(pairs).length),
      td(`<span class="mono">${esc(Object.keys(pairs).join(", "))}</span>`),
    ]);
    html += `<div class="section-title" style="margin-top:18px">중계 노드</div>`;
    html += table(["중계 노드", "중계 쌍 수", "중계한 경로"], relayRows);
    html += `<div class="notice">tinc에서는 이 홉들이 자동입니다. NSX에서는 위 쌍에 대해 명시적 연결
      (허브 라우팅 또는 직접 터널)을 구성해야 동일하게 통신됩니다.</div>`;
  }
  $("#tab-routing").innerHTML = html;
}

// ---- graph (dependency-free SVG, circular layout) -------------------------
function renderGraph(d) {
  const nodes = d.nodes;
  const box = $("#graph");
  if (!nodes.length) { box.innerHTML = `<p class="muted">노드가 없습니다.</p>`; return; }
  const W = 840, H = 560, cx = W / 2, cy = H / 2;
  const R = Math.max(120, Math.min(cx, cy) - 110);
  const relaySet = new Set(Object.keys(d.relays || {}));
  const maxTraffic = Math.max(1, ...nodes.map((n) => n.sent_bytes + n.recv_bytes));
  const pos = {};
  nodes.forEach((n, i) => {
    const a = -Math.PI / 2 + (2 * Math.PI * i) / nodes.length;
    pos[n.name] = { x: cx + R * Math.cos(a), y: cy + R * Math.sin(a), n };
  });

  const maxBytes = Math.max(1, ...d.communication_pairs.map((p) => p.bytes));
  let edges = "";
  d.communication_pairs.forEach((p) => {
    const A = pos[p.a], B = pos[p.b];
    if (!A || !B) return;
    const w = 1.2 + 4 * Math.sqrt((p.bytes || 0) / maxBytes);
    const relay = p.via.length > 0;
    const mx = (A.x + B.x) / 2, my = (A.y + B.y) / 2;
    const title = `${p.a} ⟷ ${p.b}: ${p.packets}패킷, ${fmtBytes(p.bytes)}${relay ? " (via " + p.via.join(",") + ")" : ""}`;
    edges += `<line class="edge${relay ? " relay" : ""}" x1="${A.x.toFixed(1)}" y1="${A.y.toFixed(1)}" x2="${B.x.toFixed(1)}" y2="${B.y.toFixed(1)}" stroke-width="${w.toFixed(2)}"><title>${esc(title)}</title></line>`;
    edges += `<text class="edge-label" x="${mx.toFixed(1)}" y="${(my - 3).toFixed(1)}" text-anchor="middle">${p.packets}p</text>`;
  });

  let nodeSvg = "";
  nodes.forEach((n) => {
    const P = pos[n.name];
    const r = 18 + 16 * Math.sqrt((n.sent_bytes + n.recv_bytes) / maxTraffic);
    const cls = "node" + (n.has_log ? "" : " peer") + (relaySet.has(n.name) ? " relay" : "");
    const sub = n.subnets[0] ? `<text class="sub" x="${P.x.toFixed(1)}" y="${(P.y + r + 12).toFixed(1)}">${esc(n.subnets[0])}</text>` : "";
    const title = `${n.name}\n물리주소: ${n.real_addresses.join(", ") || "-"}\n서브넷: ${n.subnets.join(", ") || "-"}\n송신 ${fmtBytes(n.sent_bytes)} / 수신 ${fmtBytes(n.recv_bytes)}`;
    nodeSvg += `<g class="${cls}"><title>${esc(title)}</title>
      <circle cx="${P.x.toFixed(1)}" cy="${P.y.toFixed(1)}" r="${r.toFixed(1)}"></circle>
      <text x="${P.x.toFixed(1)}" y="${(P.y + 4).toFixed(1)}">${esc(n.name)}</text>${sub}</g>`;
  });

  box.innerHTML = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="tinc 토폴로지">
    <g>${edges}</g><g>${nodeSvg}</g></svg>`;
}

// ---- exports --------------------------------------------------------------
function bindExports() {
  $("#btnJson").addEventListener("click", () => {
    if (state.result) download("tinc_report.json", JSON.stringify(state.result.data, null, 2), "application/json");
  });
  $("#btnFlowsCsv").addEventListener("click", () => {
    if (state.result) download("tinc_flows.csv", state.result.exports.flows_csv, "text/csv");
  });
  $("#btnPoliciesCsv").addEventListener("click", () => {
    if (state.result) download("tinc_policies.csv", state.result.exports.policies_csv, "text/csv");
  });
  $("#btnDot").addEventListener("click", () => {
    if (state.result) download("tinc_topology.dot", state.result.exports.dot, "text/vnd.graphviz");
  });
  $("#btnSummary").addEventListener("click", () => {
    if (state.result) download("tinc_summary.txt", state.result.summaryText, "text/plain");
  });
}

// ---- wiring ---------------------------------------------------------------
function bindTabs() {
  document.querySelectorAll(".tab").forEach((t) => {
    t.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
      document.querySelectorAll(".tabpanel").forEach((x) => x.classList.remove("active"));
      t.classList.add("active");
      $("#tab-" + t.dataset.tab).classList.add("active");
    });
  });
}

function init() {
  els.drop.addEventListener("click", () => els.input.click());
  els.input.addEventListener("change", (e) => { addFiles(e.target.files); e.target.value = ""; });
  ["dragenter", "dragover"].forEach((ev) => els.drop.addEventListener(ev, (e) => {
    e.preventDefault(); els.drop.classList.add("drag");
  }));
  ["dragleave", "drop"].forEach((ev) => els.drop.addEventListener(ev, (e) => {
    e.preventDefault(); els.drop.classList.remove("drag");
  }));
  els.drop.addEventListener("drop", (e) => { if (e.dataTransfer) addFiles(e.dataTransfer.files); });
  $("#btnAnalyze").addEventListener("click", analyze);
  $("#btnSample").addEventListener("click", loadSample);
  $("#btnClear").addEventListener("click", clearAll);
  bindTabs();
  bindExports();
}

document.addEventListener("DOMContentLoaded", init);
