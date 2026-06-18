"use strict";

// ---- state ----------------------------------------------------------------
const state = { files: [], result: null, liveTimer: null };
const $ = (sel) => document.querySelector(sel);
const els = {
  drop: $("#dropzone"), input: $("#fileInput"), list: $("#fileList"),
  subnetDump: $("#subnetDump"), hostMap: $("#hostMap"), year: $("#year"),
  msg: $("#msg"), results: $("#results"), overview: $("#overview"),
};

// ---- helpers --------------------------------------------------------------
function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function fmtBytes(n) {
  n = Number(n) || 0; const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return i === 0 ? `${n}B` : `${n.toFixed(1)}${u[i]}`;
}
function num(n) { return (Number(n) || 0).toLocaleString(); }
function guessNode(name) {
  let s = name.replace(/\.[^.]+$/, "");
  for (const p of ["linux_", "windows_", "macos_", "darwin_", "bsd_", "tinc_", "tincd_"])
    if (s.startsWith(p)) return s.slice(p.length);
  return s;
}
function setMsg(t, kind) { els.msg.textContent = t || ""; els.msg.className = "msg" + (kind ? " " + kind : ""); }
function readFile(file) {
  return new Promise((res, rej) => {
    const r = new FileReader();
    r.onload = () => res(String(r.result || "")); r.onerror = () => rej(r.error);
    r.readAsText(file);
  });
}
function download(filename, text, type) {
  const blob = new Blob([text], { type: type || "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}

// ---- file intake ----------------------------------------------------------
async function addFiles(fileList) {
  for (const f of Array.from(fileList || [])) {
    try {
      state.files.push({ name: f.name, node: guessNode(f.name), content: await readFile(f) });
    } catch (e) { setMsg(`'${f.name}' 읽기 실패: ${e}`, "err"); }
  }
  renderFileList();
}
function renderFileList() {
  els.list.innerHTML = state.files.map((f, i) => {
    const lines = f.content ? f.content.split(/\r?\n/).length : 0;
    return `<li>
      <div><div class="fname" title="${esc(f.name)}">${esc(f.name)}</div>
        <div class="fmeta">${num(lines)} 줄</div></div>
      <input data-i="${i}" class="nodeInput" value="${esc(f.node)}" placeholder="노드명(tinc)" title="tinc 로그일 때만 사용" />
      <button class="rm" data-i="${i}" title="제거">✕</button></li>`;
  }).join("");
  els.list.querySelectorAll(".nodeInput").forEach((inp) =>
    inp.addEventListener("input", (e) => { state.files[+e.target.dataset.i].node = e.target.value; }));
  els.list.querySelectorAll(".rm").forEach((btn) =>
    btn.addEventListener("click", (e) => { state.files.splice(+e.target.dataset.i, 1); renderFileList(); }));
}

// ---- analyze --------------------------------------------------------------
function parseHostMap() {
  const map = {};
  (els.hostMap.value || "").split(/\r?\n/).forEach((line) => {
    const i = line.indexOf("="); if (i > 0) map[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  });
  return map;
}
// ---- live capture ---------------------------------------------------------
function setLiveStatus(t, kind) {
  const el = $("#liveStatus"); el.textContent = t || ""; el.className = "msg" + (kind ? " " + kind : "");
}
function stopLivePolling() {
  if (state.liveTimer) { clearInterval(state.liveTimer); state.liveTimer = null; }
}
async function startLive() {
  const iface = ($("#liveIface").value || "").trim();
  if (!iface) { setLiveStatus("인터페이스 이름을 입력하세요 (예: tun0).", "err"); return; }
  setLiveStatus("캡처 시작 중…");
  try {
    const res = await fetch("/api/live/start", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ iface }),
    });
    const json = await res.json();
    if (!json.ok) { setLiveStatus(json.error || "시작 실패", "err"); return; }
    setLiveStatus(`'${iface}' 캡처 중…`, "ok");
    setCapturing(true, `🔴 '${iface}' 캡처 시작…`);   // hide controls, show stop bar
    els.results.classList.remove("hidden");
    window.scrollTo({ top: 0, behavior: "smooth" });   // bring results to the top
    stopLivePolling();
    await pollLive();
    state.liveTimer = setInterval(pollLive, 2000);
  } catch (e) { setLiveStatus("요청 실패: " + e, "err"); }
}
function setCapturing(on, text) {
  document.body.classList.toggle("capturing", on);
  $("#liveBar").classList.toggle("hidden", !on);
  if (text != null) $("#liveBarText").textContent = text;
}
async function pollLive() {
  try {
    const json = await (await fetch("/api/live/status")).json();
    if (!json.ok) { setLiveStatus(json.error || "상태 조회 실패", "err"); stopLivePolling(); return; }
    state.result = json;
    renderFlow(json);
    setupExports("live", json);
    const txt = `🔴 ${json.iface || "?"} 캡처 중 — ${json.elapsed}s · ${Math.round(json.pps).toLocaleString()} pkt/s · 패킷 ${num(json.data.meta.packets)}`;
    setLiveStatus(txt, json.running ? "ok" : "");
    if (json.running) setCapturing(true, txt);
    if (!json.running) { setCapturing(false); if (json.error) { setLiveStatus("캡처 종료: " + json.error, "err"); stopLivePolling(); } }
  } catch (e) { setLiveStatus("폴링 실패: " + e, "err"); stopLivePolling(); }
}
async function stopLive() {
  stopLivePolling();
  setCapturing(false);
  try { await fetch("/api/live/stop", { method: "POST" }); } catch (e) { /* ignore */ }
  setLiveStatus("캡처를 중지했습니다.");
}
async function loadVersion() {
  try {
    const v = await (await fetch("/api/version")).json();
    const build = v.build ? " · " + v.build : "";
    $("#appVer").textContent = "v" + (v.version || "?") + build;
    if (v.date) $("#appVer").title = "배포 빌드: " + (v.build || "") + " (" + v.date + ")";
    const foot = $("#appVerFoot");
    if (foot) foot.textContent = " · v" + (v.version || "?") + build + (v.date ? " (" + v.date.slice(0, 10) + ")" : "");
  } catch (e) { $("#appVer").textContent = ""; }
}
async function resumeLiveIfRunning() {
  // After a page refresh, reconnect to a capture that is still running on the server.
  try {
    const json = await (await fetch("/api/live/status")).json();
    if (json && json.ok && json.running) {
      els.results.classList.remove("hidden");
      stopLivePolling();
      await pollLive();                 // re-renders live view + re-enters capturing mode
      state.liveTimer = setInterval(pollLive, 2000);
    }
  } catch (e) { /* ignore */ }
}

async function analyze() {
  stopLivePolling();
  setCapturing(false);
  if (!state.files.length) { setMsg("파일을 먼저 추가하세요.", "err"); return; }
  setMsg("분석 중…");
  const payload = {
    files: state.files.map((f) => ({ name: f.name, node: f.node, content: f.content })),
    subnetDump: els.subnetDump.value || "", hostMap: parseHostMap(),
    year: Number(els.year.value) || 2026,
  };
  try {
    const res = await fetch("/api/analyze", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
    });
    const json = await res.json();
    if (!json.ok) { setMsg(json.error || "분석 실패", "err"); return; }
    state.result = json;
    (json.mode === "flow" ? renderFlow : renderTinc)(json);
    setupExports(json.mode, json);
    els.results.classList.remove("hidden");
    els.results.scrollIntoView({ behavior: "smooth", block: "start" });
    setMsg(json.mode === "flow"
      ? `완료 — 패킷 ${num(json.data.meta.packets)}, 호스트 ${json.data.meta.hosts}, 통신쌍 ${json.data.meta.conversations}, 서비스 ${json.data.meta.services}${json.fromReport ? " (report.json)" : ""}`
      : `완료 — 노드 ${json.data.nodes.length}, 정책 ${json.data.communication_pairs.length}`, "ok");
  } catch (e) { setMsg("요청 실패: " + e, "err"); }
}
async function loadSample() {
  setMsg("예제 로딩 중…");
  try {
    const json = await (await fetch("/api/sample")).json();
    const s = (json.samples || [])[0];
    if (!s) { setMsg("예제를 찾을 수 없습니다.", "err"); return; }
    state.files = s.files.map((f) => ({ name: f.name, node: guessNode(f.name), content: f.content }));
    els.subnetDump.value = s.subnetDump || "";
    renderFileList();
    await analyze();
  } catch (e) { setMsg("예제 로드 실패: " + e, "err"); }
}
function clearAll() {
  stopLivePolling();
  setCapturing(false);
  state.files = []; state.result = null; state.selectedIp = null;
  els.subnetDump.value = ""; els.hostMap.value = "";
  renderFileList(); els.results.classList.add("hidden"); setMsg("");
}

// ---- shared render helpers ------------------------------------------------
function card(k, v, sub) {
  return `<div class="card"><div class="k">${esc(k)}</div>
    <div class="v">${v}${sub ? ` <small>${esc(sub)}</small>` : ""}</div></div>`;
}
function table(headers, rows) {
  if (!rows.length) return `<p class="muted">데이터가 없습니다.</p>`;
  return `<table class="grid"><thead><tr>${headers.map((h, i) => `<th class="sortable" data-i="${i}">${esc(h)}<span class="sort-ind"></span></th>`).join("")
    }</tr></thead><tbody>${rows.map((r) => `<tr>${r.join("")}</tr>`).join("")}</tbody></table>`;
}
function parseSortVal(t) {
  t = (t || "").trim();
  const m = t.match(/^([\d.,]+)\s*(B|KB|MB|GB|TB)$/i);
  if (m) { const mul = { b: 1, kb: 1024, mb: 1048576, gb: 1073741824, tb: 1099511627776 }[m[2].toLowerCase()];
    return parseFloat(m[1].replace(/,/g, "")) * mul; }
  const num = t.replace(/,/g, "");
  if (/^-?\d+(\.\d+)?$/.test(num)) return parseFloat(num);
  return null;   // not numeric -> string compare
}
function sortByColumn(th) {
  const tbl = th.closest("table"); const tbody = tbl && tbl.tBodies[0]; if (!tbody) return;
  const i = +th.dataset.i;
  const dir = th.getAttribute("data-dir") === "asc" ? "desc" : "asc";
  tbl.querySelectorAll("th.sortable").forEach((h) => { h.removeAttribute("data-dir"); const s = h.querySelector(".sort-ind"); if (s) s.textContent = ""; });
  th.setAttribute("data-dir", dir);
  const ind = th.querySelector(".sort-ind"); if (ind) ind.textContent = dir === "asc" ? " ▲" : " ▼";
  Array.from(tbody.rows).sort((ra, rb) => {
    const ta = ra.cells[i] ? ra.cells[i].textContent : "", tb = rb.cells[i] ? rb.cells[i].textContent : "";
    const va = parseSortVal(ta), vb = parseSortVal(tb);
    const c = (va !== null && vb !== null) ? va - vb : String(ta).localeCompare(String(tb), undefined, { numeric: true });
    return dir === "asc" ? c : -c;
  }).forEach((r) => tbody.appendChild(r));
}
const td = (v) => `<td>${v == null ? "" : v}</td>`;
const tdn = (v) => `<td class="num">${v == null ? "" : v}</td>`;

function drawGraph(container, legend, nodes, edges, legendHtml) {
  legend.innerHTML = legendHtml;
  if (!nodes.length) { container.innerHTML = `<p class="muted">노드가 없습니다.</p>`; return; }
  const W = 860, H = 580, cx = W / 2, cy = H / 2, R = Math.max(120, Math.min(cx, cy) - 110);
  const maxW = Math.max(1, ...nodes.map((n) => n.weight || 0));
  const maxE = Math.max(1, ...edges.map((e) => e.weight || 0));
  const pos = {};
  nodes.forEach((n, i) => {
    const a = -Math.PI / 2 + (2 * Math.PI * i) / nodes.length;
    pos[n.id] = { x: cx + R * Math.cos(a), y: cy + R * Math.sin(a) };
  });
  let e = "";
  edges.forEach((ed) => {
    const A = pos[ed.a], B = pos[ed.b]; if (!A || !B) return;
    const w = 1.2 + 4 * Math.sqrt((ed.weight || 0) / maxE);
    const mx = (A.x + B.x) / 2, my = (A.y + B.y) / 2;
    e += `<line class="edge${ed.kind === "relay" ? " relay" : ""}" x1="${A.x.toFixed(1)}" y1="${A.y.toFixed(1)}" x2="${B.x.toFixed(1)}" y2="${B.y.toFixed(1)}" stroke-width="${w.toFixed(2)}"><title>${esc(ed.title || "")}</title></line>`;
    if (ed.label) e += `<text class="edge-label" x="${mx.toFixed(1)}" y="${(my - 3).toFixed(1)}" text-anchor="middle">${esc(ed.label)}</text>`;
  });
  let g = "";
  nodes.forEach((n) => {
    const P = pos[n.id], r = 18 + 16 * Math.sqrt((n.weight || 0) / maxW);
    const cls = "node" + (n.kind === "secondary" ? " peer" : "") + (n.kind === "relay" ? " relay" : "");
    const sub = n.sublabel ? `<text class="sub" x="${P.x.toFixed(1)}" y="${(P.y + r + 12).toFixed(1)}">${esc(n.sublabel)}</text>` : "";
    g += `<g class="${cls}"><title>${esc(n.title || n.label)}</title><circle cx="${P.x.toFixed(1)}" cy="${P.y.toFixed(1)}" r="${r.toFixed(1)}"></circle><text x="${P.x.toFixed(1)}" y="${(P.y + 4).toFixed(1)}">${esc(n.label)}</text>${sub}</g>`;
  });
  container.innerHTML = `<svg viewBox="0 0 ${W} ${H}" role="img"><g>${e}</g><g>${g}</g></svg>`;
}

// ---- FLOW (tshark CSV) rendering ------------------------------------------
function renderFlow(json) {
  const d = json.data, m = d.meta;
  els.overview.innerHTML = [
    card("패킷", num(m.packets)), card("바이트", fmtBytes(m.bytes)),
    card("호스트", m.hosts), card("통신쌍", m.conversations),
    card("서비스", m.services),
  ].join("");

  // 수집상태
  const sources = (m.stats && m.stats.sources) || [];
  let st = `<div class="section-title">수집 파일별 현황</div>` +
    table(["파일", "인식 패킷"], sources.map((s) => [td(`<code>${esc(s.name)}</code>`), tdn(num(s.records))]));
  st += `<div class="section-title" style="margin-top:18px">프로토콜 분포</div>` +
    table(["프로토콜", "패킷", "바이트"], d.protocols.map((p) => [td(esc(p.proto)), tdn(num(p.packets)), tdn(fmtBytes(p.bytes))]));
  const span = (m.first_seen && m.first_seen !== "-") ? `${esc(m.first_seen)} ~ ${esc(m.last_seen)} (${m.duration_seconds}s)` : "타임스탬프 없음(--no-time)";
  st += `<div class="section-title" style="margin-top:18px">수집 요약</div>
    <table class="grid"><tbody>
      <tr><th>관측 기간</th><td>${span}</td></tr>
      <tr><th>총 패킷 / 바이트</th><td>${num(m.packets)} / ${fmtBytes(m.bytes)}</td></tr>
      <tr><th>호스트 / 통신쌍 / 서비스</th><td>${m.hosts} / ${m.conversations} / ${m.services}</td></tr>
    </tbody></table>`;
  if (json.fromReport) st += `<div class="notice">사전 집계된 report.json을 로드했습니다 (스트리밍 CLI 처리 결과).</div>`;
  $("#tab-status").innerHTML = st;

  // 호스트 정보
  const roleBadge = (r) => `<span class="badge ${r === "server" ? "direct" : r === "both" ? "relay" : r === "client" ? "indirect" : "no"}">${esc(r)}</span>`;
  $("#tab-hosts").innerHTML = `<div class="section-title">호스트 정보 (물리주소 = NSX 터널/정책 엔드포인트)</div>` +
    table(["IP", "서브넷", "역할", "제공 서비스", "피어", "송신", "수신", "합계"],
      d.hosts.map((h) => [
        td(`<strong>${esc(h.ip)}</strong>`), td(`<span class="mono">${esc(h.subnet)}</span>`),
        td(roleBadge(h.role)),
        td(`<span class="mono">${esc(h.services_offered.map((s) => s.label).join(", ") || "-")}</span>`),
        tdn(h.peer_count), tdn(fmtBytes(h.sent_bytes)), tdn(fmtBytes(h.recv_bytes)), tdn(fmtBytes(h.total_bytes)),
      ]));

  // 통신쌍 (A<->B 중복 제거)
  $("#tab-conv").innerHTML = `<div class="section-title">통신쌍 — A→B와 B→A를 하나로 합산 (중복 제거) · A/B 헤더 클릭으로 정렬</div>` +
    table(["A", "B", "패킷", "바이트", "A→B", "B→A", "서비스", "기간(s)"],
      d.conversations.map((c) => [
        td(`<strong>${esc(c.a)}</strong>`),
        td(`<strong>${esc(c.b)}</strong>`),
        tdn(num(c.packets)), tdn(fmtBytes(c.bytes)),
        tdn(`${num(c.a_to_b_packets)} / ${fmtBytes(c.a_to_b_bytes)}`),
        tdn(`${num(c.b_to_a_packets)} / ${fmtBytes(c.b_to_a_bytes)}`),
        td(`<span class="mono">${esc(c.services.map((s) => s.label).join(", ") || "-")}</span>`),
        tdn(c.duration_seconds),
      ])) +
    `<div class="notice">한 패킷의 양방향(A→B, B→A)을 같은 통신쌍으로 합산합니다. NSX에서는 보통 한 쌍이 하나의 양방향 허용 정책이 됩니다.</div>`;

  // 수집된 정책 (서비스 기반)
  const basisBadge = (b) => b === "handshake"
    ? `<span class="badge direct">handshake</span>`
    : `<span class="badge indirect">port-range</span>`;
  $("#tab-policies").innerHTML = `<div class="section-title">수집된 정책 — 관측 서비스를 NSX 허용 규칙으로 변환</div>` +
    table(["정책명", "서비스", "판정", "서버(목적지)", "출발 서브넷", "#클라이언트", "패킷", "바이트", "근거"],
      d.services.map((s) => [
        td(`<code>${esc(s.name)}</code>`),
        td(`<span class="badge direct">${esc(s.service)}</span>`),
        td(basisBadge(s.basis)),
        td(`<strong>${esc(s.server)}</strong>`),
        td(`<span class="mono">${esc(s.source_subnets.join(", "))}</span>`),
        tdn(s.client_count), tdn(num(s.packets)), tdn(fmtBytes(s.bytes)),
        td(`<span class="muted" title="${esc(s.clients.join(', '))}">${esc(s.evidence)}</span>`),
      ])) +
    `<div class="notice">판정: <b>handshake</b> = TCP 3-way 핸드셰이크(SYN) 관측으로 서버 방향을 사실 확정.
      <b>port-range</b> = IANA RFC 6335 포트 범위 기반 추정(플래그 미관측). 판정 불가 시 정책으로 만들지 않습니다(추측 배제).</div>`;

  // 라우팅 (서브넷 매트릭스)
  $("#tab-routing").innerHTML = `<div class="section-title">서브넷 간 매트릭스 (그룹 단위 NSX 정책)</div>` +
    table(["서브넷 쌍", "패킷", "바이트", "호스트쌍", "서비스"],
      d.subnet_matrix.map((s) => [
        td(`<span class="mono">${esc(s.a)} ⟷ ${esc(s.b)}</span>`),
        tdn(num(s.packets)), tdn(fmtBytes(s.bytes)), tdn(s.host_pairs),
        td(`<span class="mono">${esc(s.services.map((x) => x.label).join(", ") || "-")}</span>`),
      ])) +
    `<div class="notice">단일 지점 캡처에는 중계/홉 정보가 없으므로, 라우팅은 서브넷 간 통신 관계로 표현합니다. NSX에서 IP Set(그룹) 간 정책의 근거가 됩니다.</div>`;

  // 토폴로지
  const nodes = d.hosts.map((h) => ({
    id: h.ip, label: h.ip, sublabel: h.services_offered[0] ? h.services_offered[0].label : h.subnet,
    kind: h.role === "client" ? "secondary" : (h.role === "both" ? "relay" : "primary"),
    weight: h.total_bytes, title: `${h.ip}\n역할 ${h.role}\n서비스 ${h.services_offered.map((s) => s.label).join(",") || "-"}\n송신 ${fmtBytes(h.sent_bytes)} / 수신 ${fmtBytes(h.recv_bytes)}`,
  }));
  const edges = d.conversations.map((c) => ({
    a: c.a, b: c.b, weight: c.bytes, label: c.services.map((s) => s.label).join(",") || fmtBytes(c.bytes),
    kind: "direct", title: `${c.a} ⟷ ${c.b}: ${num(c.packets)}패킷 / ${fmtBytes(c.bytes)}`,
  }));
  drawGraph($("#graph"), $("#graphLegend"), nodes, edges,
    `<span><i class="sw solid"></i> 통신</span>
     <span><i class="sw node-log"></i> 서버(서비스 제공)</span>
     <span><i class="sw node-peer"></i> 클라이언트</span>`);

  renderSubnet(d);
  renderActivity(d);
}

// ---- 서브넷별 IP + IP 드릴다운 (어떤 서버와 통신하는지) ---------------------
function peersOf(d, ip) {
  // returns [{peer, packets, bytes, services:[label], role}]
  const out = {};
  d.conversations.forEach((c) => {
    let peer = null;
    if (c.a === ip) peer = c.b; else if (c.b === ip) peer = c.a; else return;
    out[peer] = { peer, packets: c.packets, bytes: c.bytes,
      services: c.services.map((s) => s.label) };
  });
  // mark which side is the server, from services
  d.services.forEach((s) => {
    if (s.server === ip) { (s.clients || []).forEach((cl) => { if (out[cl]) out[cl].role = "client→this(server)"; }); }
    else if ((s.clients || []).includes(ip)) { if (out[s.server]) out[s.server].role = "this→" + s.server + "(server)"; }
  });
  return Object.values(out).sort((x, y) => y.bytes - x.bytes);
}
function renderSubnet(d) {
  const bySubnet = {};
  d.hosts.forEach((h) => { (bySubnet[h.subnet] = bySubnet[h.subnet] || []).push(h); });
  const subnets = Object.keys(bySubnet).sort();
  const left = subnets.map((sn) => {
    const chips = bySubnet[sn].sort((a, b) => b.total_bytes - a.total_bytes).map((h) =>
      `<span class="ip-chip ${h.role === "server" || h.role === "both" ? "server" : ""}" data-ip="${esc(h.ip)}">${esc(h.ip)}</span>`).join("");
    return `<div class="subnet-box"><h4>${esc(sn)} <span class="muted">(${bySubnet[sn].length})</span></h4>${chips}</div>`;
  }).join("");
  $("#tab-subnet").innerHTML =
    `<div class="section-title">서브넷별 통신 IP — IP를 클릭하면 통신 상대(서버)를 조회합니다</div>
     <div class="subnet-grid"><div>${left}</div><div class="ip-detail" id="ipDetail">
       <p class="muted">IP를 클릭하세요.</p></div></div>`;
  $("#tab-subnet").querySelectorAll(".ip-chip").forEach((ch) => ch.addEventListener("click", () => {
    $("#tab-subnet").querySelectorAll(".ip-chip").forEach((x) => x.classList.remove("sel"));
    ch.classList.add("sel");
    showIp(d, ch.dataset.ip);
  }));
  // Keep the selected IP detail visible across periodic re-renders (live poll).
  if (state.selectedIp && d.hosts.some((h) => h.ip === state.selectedIp)) {
    const ch = $("#tab-subnet").querySelector('.ip-chip[data-ip="' + state.selectedIp + '"]');
    if (ch) ch.classList.add("sel");
    showIp(d, state.selectedIp);
  }
}
function showIp(d, ip) {
  state.selectedIp = ip;
  const host = d.hosts.find((h) => h.ip === ip) || {};
  const peers = peersOf(d, ip);
  const offered = (host.services_offered || []).map((s) => s.label).join(", ") || "-";
  const rows = peers.map((p) => [
    td(`<strong>${esc(p.peer)}</strong>`),
    td(`<span class="mono">${esc((p.services || []).join(", ") || "-")}</span>`),
    td(esc(p.role || "-")),
    tdn(num(p.packets)), tdn(fmtBytes(p.bytes)),
  ]);
  $("#ipDetail").innerHTML =
    `<div class="section-title">${esc(ip)} <span class="muted">(${esc(host.subnet || "")}, 역할 ${esc(host.role || "-")})</span></div>
     <div class="notice" style="margin:0 0 10px">제공 서비스: <span class="mono">${esc(offered)}</span> · 피어 ${peers.length}개</div>
     ${table(["통신 상대", "서비스", "방향(서버)", "패킷", "바이트"], rows)}`;
}

// ---- 활동/유휴 시간대 (마이그레이션 창) -----------------------------------
function renderActivity(d) {
  const act = d.activity;
  if (!act || !act.hosts.length) { $("#tab-activity").innerHTML = `<p class="muted">타임스탬프가 없어 활동 분석을 할 수 없습니다(--no-time).</p>`; return; }
  const wd = act.weekdays;
  const top = act.hosts.slice(0, 12);
  let maxv = 1; top.forEach((h) => h.week.forEach((v) => { if (v > maxv) maxv = v; }));
  const blocks = top.map((h) => {
    let grid = `<table class="heat"><tr><th></th>${Array.from({ length: 24 }, (_, i) => `<th>${i}</th>`).join("")}</tr>`;
    for (let day = 0; day < 7; day++) {
      grid += `<tr><th>${wd[day]}</th>`;
      for (let hr = 0; hr < 24; hr++) {
        const v = h.week[day * 24 + hr] || 0;
        const a = v ? (0.15 + 0.85 * Math.sqrt(v / maxv)).toFixed(2) : 0;
        const bg = v ? `background:rgba(79,70,229,${a})` : "";
        grid += `<td class="cell" style="${bg}" title="${wd[day]} ${hr}:00 — ${num(v)}p"></td>`;
      }
      grid += `</tr>`;
    }
    grid += `</table>`;
    const idle = (h.idle_windows || []).map((w) =>
      `<span class="idle-tag">${wd[w.weekday]} ${String(w.start_hour).padStart(2, "0")}:00–${String(w.end_hour).padStart(2, "0")}:59</span>`).join("") || "<span class='muted'>유휴 구간 없음(항상 활성)</span>";
    return `<div class="subnet-box" style="margin-bottom:14px">
      <h4>${esc(h.ip)} <span class="muted">(${esc(h.subnet)}, 활성 ${h.active_hours}시간/주, ${num(h.total_packets)}p)</span></h4>
      <div class="heatwrap">${grid}</div>
      <div style="margin-top:8px"><b>마이그레이션 가능 유휴 창</b>(네트워크는 활성인데 이 IP는 무통신): ${idle}</div></div>`;
  }).join("");
  $("#tab-activity").innerHTML =
    `<div class="section-title">피어별 활동 시간대(주중×시간) · 유휴 시간 = 안전한 마이그레이션 창</div>
     <div class="notice" style="margin-top:0">색이 진할수록 트래픽이 많은 시간대입니다. 충분한 기간(≥1주) 캡처할수록 패턴이 정확합니다.</div>${blocks}`;
}

// ---- TINC log rendering ---------------------------------------------------
function renderTinc(json) {
  const d = json.data;
  const logged = d.nodes.filter((n) => n.has_log).length;
  const relayed = d.communication_pairs.filter((p) => p.via.length || p.forwarded_packets).length;
  els.overview.innerHTML = [
    card("노드", d.nodes.length, `로그 ${logged}`), card("정책(통신쌍)", d.communication_pairs.length),
    card("라우팅(중계)", relayed), card("서브넷", Object.keys(d.subnets).length), card("플로우", d.flows.length),
  ].join("");

  const sources = (d.meta.stats && d.meta.stats.sources) || [];
  const peerOnly = d.nodes.filter((n) => !n.has_log).map((n) => n.name);
  const span = (d.meta.first_seen && d.meta.first_seen !== "-") ? `${esc(d.meta.first_seen)} ~ ${esc(d.meta.last_seen)}` : "타임스탬프 없음";
  let st = `<div class="section-title">수집 파일별 현황</div>` +
    table(["파일", "노드", "라인", "인식 이벤트"], sources.map((s) => [td(`<code>${esc(s.name)}</code>`), td(esc(s.node || "-")), tdn(num(s.lines)), tdn(num(s.events))]));
  st += `<div class="section-title" style="margin-top:18px">수집 요약</div>
    <table class="grid"><tbody>
      <tr><th>관측 기간</th><td>${span}</td></tr>
      <tr><th>로그 수집 노드</th><td>${logged} / ${d.nodes.length}</td></tr>
      <tr><th>피어로만 관측</th><td>${peerOnly.length ? esc(peerOnly.join(", ")) : "<span class='muted'>없음</span>"}</td></tr>
    </tbody></table>`;
  if (d.meta.events_without_local) st += `<div class="notice">패킷 ${d.meta.events_without_local}건은 기록 노드를 식별하지 못했습니다. 파일 목록에서 노드명을 지정하세요.</div>`;
  $("#tab-status").innerHTML = st;

  $("#tab-hosts").innerHTML = `<div class="section-title">호스트/노드 정보 (물리주소 = NSX 터널 엔드포인트)</div>` +
    table(["노드", "수집", "물리주소", "소유 서브넷", "피어", "송신", "수신"],
      d.nodes.map((n) => [
        td(`<strong>${esc(n.name)}</strong>`),
        td(n.has_log ? `<span class="badge yes">수집됨</span>` : `<span class="badge no">피어관측</span>`),
        td(`<span class="mono">${esc(n.real_addresses.join(", ") || "-")}</span>`),
        td(`<span class="mono">${esc(n.subnets.join(", ") || "-")}</span>`),
        tdn(n.peers.length), tdn(fmtBytes(n.sent_bytes)), tdn(fmtBytes(n.recv_bytes)),
      ]));

  const pairBadge = (p) => p.direct_link && !p.via.length ? `<span class="badge direct">직접</span>`
    : p.via.length ? `<span class="badge relay">중계 via ${esc(p.via.join(", "))}</span>` : `<span class="badge indirect">간접</span>`;
  $("#tab-conv").innerHTML = `<div class="section-title">통신쌍 (A↔B 중복 제거) · A/B 헤더 클릭으로 정렬</div>` +
    table(["A", "B", "패킷", "바이트", "경로", "방향수"],
      d.communication_pairs.map((p) => [
        td(`<strong>${esc(p.a)}</strong>`),
        td(`<strong>${esc(p.b)}</strong>`),
        tdn(num(p.packets)), tdn(fmtBytes(p.bytes)), td(pairBadge(p)), tdn(p.directions.length),
      ]));

  $("#tab-policies").innerHTML = `<div class="section-title">수집된 정책 (NSX 허용 규칙 후보)</div>` +
    table(["정책명", "연결", "A 서브넷", "B 서브넷", "동작", "패킷", "바이트"],
      (d.policies || []).map((p) => [
        td(`<code>${esc(p.name)}</code>`), td(`${esc(p.a)} ⟷ ${esc(p.b)}`),
        td(`<span class="mono">${esc(p.a_subnets.join(", ") || "-")}</span>`),
        td(`<span class="mono">${esc(p.b_subnets.join(", ") || "-")}</span>`),
        td(`<span class="badge yes">${esc(p.action)}</span>`), tdn(num(p.packets)), tdn(fmtBytes(p.bytes)),
      ]));

  const directSet = new Set((d.direct_links || []).map((p) => p.slice().sort().join("|")));
  const routed = d.flows.filter((f) => f.via.length || f.forwarded_packets);
  let rt = `<div class="section-title">라우팅 / 중계 경로</div>`;
  rt += routed.length ? table(["경로", "패킷", "비고"], routed.map((f) => {
    const noTunnel = !directSet.has([f.src, f.dst].sort().join("|"));
    return [td(`<span class="mono">${esc(f.src)} → ${esc(f.via.join("/") || "?")} → ${esc(f.dst)}</span>`),
      tdn(f.forwarded_packets || f.packets),
      td(noTunnel ? `<span class="badge indirect">직접 터널 없음</span>` : `<span class="badge direct">직접 터널 있음</span>`)];
  })) : `<p class="muted">중계(멀티홉) 트래픽이 없습니다 — 모두 직접 연결입니다.</p>`;
  $("#tab-routing").innerHTML = rt;

  const relaySet = new Set(Object.keys(d.relays || {}));
  const nodes = d.nodes.map((n) => ({
    id: n.name, label: n.name, sublabel: n.subnets[0] || "",
    kind: !n.has_log ? "secondary" : (relaySet.has(n.name) ? "relay" : "primary"),
    weight: n.sent_bytes + n.recv_bytes,
    title: `${n.name}\n물리 ${n.real_addresses.join(",") || "-"}\n서브넷 ${n.subnets.join(",") || "-"}`,
  }));
  const edges = d.flows.filter((f) => f.packets || f.forwarded_packets).map((f) => ({
    a: f.src, b: f.dst, weight: f.bytes, label: `${f.packets}p`,
    kind: f.via.length ? "relay" : "direct", title: `${f.src}→${f.dst}: ${f.packets}p`,
  }));
  drawGraph($("#graph"), $("#graphLegend"), nodes, edges,
    `<span><i class="sw solid"></i> 직접</span><span><i class="sw dashed"></i> 중계</span>
     <span><i class="sw node-log"></i> 로그 수집</span><span><i class="sw node-peer"></i> 피어관측</span>`);
  $("#tab-subnet").innerHTML = `<p class="muted">서브넷/IP 보기는 패킷 캡처(CSV) 분석에서 제공됩니다.</p>`;
  $("#tab-activity").innerHTML = `<p class="muted">활동/유휴 분석은 패킷 캡처(CSV) 분석에서 제공됩니다.</p>`;
}

// ---- full-screen topology --------------------------------------------------
function currentGraph() {
  const json = state.result; if (!json) return null;
  const d = json.data;
  if (json.mode === "flow") {
    return {
      title: "flow topology",
      nodes: d.hosts.map((h) => ({ id: h.ip, label: h.ip,
        sub: h.services_offered[0] ? h.services_offered[0].label : h.subnet,
        kind: h.role === "client" ? "secondary" : (h.role === "both" ? "relay" : "primary"),
        weight: h.total_bytes })),
      edges: d.conversations.map((c) => ({ a: c.a, b: c.b, weight: c.bytes,
        label: c.services.map((s) => s.label).join(",") || "", kind: "direct" })),
    };
  }
  const relaySet = new Set(Object.keys(d.relays || {}));
  return {
    title: "tinc topology",
    nodes: d.nodes.map((n) => ({ id: n.name, label: n.name, sub: n.subnets[0] || "",
      kind: !n.has_log ? "secondary" : (relaySet.has(n.name) ? "relay" : "primary"),
      weight: n.sent_bytes + n.recv_bytes })),
    edges: d.flows.filter((f) => f.packets || f.forwarded_packets).map((f) => ({
      a: f.src, b: f.dst, weight: f.bytes, label: `${f.packets}p`, kind: f.via.length ? "relay" : "direct" })),
  };
}
async function openFullTopo() {
  const g = currentGraph();
  if (!g) { setMsg("먼저 분석을 실행하세요.", "err"); return; }
  try {
    await fetch("/api/last", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: g }) });
    window.open("/static/topology.html", "_blank");
  } catch (e) { setMsg("토폴로지 열기 실패: " + e, "err"); }
}

// ---- system / storage dashboard -------------------------------------------
async function loadPersistConfig() {
  try {
    const j = await (await fetch("/api/persist/config")).json();
    const c = j.config || {};
    $("#saveDir").value = c.save_dir || "";
    $("#persMinute").checked = !!c.minute; $("#persHour").checked = !!c.hour;
    $("#persDay").checked = !!c.day; $("#persRetention").value = c.retention || 0;
    $("#persCompress").checked = !!c.compress;
  } catch (e) { /* ignore */ }
}
async function applyPersist() {
  const body = { save_dir: $("#saveDir").value, minute: $("#persMinute").checked,
    hour: $("#persHour").checked, day: $("#persDay").checked,
    retention: Number($("#persRetention").value) || 0,
    compress: $("#persCompress").checked };
  const el = $("#persistMsg");
  try {
    const j = await (await fetch("/api/persist/config", { method: "POST",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })).json();
    if (j.ok) { el.textContent = "저장됨: " + j.config.save_dir; el.className = "msg ok"; }
    else { el.textContent = j.error || "실패"; el.className = "msg err"; }
  } catch (e) { el.textContent = "요청 실패: " + e; el.className = "msg err"; }
}
function gauge(pct, label) {
  const cls = pct >= 90 ? "danger" : (pct >= 70 ? "warn" : "");
  return `<div class="gauge ${cls}"><span style="width:${Math.min(100, pct)}%"></span></div><div class="muted" style="font-size:11px;margin-top:3px">${esc(label)}</div>`;
}
async function pollSys() {
  let j;
  try { j = await (await fetch("/api/sysstatus")).json(); } catch (e) { return; }
  if (!j || !j.ok) return;
  const s = j.system, disk = s.disk, saved = s.saved, cap = j.capture || {};
  const memMB = s.rss_bytes / 1048576, peakMB = s.peak_rss_bytes / 1048576;
  $("#sysCards").innerHTML = [
    card("프로세스 CPU", s.cpu_percent + "<small>%</small>") .replace("</div></div>", gauge(s.cpu_percent, "포탈 프로세스") + "</div></div>"),
    card("메모리(RSS)", memMB.toFixed(0) + "<small>MB</small>", "peak " + peakMB.toFixed(0) + "MB"),
    card("디스크 여유", fmtBytes(disk.free), "/ " + fmtBytes(disk.total))
      .replace("</div></div>", gauge(disk.percent_used, esc(disk.path) + " 사용 " + disk.percent_used + "%") + "</div></div>"),
    card("저장 파일", saved.count, fmtBytes(saved.bytes)),
    card("라이브 캡처", cap.running ? "ON" : "off", cap.running ? num(cap.packets) + "p" : ""),
  ].join("");
  const last = j.persist && j.persist.last || {};
  state.saveDir = saved.dir || "";
  state.lastSaved = `마지막 저장 — 분: ${esc(last.minute || "-")} · 시: ${esc(last.hour || "-")} · 일: ${esc(last.day || "-")}`;
  loadSavedFiles();
}

// ---- saved file browser (click filename -> first 100 lines, save verify) ---
async function loadSavedFiles() {
  let files = [];
  try { const j = await (await fetch("/api/persist/files")).json(); if (j.ok) files = j.files; } catch (e) { return; }
  const rows = files.map((f) =>
    `<tr><td><span class="filename-link" data-f="${esc(f.name)}">${esc(f.name)}</span></td>`
    + `<td class="num">${fmtBytes(f.bytes)}</td><td>${esc(f.mtime)}</td></tr>`).join("");
  $("#savedFiles").innerHTML =
    `<div class="section-title" style="margin-top:14px">저장 파일 <span class="muted">(${esc(state.saveDir || "")}) · ${files.length}개 · 파일명 클릭 = 첫 100줄 확인</span></div>`
    + `<div class="muted" style="font-size:12px;margin-bottom:6px">${state.lastSaved || ""}</div>`
    + (files.length ? `<table class="grid"><thead><tr><th>파일</th><th>용량</th><th>시각</th></tr></thead><tbody>${rows}</tbody></table>`
                    : `<p class="muted">아직 저장된 스냅샷이 없습니다(설정에서 분/시/일 저장을 켜고 라이브 캡처를 실행하세요).</p>`);
  $("#savedFiles").querySelectorAll(".filename-link").forEach((el) =>
    el.addEventListener("click", () => previewFile(el.dataset.f)));
}
async function previewFile(name) {
  const pre = $("#filePreview");
  pre.classList.remove("hidden");
  pre.textContent = name + " 불러오는 중…";
  try {
    const j = await (await fetch("/api/persist/file?name=" + encodeURIComponent(name) + "&lines=100")).json();
    if (!j.ok) { pre.textContent = "읽기 실패: " + (j.error || ""); return; }
    pre.textContent = "// " + name + "  (첫 " + j.lines.length + "줄)\n" + j.lines.join("\n");
  } catch (e) { pre.textContent = "요청 실패: " + e; }
}

// ---- settings menu (snapshot / capture exclude / auto-update) -------------
function toggleSettings(show) {
  const s = $("#settings");
  const open = (show === undefined) ? s.classList.contains("hidden") : show;
  s.classList.toggle("hidden", !open);
  if (open) { loadCaptureCfg(); loadUpdateCfg(); window.scrollTo({ top: 0, behavior: "smooth" }); }
}
async function loadCaptureCfg() {
  try { const j = await (await fetch("/api/capture/config")).json();
    $("#captureExclude").value = (j.exclude || []).join("\n");
    $("#captureResume").checked = (j.resume !== false); } catch (e) { /* */ }
}
async function applyCaptureCfg() {
  const list = $("#captureExclude").value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  const el = $("#captureMsg");
  try {
    const j = await (await fetch("/api/capture/config", { method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ exclude: list, resume: $("#captureResume").checked }) })).json();
    if (j.ok) { el.textContent = "저장됨 · 필터: " + (j.filter || "(없음)") + " · 다음 캡처부터 적용"; el.className = "msg ok"; }
    else { el.textContent = j.error || "실패"; el.className = "msg err"; }
  } catch (e) { el.textContent = "요청 실패: " + e; el.className = "msg err"; }
}
async function loadUpdateCfg() {
  try {
    const c = (await (await fetch("/api/update/config")).json()).config || {};
    $("#updEnabled").checked = !!c.enabled; $("#updWatchDir").value = c.watch_dir || "";
    $("#updRemoteBase").value = c.remote_base || ""; $("#updAutoApply").checked = !!c.auto_apply;
    $("#updAutoRestart").checked = !!c.auto_restart;
    $("#updToken").placeholder = c.has_token ? "설정됨 (변경 시에만 입력)" : "토큰 없음";
  } catch (e) { /* */ }
  renderUpdateStatus();
}
async function applyUpdateCfg() {
  const body = { enabled: $("#updEnabled").checked, watch_dir: $("#updWatchDir").value,
    remote_base: $("#updRemoteBase").value, auto_apply: $("#updAutoApply").checked,
    auto_restart: $("#updAutoRestart").checked };
  const t = $("#updToken").value.trim(); if (t) body.token = t;
  const el = $("#updMsg");
  try {
    const j = await (await fetch("/api/update/config", { method: "POST",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })).json();
    el.textContent = j.ok ? "설정 저장됨" : "실패"; el.className = "msg " + (j.ok ? "ok" : "err");
    $("#updToken").value = ""; renderUpdateStatus();
  } catch (e) { el.textContent = "요청 실패: " + e; el.className = "msg err"; }
}
async function checkUpdate() {
  const el = $("#updMsg"); el.textContent = "확인 중…"; el.className = "msg";
  try {
    const j = await (await fetch("/api/update/check", { method: "POST" })).json();
    if (!j.ok) el.textContent = "확인 실패";
    else if (j.available) {
      el.textContent = "⬆ 새 버전 있음"
        + (j.local ? " (로컬 " + j.local.version + ")" : "")
        + (j.remote && j.remote.latest ? " (원격 " + j.remote.latest + ")" : "");
      el.className = "msg ok"; return;
    } else el.textContent = "이미 최신입니다 (현재 " + j.current + ")";
  } catch (e) { el.textContent = "요청 실패: " + e; el.className = "msg err"; }
  renderUpdateStatus();
}
async function applyUpdate() {
  if (!window.confirm("새 버전을 적용할까요? 적용 후 '재시작'으로 반영됩니다.")) return;
  const el = $("#updMsg"); el.textContent = "적용 중…"; el.className = "msg";
  try {
    const j = await (await fetch("/api/update/apply", { method: "POST" })).json();
    if (j.ok) { el.textContent = "적용됨: " + (j.from || "") + " → " + (j.version || "") + " · '재시작'을 누르세요"; el.className = "msg ok"; }
    else { el.textContent = j.reason || "적용 실패"; el.className = "msg err"; }
  } catch (e) { el.textContent = "요청 실패: " + e; el.className = "msg err"; }
}
async function restartUpdate() {
  if (!window.confirm("서버를 재시작할까요? 진행 중인 캡처가 중단됩니다.")) return;
  $("#updMsg").textContent = "재시작 요청됨 — 잠시 후 페이지를 새로고침하세요."; $("#updMsg").className = "msg";
  try { await fetch("/api/update/restart", { method: "POST" }); } catch (e) { /* expected */ }
}
async function renderUpdateStatus() {
  try {
    const j = await (await fetch("/api/update/status")).json();
    const c = j.config || {};
    $("#updStatus").textContent = "현재 v" + (j.current || "?")
      + (c.enabled ? (c.auto_apply && c.auto_restart ? " · 무인 업데이트 ON" : " · 자동확인 ON") : " · OFF")
      + (j.latest ? " · 최신 " + j.latest : "")
      + (j.available ? " · ⬆ 업데이트 가능" : "")
      + (j.pending_restart ? " · 적용됨(재시작 대기)" : "")
      + (j.error ? " · " + j.error : "");
  } catch (e) { /* */ }
}

// ---- exports --------------------------------------------------------------
function setupExports(mode, json) {
  const data = json.data, ex = json.exports || {};
  if (mode === "live") {
    const go = (fmt) => () => { window.location.href = "/api/live/export?fmt=" + fmt; };
    [["btnJson", "JSON", go("json")], ["btnFlowsCsv", "통신쌍 CSV", go("conversations")],
     ["btnPoliciesCsv", "정책 CSV", go("policies")], ["btnSummary", "호스트 CSV", go("hosts")],
     ["btnDot", "DOT", go("dot")]].forEach(([id, label, fn]) => {
      const b = $("#" + id); if (b) { b.textContent = label; b.onclick = fn; }
    });
    return;
  }
  const conf = mode === "flow" ? [
    ["btnJson", "JSON", () => download("flow_report.json", JSON.stringify(data, null, 2), "application/json")],
    ["btnFlowsCsv", "통신쌍 CSV", () => download("conversations.csv", ex.conversations_csv, "text/csv")],
    ["btnPoliciesCsv", "정책 CSV", () => download("policies.csv", ex.policies_csv, "text/csv")],
    ["btnSummary", "호스트 CSV", () => download("hosts.csv", ex.hosts_csv, "text/csv")],
    ["btnDot", "DOT", () => download("topology.dot", ex.dot, "text/vnd.graphviz")],
  ] : [
    ["btnJson", "JSON", () => download("tinc_report.json", JSON.stringify(data, null, 2), "application/json")],
    ["btnFlowsCsv", "Flows CSV", () => download("tinc_flows.csv", ex.flows_csv, "text/csv")],
    ["btnPoliciesCsv", "정책 CSV", () => download("tinc_policies.csv", ex.policies_csv, "text/csv")],
    ["btnSummary", "요약 TXT", () => download("summary.txt", json.summaryText || "", "text/plain")],
    ["btnDot", "DOT", () => download("tinc_topology.dot", ex.dot, "text/vnd.graphviz")],
  ];
  conf.forEach(([id, label, fn]) => {
    const b = $("#" + id); if (!b) return;
    b.textContent = label; b.onclick = fn;
  });
}

// ---- wiring ---------------------------------------------------------------
function bindTabs() {
  document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
    document.querySelectorAll(".tabpanel").forEach((x) => x.classList.remove("active"));
    t.classList.add("active"); $("#tab-" + t.dataset.tab).classList.add("active");
  }));
}
function init() {
  els.drop.addEventListener("click", () => els.input.click());
  els.input.addEventListener("change", (e) => { addFiles(e.target.files); e.target.value = ""; });
  ["dragenter", "dragover"].forEach((ev) => els.drop.addEventListener(ev, (e) => { e.preventDefault(); els.drop.classList.add("drag"); }));
  ["dragleave", "drop"].forEach((ev) => els.drop.addEventListener(ev, (e) => { e.preventDefault(); els.drop.classList.remove("drag"); }));
  els.drop.addEventListener("drop", (e) => { if (e.dataTransfer) addFiles(e.dataTransfer.files); });
  $("#btnAnalyze").addEventListener("click", analyze);
  $("#btnSample").addEventListener("click", loadSample);
  $("#btnClear").addEventListener("click", clearAll);
  $("#btnLiveStart").addEventListener("click", startLive);
  $("#btnLiveStop").addEventListener("click", stopLive);
  $("#btnLiveStopBar").addEventListener("click", stopLive);
  $("#btnFullTopo").addEventListener("click", openFullTopo);
  $("#btnPersistApply").addEventListener("click", applyPersist);
  $("#btnSettings").addEventListener("click", () => toggleSettings());
  $("#btnSettingsClose").addEventListener("click", () => toggleSettings(false));
  $("#btnCaptureApply").addEventListener("click", applyCaptureCfg);
  $("#btnUpdSave").addEventListener("click", applyUpdateCfg);
  $("#btnUpdCheck").addEventListener("click", checkUpdate);
  $("#btnUpdApply").addEventListener("click", applyUpdate);
  $("#btnUpdRestart").addEventListener("click", restartUpdate);
  bindTabs();
  document.addEventListener("click", (e) => {
    const th = e.target.closest && e.target.closest("th.sortable");
    if (th) sortByColumn(th);
  });
  loadVersion();
  loadPersistConfig();
  pollSys();
  setInterval(pollSys, 3000);
  resumeLiveIfRunning();   // reconnect to an in-progress capture after refresh
}
document.addEventListener("DOMContentLoaded", init);
