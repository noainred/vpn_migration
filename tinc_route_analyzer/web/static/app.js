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
    els.results.classList.remove("hidden");
    stopLivePolling();
    await pollLive();
    state.liveTimer = setInterval(pollLive, 2000);
  } catch (e) { setLiveStatus("요청 실패: " + e, "err"); }
}
async function pollLive() {
  try {
    const json = await (await fetch("/api/live/status")).json();
    if (!json.ok) { setLiveStatus(json.error || "상태 조회 실패", "err"); stopLivePolling(); return; }
    state.result = json;
    renderFlow(json);
    setupExports("live", json);
    setLiveStatus(`'${json.iface || "?"}' 캡처 중 — ${json.elapsed}s · ${Math.round(json.pps).toLocaleString()} pkt/s · 패킷 ${num(json.data.meta.packets)}`,
      json.running ? "ok" : "");
    if (!json.running && json.error) { setLiveStatus("캡처 종료: " + json.error, "err"); stopLivePolling(); }
  } catch (e) { setLiveStatus("폴링 실패: " + e, "err"); stopLivePolling(); }
}
async function stopLive() {
  stopLivePolling();
  try { await fetch("/api/live/stop", { method: "POST" }); } catch (e) { /* ignore */ }
  setLiveStatus("캡처를 중지했습니다.");
}

async function analyze() {
  stopLivePolling();
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
  state.files = []; state.result = null;
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
  return `<table class="grid"><thead><tr>${headers.map((h) => `<th>${esc(h)}</th>`).join("")
    }</tr></thead><tbody>${rows.map((r) => `<tr>${r.join("")}</tr>`).join("")}</tbody></table>`;
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
  $("#tab-conv").innerHTML = `<div class="section-title">통신쌍 — A→B와 B→A를 하나로 합산 (중복 제거)</div>` +
    table(["통신쌍", "패킷", "바이트", "A→B", "B→A", "서비스", "기간(s)"],
      d.conversations.map((c) => [
        td(`<strong>${esc(c.a)}</strong> ⟷ <strong>${esc(c.b)}</strong>`),
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
  $("#tab-conv").innerHTML = `<div class="section-title">통신쌍 (A↔B 중복 제거)</div>` +
    table(["노드 쌍", "패킷", "바이트", "경로", "방향수"],
      d.communication_pairs.map((p) => [
        td(`<strong>${esc(p.a)}</strong> ⟷ <strong>${esc(p.b)}</strong>`),
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
  bindTabs();
}
document.addEventListener("DOMContentLoaded", init);
