# tinc → NSX VPN Migration: Route / Traffic Analyzer

기존에 여러 OS(Linux/Windows/macOS 등)에서 **tinc VPN**을 사용 중인 환경을
**NSX VPN**으로 마이그레이션할 때, *어떤 노드들 사이에 실제 트래픽이 오가는지*
와 *그 트래픽이 어떤 경로(직접/중계)로 흐르는지*를 tinc 로그로부터 분석해 주는
도구입니다. 마이그레이션 시 NSX에서 다시 만들어야 하는 **연결 관계 / 방화벽
정책 / 라우팅**의 근거 자료를 자동으로 추출합니다.

> Reads tinc VPN logs collected from many machines, reconstructs **which node
> talks to which node**, the **route/relay path** used, and the **subnets each
> node owns** — exactly the inputs you need to recreate connectivity and
> firewall policy on NSX.

두 가지 입력을 지원합니다:

1. **tshark/Wireshark 패킷 캡처 CSV** — 실제 트래픽을 캡처해 분석(주 사용 경로,
   **수십 GB** 스트리밍 처리). `A→B`와 `B→A`는 하나의 통신쌍으로 중복 제거.
2. **tinc VPN 로그** — 기존 VPN의 연결/서브넷/중계 정보 분석.

- 의존성 없음 (Python 3.8+ 표준 라이브러리만) · 폐쇄망/에어갭 동작 · 외부 CDN 없음
- **웹 포탈**(시각화) + **스트리밍 CLI**(대용량 처리)
- 출력: 수집상태 · 호스트 · 통신쌍 · 수집된 정책(NSX 허용 규칙) · 라우팅 + CSV/JSON/DOT

---

## 📦 패킷 캡처(tshark CSV) 분석 — 대용량(수십 GB)

캡처 (예: 사용자 명령):

```bash
tshark -i ens192 -T fields -E header=y -E separator=, \
  -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
  -e ip.proto -e frame.len > network.csv
```

분석 (데이터가 있는 서버에서 스트리밍 처리, `.gz`·glob·병렬 지원):

```bash
# 사람이 읽는 요약
python3 -m tinc_route_analyzer.flowcsv samples/network.csv

# 수십 GB: 병렬 처리(-j) + 진행률, 결과를 작은 report.json 으로 저장
python3 -m tinc_route_analyzer.flowcsv -j 4 --progress -f json -o report.json '/caps/*.csv.gz'

# 정책(NSX 허용 규칙) CSV만 추출
python3 -m tinc_route_analyzer.flowcsv -f policies-csv network.csv > policies.csv
```

그런 다음 **웹 포탈에 `report.json`을 업로드**하면 시각화됩니다(아래).

### 설계 — 왜 수십 GB가 되는가 (측정값 기반, 추정 아님)
- **단일 패스 스트리밍.** 캡처 전체를 메모리에 올리지 않습니다.
- **메모리는 패킷 수가 아니라 네트워크 카디널리티(호스트/통신쌍/서비스/서브넷)에
  비례.** 측정: 300만 패킷 처리 시 최대 RSS **약 13–22 MB**.
- **병렬(-j)은 정확한 라인 경계로 분할**하여 순차 결과와 **비트 단위로 동일**함을
  검증(경계에서 누락/중복 없음).
- 측정 처리량(4코어): 순차 ≈ 0.12 M pkt/s, `-j 4` ≈ 0.34 M pkt/s(**3.7×**,
  `--no-time` 시), 30 GB 외삽 ≈ **약 14분**(코어 수에 따라 선형 단축).

### 근거 기반 서비스(리스닝 포트) 판정 — 추측 배제
판정 근거(basis)를 2단계로 둡니다:
- **handshake (가장 확실)** — 캡처에 `tcp.flags`가 있으면 **TCP 3-way 핸드셰이크**로
  서버를 사실 확정합니다. SYN(=클라이언트→서버)이면 목적지가 서버, SYN-ACK이면
  출발지가 서버. 포트 범위가 같아도 핸드셰이크가 관측되면 확정됩니다.
- **port-range (추정)** — 플래그가 없을 때만 **IANA RFC 6335 포트 범위**(시스템
  ≤1023, 등록 1024–49151, 동적 ≥49152) + OS 에페메럴 범위(Linux 32768–60999)로
  추정합니다. 두 포트가 같은 범주면 **판정하지 않고**(추측 배제) 정책을 만들지
  않습니다.

각 서비스에는 basis와 **실제 관측된 서로 다른 클라이언트 수**를 함께 표기합니다.
(예: 플래그 없는 `network.csv`에서 `10.94.40.36:TCP/665`는 port-range·클라이언트
4개로 판정.) 핸드셰이크 판정을 원하면 캡처 시 `-e tcp.flags` 를 추가하세요:

```bash
tshark -i tun0 -T fields -E header=y -E separator=, \
  -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
  -e tcp.flags -e udp.srcport -e udp.dstport -e ip.proto -e frame.len > network.csv
```

---

## 🚀 웹 포탈 — 브라우저로 편리하게

```bash
python3 -m tinc_route_analyzer.web --port 8080
# 브라우저에서 http://localhost:8080 접속
```

1. 파일을 **끌어다 놓거나** 선택 → **[분석하기]**. 입력 종류는 자동 감지됩니다:
   - 패킷 캡처 **CSV**(작은 샘플) · 사전 집계 **report.json**(대용량 결과) · **tinc 로그**
2. 결과를 탭으로 확인 (입력 종류에 맞게 표시):
   - **수집상태** — 파일별 인식 패킷/이벤트, 프로토콜 분포, 관측 기간
   - **호스트 정보** — IP/서브넷·역할(서버/클라이언트)·제공 서비스·송수신량
   - **통신쌍** — `A↔B` 중복 제거 + 방향별(A→B, B→A) 분리 표기
   - **수집된 정책** — 서비스(proto/port) → NSX 허용 규칙(서버·출발 서브넷·근거)
   - **라우팅** — 서브넷 간 매트릭스(그룹 단위 NSX 정책) / (tinc는 중계 경로)
   - **토폴로지** — 호스트·통신 그래프
3. **Export**: JSON · 통신쌍 CSV · 정책 CSV · 호스트 CSV · Graphviz DOT

- **[예제 불러오기]** 로 동봉된 실제 형식 캡처(`network.csv`)를 즉시 분석합니다.
- 분석은 **로컬·표준 라이브러리·CDN 없음** → 폐쇄망/에어갭에서 동작.
- 기본 바인딩은 `127.0.0.1`. 원격 접속은 `--host 0.0.0.0` 또는 SSH 포워딩.

> **대용량 캡처는 포탈에 직접 올리지 마세요.** 브라우저 직접 분석은 64 MB로 제한되며
> 초과 시 CLI 사용을 안내합니다. 권장 흐름: 서버에서
> `tinc-flow-analyzer -j 4 -f json -o report.json capture.csv` → 포탈에 `report.json` 업로드.

---

## 📡 실시간 분석 (Live)

도구가 패킷을 직접 잡지는 않습니다(폐쇄망용 표준 라이브러리). `tshark` 라이브
출력을 흘려보내면 **준실시간**으로 집계합니다.

> **"end-to-end IP"는 캡처 위치가 결정합니다.** 진짜 종단 간(오버레이 내부)
> IP는 VPN 인터페이스 `tun0`에서, 노드(터널 엔드포인트) IP는 물리 NIC `ens192`
> 에서 보입니다. NAT 뒤에서는 변환된 IP가 보입니다.

**① CLI 실시간 대시보드** — `tshark | ... --stdin --live` (N초마다 화면 갱신)

```bash
tshark -i tun0 -l -T fields -E header=y -E separator=, \
  -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
  -e tcp.flags -e udp.srcport -e udp.dstport -e ip.proto -e frame.len \
  | python3 -m tinc_route_analyzer.flowcsv --stdin --live --interval 2
```
(`tcp.flags` 를 포함하면 서버/클라이언트 방향을 핸드셰이크로 확정합니다.)

**② 포탈 라이브 뷰** — 서버가 `tshark`를 실행해 실시간 시각화

```bash
# 보안상 기본 비활성. 명시적으로 켜야 하며 캡처 권한 필요.
python3 -m tinc_route_analyzer.web --port 8080 --enable-capture
```
포탈의 **📡 실시간 캡처** 패널에서 인터페이스(`tun0` 등)를 입력하고 **[실시간 시작]**
→ 통신쌍/서비스/토폴로지가 2초마다 갱신됩니다.

- 보안: `--enable-capture` 없이는 캡처 API가 **403**으로 거부됩니다. 인터페이스
  이름은 화이트리스트 정규식으로 검증하고, `tshark`는 **셸 없이**(argv 리스트)
  실행해 명령 주입을 차단합니다. 기본 바인딩은 `127.0.0.1`.
- TCP/UDP 포트를 모두 캡처하며(파서가 자동 인식), 서비스 판정은 동일하게 IANA
  포트 범위 사실 기반입니다.

---

## 1. CLI 빠르게 실행해 보기 (Quick start)

```bash
# 동봉된 예제 로그로 바로 실행
python3 -m tinc_route_analyzer samples/*.log

# 호스트네임이 없는 로그(Windows 콘솔 캡처 등)는 노드 이름을 직접 지정
python3 -m tinc_route_analyzer --node branch2=samples/windows_branch2.log \
    samples/linux_hq.log samples/linux_cloud.log samples/macos_laptop.log
```

예제 요약 출력(발췌):

```
Communication pairs (each pair => one NSX connectivity / firewall policy)
  node pair           packets  bytes  path       dirs
  ------------------  -------  -----  ---------  ----
  cloud <-> hq        2        2.9KB  direct     2
  branch2 <-> laptop  3        750B   via cloud  2
  ...

Routing / relay paths (multi-hop traffic that tinc auto-routed)
  path                        packets  note
  --------------------------  -------  ------------------
  laptop -> cloud -> branch2  2        [no direct tunnel]
```

테스트:

```bash
python3 -m unittest discover -s tests
```

---

## 2. 무엇을 분석하나 (What it extracts)

tinc 로그 한 줄은 OS마다 다른 접두사(타임스탬프/호스트/프로그램) 뒤에 **tinc
메시지 본문**이 붙는 구조입니다. 메시지 본문은 OS·버전과 무관하게 거의
동일하므로, 이를 이용해 다음을 추출합니다.

| 추출 항목 | 근거가 되는 tinc 로그 | NSX 마이그레이션에서의 쓰임 |
|---|---|---|
| **노드 인벤토리 + 물리 IP** | `Connection with X (IP port) activated` 등 | IPsec/Route-based VPN **터널 엔드포인트** |
| **노드별 소유 서브넷** | `Got ADD_SUBNET ... for <owner> <subnet>` | NSX **IP Set / Group**, 광고할 네트워크 |
| **노드 간 통신 쌍(트래픽)** | `Sending/Received packet of N bytes ...` | NSX **분산 방화벽(DFW)/게이트웨이 규칙** |
| **중계 경로(멀티홉)** | `Forwarding packet from X to Y ...` | NSX에서 **명시적 연결/라우팅**이 필요한 구간 |

### 방향(directed) 트래픽과 중복 카운트 처리
하나의 실제 패킷은 보내는 노드(`Sending ... to`)와 받는 노드(`Received ...
from`) 양쪽에서 각각 로그로 남습니다. 두 관측을 단순 합산하면 **중복 집계**가
되므로, 이 도구는 송신/수신 관측을 분리해 저장하고 방향별 패킷·바이트 수는 두
관측 중 큰 값을 채택합니다. `Forwarding`(중계) 로그는 동일 패킷의 *경로*
정보이므로 트래픽 양에 더하지 않고 **경로/중계자** 정보로만 사용합니다.

### 관측 노드(local node) 식별
패킷 로그의 방향을 정하려면 그 줄을 *기록한 노드*를 알아야 합니다. 우선순위는:
1. 줄에 들어 있는 syslog 호스트네임 (중앙 로그 서버로 여러 호스트를 모은 경우에
   각 줄마다 다른 호스트도 정확히 처리)
2. `--node NAME=FILE` 로 파일에 지정한 노드명 (접두사가 없는 Windows 콘솔
   로그 등)
3. 파일명에서 추론 (`linux_hq.log` → `hq`, `windows_branch2.log` → `branch2`)

OS 호스트네임과 tinc 노드명이 다르면 `--host-map win-pc01=branch2` 처럼
매핑하세요.

---

## 3. 사용법 (Usage)

```
python3 -m tinc_route_analyzer [옵션] LOGFILE [LOGFILE ...]

옵션:
  --node NAME=FILE      접두사(호스트네임)가 없는 로그 파일의 노드명을 지정 (반복 가능)
  --host-map OSHOST=NODE OS 호스트네임 → tinc 노드명 변환 (반복 가능)
  --subnets-dump FILE   'tinc dump subnets' 출력으로 서브넷→소유자 매핑 보강 (반복 가능)
  -f, --format FORMAT   summary(기본) | nodes | pairs | policies | flows |
                        routes | subnets | csv | policies-csv | json | dot
  -o, --output FILE     stdout 대신 파일로 저장
  --top N               pair/flow 표를 상위 N개로 제한
  --year YYYY           연도가 없는 BSD syslog 타임스탬프에 사용할 연도(기본: 올해)
```

### 출력 포맷
- `summary` — 사람이 읽는 종합 리포트(개요·노드·통신쌍·경로·서브넷)
- `pairs` — 통신 노드 쌍 = NSX 정책 후보 (마이그레이션의 핵심 산출물)
- `policies` — 통신 쌍을 NSX 허용 규칙(양측 서브넷/엔드포인트 포함)으로 변환
- `routes` — 멀티홉/중계 경로. NSX에서 직접 연결을 만들어야 하는 구간 표시
- `flows` — 방향별 상세 플로우(송신/수신/중계 카운트)
- `nodes` / `subnets` — 노드·서브넷 인벤토리
- `csv` — 방향별 플로우 표(스프레드시트/추가 가공용)
- `policies-csv` — 정책(허용 규칙) 표 CSV (NSX 반입용 가공 기반)
- `json` — 전체 구조화 데이터(자동화/NSX 정책 생성 파이프라인용)
- `dot` — Graphviz 그래프. 실선=직접, 점선=중계, 점선 박스=로그가 없는 노드

```bash
# 그래프 이미지 생성 (graphviz 필요)
python3 -m tinc_route_analyzer -f dot samples/*.log | dot -Tpng -o topology.png

# 자동화용 JSON
python3 -m tinc_route_analyzer -f json -o report.json samples/*.log
```

### (선택) 설치해서 명령어로 사용
```bash
pip install -e .
tinc-flow-analyzer  network.csv        # 패킷 캡처 CSV(대용량)
tinc-route-analyzer samples/*.log      # tinc 로그
tinc-route-analyzer-web --port 8080    # 웹 포탈
```

> 패킷 캡처 CSV 전용 옵션은 `python3 -m tinc_route_analyzer.flowcsv -h` 참고
> (`-j/--workers`, `--no-time`, `--progress`, `.gz`/glob 입력,
> 포맷: summary/hosts/services/subnets/json/conversations-csv/policies-csv/hosts-csv/dot).

---

## 4. tinc 쪽 준비 — 어떤 로그가 필요한가

- **연결/토폴로지/서브넷**(누가 누구와 연결, 어떤 서브넷 소유)은 기본 로그
  레벨에서도 나옵니다.
- **패킷 단위 트래픽 양/방향**은 tinc의 디버그 레벨이 **3(traffic) 이상**일 때
  기록됩니다. 트래픽 매트릭스를 원하면 일정 기간 다음과 같이 상세 로깅을
  켜세요.

```bash
# 실행 중 디버그 레벨 상향 (예: 5). 0으로 되돌릴 수 있음
tinc -n <netname> set LogLevel 5      # tinc 1.1
# 또는 tincd 실행 시
tincd -n <netname> -d5

# 로그 위치 예
#   Linux(syslog/journald): journalctl -u tinc@<netname>  또는 /var/log/syslog
#   macOS: /var/log/system.log (tincd)
#   Windows: --logfile 로 파일 출력 또는 이벤트 로그
```

디버그 레벨이 낮아 패킷 로그가 없더라도, 연결·서브넷·중계 정보만으로
**토폴로지와 통신 관계의 상당 부분**을 복원할 수 있습니다.

권위 있는 서브넷→노드 매핑이 필요하면 `tinc -n <netname> dump subnets` 출력을
저장해 `--subnets-dump` 로 넣으면 됩니다(형식: `<subnet> owner <node>`).

---

## 5. 내 환경의 로그 포맷이 다를 때 (Adapting the patterns)

메시지 본문 패턴은 `tinc_route_analyzer/parser.py` 의 `_PATTERNS` 목록에
정규식으로 모여 있습니다. tinc 버전/언어 설정에 따라 문구가 다르면 해당 정규식만
추가/수정하면 됩니다(명명 그룹 `peer/src/dst/owner/subnet/size/addr/via` 를
그대로 쓰면 분석기가 자동 인식). syslog 접두사 처리(타임스탬프/호스트/프로그램
토큰)는 `split_prefix` 에 있습니다.

실제 운영 로그 샘플을 주시면 패턴을 그 포맷에 맞춰 바로 조정해 드릴 수 있습니다.

---

## 6. 가정과 한계 (Assumptions & limitations)
**패킷 캡처(CSV)**
- 캡처에 TCP 플래그가 없으므로, 양쪽 포트가 같은 범주면 발신자(서버)를 주소만으로
  **단정하지 않고** 서비스/정책을 만들지 않습니다(근거 기반). 필요하면 캡처에
  `-e tcp.flags` 를 추가하면 SYN 기반 판정을 더 강화할 수 있습니다(향후 옵션).
- 열 순서는 헤더(`-E header=y`)가 있으면 헤더로, 없으면 위 예시 순서를 가정합니다.
  UDP 포트만 캡처한 경우 `-e udp.srcport -e udp.dstport` 도 자동 인식합니다.
- 단일 지점 캡처에는 경로(홉) 정보가 없어 "라우팅"은 서브넷 간 관계로 표현합니다.
- 서브넷 그룹화는 IPv4 `/24` 기준입니다(다른 마스크가 필요하면 알려주세요).

**tinc 로그**
- 타임스탬프는 **표기된 벽시계 값 그대로**(타임존 제거) 비교합니다.
- 바이트 수는 `Sending/Received` 기준 추정치이며 `Forwarding`(중계)은 패킷 수만 집계.
- L3(서브넷 기반) 라우터 모드를 주 대상으로 설계(L2 MAC 학습도 인식).

---

## 7. 프로젝트 구조

```
tinc_route_analyzer/
  flowcsv.py    tshark 캡처 CSV: 스트리밍 파싱 → 통신쌍(중복제거)·호스트·서비스·
                서브넷 집계 + 병렬 엔진(merge) + 리포트 + CLI
  parser.py     tinc 로그 한 줄 → LogEvent (접두사 분리 + 메시지 패턴 매칭)
  models.py     LogEvent / FlowStats / NodeInfo 데이터 모델
  analyzer.py   tinc 이벤트 집계 (analyze_files: 파일 / analyze_texts: 메모리·웹용)
  reporter.py   tinc 렌더러(summary/pairs/policies/routes/.../csv/json/dot)
  cli.py        tinc 로그 CLI
  web/          웹 포탈 (표준 라이브러리 http.server, CDN 없음)
    server.py     라우팅 + analyze_payload() — 입력 자동 감지(flow JSON/CSV/tinc)
    static/       index.html · style.css · app.js (모드별 렌더링)
samples/        network.csv(실제 캡처 형식) + tinc 예제 로그 + dump_subnets.txt
tests/          flowcsv/parser/analyzer/web 테스트 (python -m unittest)
CLAUDE.md       엔지니어링 원칙(근거 기반·대용량 설계) — 세션 간 유지
```

실행:

```bash
python3 -m tinc_route_analyzer.web --port 8080      # 웹 포탈(시각화)
python3 -m tinc_route_analyzer.flowcsv -j4 network.csv   # 패킷 캡처 CLI(대용량)
python3 -m tinc_route_analyzer samples/*.log        # tinc 로그 CLI
python3 -m unittest discover -s tests               # 테스트(54건)
```
