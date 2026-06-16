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

- 의존성 없음 (Python 3.8+ 표준 라이브러리만 사용)
- 여러 OS의 로그 포맷(BSD syslog / ISO·journald / macOS / Windows 콘솔)을 모두 처리
- **웹 포탈** + CLI 두 가지 사용 방식
- 사람이 읽는 요약 + CSV / JSON / Graphviz(DOT) 출력

---

## 🚀 웹 포탈 (권장) — 브라우저로 편리하게

```bash
python3 -m tinc_route_analyzer.web --port 8080
# 브라우저에서 http://localhost:8080 접속
```

1. tinc 로그 파일을 **끌어다 놓거나** 선택 → (필요 시 파일별 노드명 지정) → **[분석하기]**
2. 결과를 탭으로 확인:
   - **수집상태** — 파일별 인식 이벤트 수, 관측 기간, 로그 수집/피어관측 노드
   - **호스트 정보** — 노드별 물리주소(터널 엔드포인트)·소유 서브넷·송수신량
   - **수집된 정책** — 통신 노드 쌍 → NSX 허용 규칙 후보(양측 서브넷 포함)
   - **라우팅** — 멀티홉/중계 경로, "직접 터널 없음" 구간 표시
   - **토폴로지** — 직접(실선)/중계(점선) 그래프
3. **Export**: JSON · Flows CSV · 정책 CSV · Graphviz DOT · 요약 TXT 다운로드

- **[예제 불러오기]** 버튼으로 동봉된 멀티 OS 예제를 즉시 분석해 볼 수 있습니다.
- 모든 분석은 **로컬에서 표준 라이브러리만으로** 수행되고, 외부 CDN을 전혀
  사용하지 않으므로 **폐쇄망/에어갭 환경**에서도 그대로 동작합니다.
- 기본 바인딩은 안전하게 `127.0.0.1` 입니다. 원격 서버에서 띄워 접속하려면
  `--host 0.0.0.0` (또는 SSH 포트 포워딩)을 사용하세요.

> 브라우저가 파일을 읽어 JSON으로 전송 → 서버가 분석해 결과/그래프를 반환하는
> 구조라, 서버는 멀티파트 업로드 파싱 없이 동작합니다.

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
tinc-route-analyzer samples/*.log
```

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
- 타임스탬프는 **표기된 벽시계 값 그대로**(타임존 제거) 비교합니다. 오프셋이
  다른 여러 타임존 로그를 섞어 상관분석하려면 미리 UTC 등으로 통일하세요.
- 패킷 바이트 수는 `Sending/Received` 로그 기준의 *추정치*이며, `Forwarding`
  로그에는 크기가 없어 중계 구간은 패킷 수만 집계합니다.
- 스위치 모드(L2)의 MAC 학습 로그도 인식하지만, 라우터 모드(L3, 서브넷 기반)
  환경을 주 대상으로 설계되었습니다.

---

## 7. 프로젝트 구조

```
tinc_route_analyzer/
  parser.py     로그 한 줄 → LogEvent (접두사 분리 + 메시지 패턴 매칭)
  models.py     LogEvent / FlowStats / NodeInfo 데이터 모델
  analyzer.py   이벤트 집계 → 노드·플로우·중계·서브넷
                (analyze_files: 파일 / analyze_texts: 메모리·웹용)
  reporter.py   summary/pairs/policies/routes/flows/nodes/subnets/csv/json/dot 렌더러
  cli.py        명령행 인터페이스
  web/          웹 포탈 (표준 라이브러리 http.server)
    server.py     라우팅 + analyze_payload() (순수 함수, 테스트 대상)
    static/       index.html · style.css · app.js (외부 의존성 없음)
samples/        여러 OS 포맷의 예제 로그 + dump_subnets.txt
tests/          parser/analyzer/web 단위·통합 테스트 (python -m unittest)
```

실행:

```bash
python3 -m tinc_route_analyzer.web --port 8080   # 웹 포탈
python3 -m tinc_route_analyzer samples/*.log     # CLI
python3 -m unittest discover -s tests            # 테스트(34건)
```
