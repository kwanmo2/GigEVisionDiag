# FetchNetworkConfig

GigE Vision 카메라 장애 조사를 위한 **Windows 10/11 x64용 설치 없는 콘솔 수집기**입니다. 고객 PC의 NIC·네트워크 현재 상태와 기존 로그를 읽어 진단 ZIP을 만듭니다.

Sapera SDK 로그도 기본 수집에 포함합니다. `HKLM\SOFTWARE\Teledyne DALSA\Sapera Log Server`의 `LogFile` 값을 64비트/32비트 순서로 읽고, 값이 없으면 `%WINDIR%\System32\Logs.dat`를 사용합니다. 최대 64 MiB까지 전체 원본 바이트를 `sapera-Logs.dat`로 ZIP에 저장하며, 초과 파일은 잘라 저장하지 않고 미수집 사유를 기록합니다. 원본 경로·크기·수정 시각·읽기 중 변경 여부는 `snapshot.json`의 `sapera` 모듈에 남습니다. 파일 없음·권한 부족·잠금은 나머지 수집을 중단하지 않습니다.

Sapera 파일에는 `--days` 날짜 필터나 MVSDK/CamClient 텍스트 분석을 적용하지 않습니다. 분석 시 원본의 해시와 ZIP CRC만 검증합니다. Sapera Log Server와 로그 설정은 변경하지 않으며 Log Viewer도 실행하지 않습니다. 전달받은 파일은 Sapera Log Viewer에서 별도로 확인합니다.

## 고객 PC에서 실행

1. 배포 ZIP을 원하는 로컬 폴더에 풀어 놓습니다. 설치 프로그램은 없습니다.
2. EXE가 있는 폴더에 결과를 저장할 수 있어야 합니다. 쓰기 가능한 로컬/외장 폴더에서 실행합니다.
3. 명령 프롬프트 또는 PowerShell을 **관리자 권한으로** 열고 EXE를 실행합니다. 옵션이나 별도 입력은 필요하지 않습니다.

```powershell
.\FetchNetworkConfig.exe
```

기본 동작은 **한 번 수집, 최근 30일의 기존 이력 조회, EXE 옆에 고유 결과 폴더 생성**입니다. 파일을 덮어쓰지 않습니다. 실행한 콘솔의 현재 폴더가 다른 위치여도 EXE가 있는 폴더에 저장합니다. 기본 위치에 저장할 수 없으면 안내 후 종료하며 다른 위치로 자동 저장하지 않습니다.

옵션은 수집 조건을 바꾸고 싶을 때만 사용합니다. 저장 위치만 바꾸려면 기존 폴더를 지정합니다.

```powershell
.\FetchNetworkConfig.exe --output "D:\CameraDiagnostics"
```

장애 시각과 알려진 카메라 정보를 입력할 수도 있습니다. 아래 값은 예시이며 실제 고객 정보로 바꿉니다. 이전의 `collect` 명령 형식도 계속 지원합니다.

```powershell
.\FetchNetworkConfig.exe --output "D:\CameraDiagnostics" --days 30 --incident-time "2026-10-08T14:00:00+09:00" --camera-mac "aa:bb:cc:dd:ee:ff" --expected-camera-ip "192.168.10.20" --log-file "D:\CameraApp\Logs\existing.log"
```

- `--output`: 기본 저장 위치(EXE 옆)를 다른 기존 로컬/외장 폴더로 바꿉니다.
- `--days`: 기존 이력 범위, 기본 30일, 허용 1~3650일. 장애 시각 옵션은 범위를 자동으로 넓히지 않습니다.
- `--incident-time`: ISO 8601 시각. `Z` 또는 `+09:00` 같은 시간대가 필수입니다.
- 카메라 MAC/IP는 **사용자가 제공한 조사 기준**입니다. 프로그램은 카메라에 검색·접속·조회 패킷을 보내지 않습니다.
- `--log-file`: 사용자가 명시한 기존 로그만 읽습니다. 최대 16개를 반복 지정할 수 있습니다. 로그를 찾기 위해 고객 디스크 전체를 검색하지 않습니다.
- `--log-utc-offset +09:00`: SDK 로그의 시간대 없는 원래 시각에 적용할 고정 오프셋입니다. 지정하지 않으면 UTC로 추정하지 않습니다.
- `--app-name Example.exe`: 경로 없는 실행 파일명을 반복 지정하면 해당 앱의 오류·응답 없음·WER·.NET Runtime 기록도 포함합니다. 카메라/SDK 관련 기록은 기본으로 선별합니다.
- `--dump-file existing.dmp`: 기존 덤프의 메타데이터만 읽습니다. 최대 8개, 각각 1GiB 이하입니다. 스택이나 장애 원인을 분석하지 않습니다.
- `--attach-dumps`: 명시한 덤프 원본을 별도의 `dump-attachments.zip`에 첨부합니다. 원본 합계는 2GiB 이하이며 기본값은 원본 첨부 없음입니다.
- `--include-evtx`: JSONL로 선택한 System/Application Record ID를 EVTX로 추가 복사합니다. 기존 이벤트를 지우거나 채널 설정을 변경하지 않습니다.
- UNC, 네트워크 드라이브, 장치 경로, 대체 데이터 스트림, 심볼릭 링크와 junction 경로는 사용하지 않습니다.
- `--help`와 `--version`은 관리자 권한 없이 실행 가능하며 수집 파일을 만들지 않습니다.

수집은 작업별 최대 30초, 전체 최대 5분이며 이후 보고서·ZIP 생성 시간이 추가됩니다. 접근 거부나 미지원 항목이 있어도 가능한 수집은 계속됩니다. 기본 30일 동안 기존 이벤트가 아주 많으면 최신 기록부터 제한된 양을 보존하고 누락 사유를 표시합니다.

선택한 덤프 원본 첨부에는 별도로 최대 5분을 적용합니다. 첨부나 EVTX 내보내기가 실패하거나 한도를 넘으면 기본 진단 자료를 유지하고 부분 수집으로 표시합니다. 미완성 첨부·한도 초과 EVTX는 기본 ZIP에 넣지 않습니다.

### NIC의 Jumbo Packet·절전 설정

별도 옵션 없이 함께 조회하여 `snapshot.json`에 기록합니다. WMI의 고정 `SELECT` 질의와 레지스트리 `KEY_READ`로 읽으며 설정 변경 메서드를 호출하지 않습니다.

| 항목 | 원본 위치 | 기록 내용 |
|---|---|---|
| Jumbo Packet 및 드라이버 고급 설정 | `modules`의 `task_id: advanced` → `queries[].rows[]` | NIC 이름/장치 ID, RegistryKeyword, DisplayName/DisplayValue, RegistryValue, 기본값·선택 가능한 값, Source |
| 전원관리 | `task_id: power` → `queries[].rows[]` | AllowComputerToTurnOffDevice, SelectiveSuspend, DeviceSleepOnDisconnect, WakeOnMagicPacket/Pattern, 전원 관련 offload, Source |
| EEE·Green Ethernet·절전 시 속도 감소 등 | `task_id: advanced` | 드라이버가 제공하는 원래 키와 표시값·저장값 |
| IP MTU | `task_id: network` → `adapters[]` / `interfaces[]` | IP Helper API에서 조회한 MTU. Jumbo 드라이버 설정과 별도 값 |
| 분리된 NIC의 저장 설정 | `task_id: registry` → `keys[].values[]` | NIC 클래스 키의 원래 값·레지스트리 형식·증거 경로. 현재 적용 여부는 확인하지 않음 |

제조사마다 항목 이름·지원 여부·값 의미가 다릅니다. 예를 들어 Jumbo의 저장값 `2`는 드라이버의 선택 코드일 수 있어 `2 bytes`로 해석하지 않습니다. 전원관리의 `Unsupported (0)`과 `Disabled (1)`도 구분합니다. 미지원/권한 부족/시간 초과는 모듈 상태에 표시하며, 값이 없다는 이유로 비활성으로 판단하지 않습니다.

## 전달할 결과

콘솔에 출력된 `FetchNetworkConfig-…\diagnostics.zip`을 기술지원 담당자에게 전달합니다. 업로드나 메일 전송은 프로그램이 수행하지 않습니다. 설정 정보, 컴퓨터명, IP/MAC, 방화벽의 프로그램 경로 등이 포함되므로 전달 전 고객사의 정보 제공 정책을 확인합니다.

| 파일 | 내용 |
|---|---|
| `summary.txt` | 한국어 요약, 확인 사실·조사 후보·확인 불가, 모듈별 수집 범위와 누락 |
| `snapshot.json` | 스키마 버전 1, 현재 상태, 원래 설정 키/값과 형식, 수집 출처·시각·오류 |
| `timeline.csv` | 시간순 이벤트 및 증거 파일/행 번호, 입력 장애 시각과 시간 차이 |
| `events-*.jsonl` | 한 줄에 한 이벤트. `xml` 문자열에 원본 XML, Provider/Event ID/Record ID와 메시지 |
| `setupapi-nic.log` | 장치 ID와 기간에 대응하는 SetupAPI 설치 기록 구간, UTF-8로 저장 |
| `setupapi-timeline.jsonl` | 설치 기록 위치와 해석한 시각; 시각 없는 구간은 날짜를 만들지 않음 |
| `user-log-*.log` | 지정한 프로그램 로그의 원래 바이트. 큰 로그는 끝부분과 원래 offset 기록 |
| `sdk-events.jsonl` / `sdk-summary.json` | 인식한 MVSDK/CamClient 이벤트·세션·실행 버전·MTU/패킷·통계·오류 유형 및 원본 위치 |
| `dump-*-metadata.json` | 덤프 생성 시각, 아키텍처, OS build, 플래그, 모듈 파일 버전, 예외 스트림 유무 |
| `selected-System.evtx` / `selected-Application.evtx` | 선택 옵션으로 복사한 원본 이벤트. JSONL Record ID와 대조된 파일만 포함 |
| `manifest.json` | 수집 조건, 모듈 상태, 각 증거·보고서 파일의 SHA-256 |
| `diagnostics.zip.sha256` | 최종 ZIP의 SHA-256, ZIP 옆에 저장 |

ZIP과 원래 결과 파일은 함께 유지됩니다. 기존 파일을 덮어쓰지 않습니다. `manifest.json` 자체와 ZIP은 순환 해시 때문에 내부 파일 목록에서 제외됩니다. 해시는 무결성 확인용이며 전자서명이 아닙니다.

`dump-attachments.zip`은 기본 `diagnostics.zip`에 포함되지 않습니다. 첨부 내부 manifest에 원본별 크기·SHA-256·경로를 기록하고, 기본 manifest에 외부 첨부의 크기·SHA-256을 기록합니다. 요청한 경우 별도 ZIP과 체크섬도 함께 전달합니다. 원본 덤프는 프로세스 메모리를 포함할 수 있으므로 고객이 허용한 전달 범위로 취급합니다.

CSV는 UTF-8 BOM을 포함하며 수식 실행을 방지하기 위해 위험한 시작 문자를 가진 셀에 작은따옴표를 붙입니다. 메시지는 발췌일 수 있으며 전체 원본은 JSONL에서 확인합니다. 원본 XML은 `xml` 필드의 JSON escape를 해제하면 읽을 수 있습니다.

JSON/JSONL은 BOM 없는 UTF-8입니다. Windows PowerShell 5.1에서 읽을 때는 `Get-Content -Encoding UTF8`을 지정합니다.

## 결과를 한 파일로 분석하기

수집 결과 폴더 또는 내부 `diagnostics.zip` 하나를 입력하면 **검색 가능한 `analysis.html` 한 개**를 만듭니다. 기존 1.0.1 결과도 지원합니다. Python 설치나 관리자 권한이 필요하지 않습니다. 수집 명령과 달리 저장된 증거만 읽습니다.

```powershell
.\FetchNetworkConfig.exe analyze "D:\Received\diagnostics.zip"
```

현재 프로젝트의 결과 폴더를 직접 분석할 수도 있습니다.

```powershell
.\FetchNetworkConfig.exe analyze "D:\Received\FetchNetworkConfig-example"
```

기본 저장 위치는 EXE 옆의 고유 `FetchNetworkAnalysis-…` 폴더입니다. 다른 기존 폴더를 원하면 `--output "D:\Analysis"`를 붙입니다. 폴더 입력을 분석할 때 그 증거 폴더와 하위에는 분석 결과를 쓰지 않습니다. ZIP 입력은 ZIP 자체를 변경하지 않습니다. 완료 후 출력된 `analysis.html`을 브라우저에서 열면 됩니다. 자동으로 브라우저를 실행하지 않습니다.

보고서는 NIC·주소·경로·필터·전원관리·고급 속성·드라이버·영상 소프트웨어·방화벽·이벤트·수집 범위를 정리합니다. 표 검색, NIC의 Up만 보기, 인쇄/PDF 저장을 지원합니다. 외부 라이브러리나 리소스를 다운로드하지 않습니다.

1절의 **NIC별 IP 요약표**에서 NIC 이름을 누르면 해당 NIC의 상세 카드가 열립니다. 연결된 하드웨어 NIC부터 표시하고, 각 카드에 다음 내용을 함께 정리합니다.

- IPv4 주소·prefix·서브넷 마스크·수동/DHCP 할당, 게이트웨이·DNS·네트워크 프로필, 별도의 IPv6 목록.
- MAC·장치 GUID·링크 속도·IP MTU·NIC 드라이버 버전/공급자/INF.
- 해당 NIC의 필터 드라이버와 활성/비활성 상태, 전체 바인딩.
- 전원 차단 허용·Selective Suspend·연결 해제 시 절전·Wake, Jumbo·EEE·속도/duplex·버퍼 등의 주요 고급 설정.
- 펼쳐 볼 수 있는 전체 고급 설정, RSS·오프로드 속성, 저장된 레지스트리 값, 누적 카운터.

검색과 `NIC에서 Up만 보기`는 NIC 카드와 요약표에 적용됩니다. `NIC 펼치기/접기` 버튼도 제공합니다. 원본에 대응하는 값이 없는 항목은 미수집/미매핑으로 표시하며 전체 비교표에 원래 조회값을 유지합니다.

NIC 설정·필터는 장치 GUID로, GUID가 없는 프로필은 기록된 ifIndex로 연결합니다. NIC 드라이버 버전은 GUID → PNPDeviceID → 서명된 드라이버 DeviceID로 연결하며 이름이나 공통 드라이버 설명만으로 연결하지 않습니다. Jumbo의 드라이버 표시값과 IP MTU는 별도 값입니다. 주요 고급 설정은 원래 키의 문자열로 선별하므로 나머지 항목은 전체 표에서 확인합니다. 기존 결과 ZIP도 다시 수집할 필요 없이 이 보고서로 분석 가능합니다. 경로와 전체 NIC 비교표는 접어서 표시합니다.

- 수동 `169.254` 주소와 DHCP 주소를 구분하고, Up인 NIC 간 중복과 비활성 NIC가 포함된 중복을 분리합니다.
- 원본 XML의 Provider/ID/Record ID/시각을 대조합니다. 같은 이벤트를 중복 집계하지 않습니다.
- 이벤트 집계에 원본 파일명·행 번호를 표시합니다. 일부 Intel/Marvell 링크 이벤트는 XML 장치명으로 NIC에 매핑해 날짜별로 집계합니다. 미지원 이벤트 종류도 Provider/ID별 집계에는 포함됩니다.
- 시간 초과·부분 수집·보존 기간·채널 비활성·깨진 JSONL 행을 명시합니다. 일부 수집이어도 유효한 기록은 분석합니다.
- manifest 파일 크기/SHA-256, ZIP CRC를 먼저 검증합니다. ZIP 옆 체크섬이 있으면 ZIP 해시도 대조합니다. 불일치하면 분석 파일을 만들지 않습니다. 해시는 서명이 아니며 자료 출처를 인증하지 않습니다.
- ZIP은 메모리에서만 읽으며 압축을 디스크에 풀지 않습니다. 폴더 입력은 manifest에 열거된 파일만 읽습니다. 원본을 수정하거나 삭제하지 않습니다.
- 지원 스키마는 1입니다. 파일당 64MiB, 압축 해제 자료 총 256MiB, ZIP 512MiB, 파일 256개, JSONL 전체 100,000행으로 제한합니다. 제한 초과는 종료 코드 2입니다.
- 보고서의 이벤트 그룹과 SetupAPI 목록은 최대 500개, 링크 증거 예시는 포트당 최대 6개입니다. 전체 유효 이벤트의 집계에는 표시 제한을 적용하지 않습니다. 긴 셀은 발췌 표시합니다.
- 사용자 앱 로그 본문 전체, 실제 카메라 설정, 실시간 패킷 상태, 변경 주체 또는 장애 원인을 자동으로 판정하지 않습니다.

1.4.0은 MVSDK/CamClient 형식의 명시 로그를 구조화합니다. 기존 번들에 SDK 파생 파일이 없으면 원본 로그를 작은 단위로 읽으면서 분석합니다. 원본 16개 × 16MiB 전체를 메모리에 보관하지 않습니다. SDK 구조화 이벤트는 전체 10,000개/4MiB, 행은 64KiB로 제한합니다. UTF-8·UTF-16LE와 CP949 대체 해석을 지원하며 원본 바이트는 그대로 유지합니다. 잘린 로그의 행 번호는 복사본 기준이며 바이트 위치는 원본 파일 기준입니다. 인식하지 못한 로그는 자동 장애 판정을 하지 않습니다.

SDK/설치 목록/덤프 모듈 버전은 별도의 관찰값입니다. ERROR 개수, 미지원 파라미터, 취득 중단 전환만으로 네트워크 장애를 단정하지 않습니다. Application Error와 WER는 별도 기록으로 유지하고 ReportID 또는 앱·PID와 5분 이내 시각의 근거가 있을 때만 연관 표시합니다. NDIS의 알 수 없는 링크 속도(`UINT64_MAX`)는 미확인으로 표시합니다. 물리 메모리는 총량·가용량·부하와 모듈별 용량(64비트)·제조사·Part number·보고 속도 및 관찰 시각을 기록합니다.

분석 종료 코드: `0` 접근 가능한 자료 분석 완료, `1` 원본의 일부 수집/분석 제외 있음(보고서는 생성), `2` 잘못된 입력·무결성 불일치·저장 실패. `analyze --help`는 파일을 만들지 않습니다.

### 특정 날짜의 이벤트 추출

`--date YYYY-MM-DD`를 추가하면 저장된 이벤트와 SetupAPI 이력 중 해당 날짜만 선택합니다. 기본 기준은 **한국 시간 UTC+09:00, 그날 00:00 이상부터 다음 날 00:00 미만**입니다. 분석 PC의 현재 시간대나 원본의 local 문자열로 판정하지 않고, 원래 UTC 시각에 지정한 offset을 적용합니다.

```powershell
.\FetchNetworkConfig.exe analyze "D:\Received\diagnostics.zip" --date 2026-10-08
```

다른 기준이 필요하면 고정 UTC offset을 지정합니다. UTC 하루는 `--utc-offset +00:00`입니다. DST 지역은 해당 날짜에 적용할 offset을 사용자가 지정합니다.

```powershell
.\FetchNetworkConfig.exe analyze "D:\Received\diagnostics.zip" --date 2026-10-08 --utc-offset +00:00
```

같은 새 결과 폴더에 다음 세 파일을 만듭니다.

| 파일 | 내용 |
|---|---|
| `analysis.html` | 선택 날짜·UTC 범위·선택/원본 횟수, 시간순 이벤트 목록(최대 1,000개 표시), 해당 날짜만 반영한 이벤트 집계 |
| `selected-events.csv` | 선택된 전체 이벤트/SetupAPI 이력, 선택한 시간대 및 원래 UTC/local 시각, 메시지, 원본 파일명/행. UTF-8 BOM, 수식 실행 방지 |
| `selected-events.jsonl` | 선택된 전체 이력. `record`에 원래 JSON 필드와 XML을 그대로 유지하며 `source_file`, `source_line`, `time_selected`를 추가한 wrapper |

NIC/IP/필터/전원 설정은 수집 시점의 스냅샷이며 특정 날짜의 과거 설정을 복원하지 않습니다. 날짜를 판정할 수 없는 SetupAPI 이력은 제외 횟수와 부분 분석 상태를 표시합니다. 손상/중복 이벤트는 원래 분석 규칙에 따라 제외하며 원본의 시간 초과·누락 표시를 유지합니다. 날짜에 맞는 기록이 없어도 헤더만 있는 CSV, 빈 JSONL과 설명이 포함된 HTML을 만듭니다. 이는 해당 날짜에 사건이 없었다는 증거가 아닙니다.

SDK 로그의 원본 오프셋과 날짜 선택 기준은 별개입니다. `--utc-offset`은 날짜 경계이며, `--log-utc-offset`은 시간대 없는 SDK 원래 시각의 해석입니다. 분석 시 지정한 로그 오프셋이 수집 시 저장한 값보다 우선합니다. 로그 오프셋이 없으면 원래 시각을 표시하고 날짜 추출에서는 제외 횟수를 표시합니다. SDK는 `kind: sdk`로 내보내며 Windows 이벤트 건수에 합산하지 않습니다. 세션과 버전 표는 전체 원본 범위를 보여 줍니다.

```powershell
.\FetchNetworkConfig.exe analyze "D:\Received\diagnostics.zip" --date 2026-10-09 --utc-offset +09:00 --log-utc-offset +09:00
```

일반 분석은 HTML 하나만 생성합니다. 날짜 추출의 CSV/JSONL은 각각 64MiB로 제한하며 초과 시 새 출력 폴더를 만들기 전에 종료 코드 2로 실패합니다. 원본은 수정하지 않습니다.

### 종료 코드와 상태

| 종료 코드 | 의미 |
|---|---|
| 0 | 접근 가능한 수집 완료. 원래 없는 선택적 로그 채널도 요약에 표시됨 |
| 1 | 접근 거부·미지원·시간 초과·제한·오류 등으로 일부 수집 불완전 |
| 2 | 인자 오류, 저장 또는 패키징 실패. 만들어진 증거는 유지됨 |
| 3 | 관리자 권한 없음. 결과 폴더를 만들지 않음 |

모듈 상태: `ok`, `empty`, `missing`, `unsupported`, `access_denied`, `partial`, `timeout`, `not_collected`, `error`. 수집되지 않은 항목은 값이 정상이라는 뜻이 아닙니다. 요청한 `--log-file`이 없으면 종료 코드 1입니다. 메시지 리소스가 없는 이벤트도 XML이 보존되면 증거로 사용 가능합니다.

## 읽기 전용 계약과 한계

상세 계약과 금지된 동작은 [READ_ONLY_CONTRACT.md](docs/READ_ONLY_CONTRACT.md)에 있습니다.

**설정 불변**을 목표로 하며, 프로그램 실행 중 Windows가 남기는 Prefetch·보안·WMI 실행 기록 등 OS 자체 흔적까지 없애는 도구는 아닙니다. 메모리 사용과 파일 읽기 부하는 발생합니다.

- NIC/IP/드라이버/방화벽/전원/감사/로그 설정을 변경하지 않습니다.
- 카메라 SDK를 로드하지 않고 카메라를 열지 않습니다. ForceIP, DHCP 갱신, ping, DNS 질의, 패킷 캡처도 없습니다.
- 이력은 이미 남아 있는 기록만 읽습니다. 로그가 없다는 이유로 변경이 없었다고 판단하지 않습니다.
- Security 4657은 당시 레지스트리 감사가 설정되어 있어야 존재합니다. 권한이 부족하면 그대로 표시합니다.
- PC의 DHCP 정보와 카메라의 DHCP 정보는 별개입니다. ARP는 현재 카메라 IP를 확정하는 증거가 아닙니다.
- IP·경로·Neighbor 표는 현재 routing compartment 기준입니다. 다른 compartment를 전환하거나 조회하기 위해 설정을 변경하지 않습니다.
- 현재 상태는 순차 관찰이며 원자적 스냅샷이 아닙니다. 자연적인 DHCP·캐시·로그 변화가 발생할 수 있습니다.
- SetupAPI의 시간대 없는 시각은 현재 Windows 시간대 규칙으로 해석합니다. 과거 시간대 변경은 복원하지 않습니다.
- 각 이벤트 채널: 최대 20만 개 검사, 1만 개 선택, 증거 16 MiB. SetupAPI: 마지막 32 MiB 검사, 관련 구간 최대 8 MiB. 지정 로그: 각각 마지막 16 MiB. WMI: 질의별 4096행/직렬화 데이터 3 MiB. 수집 프로세스 메모리 상한 192 MiB, 응답 상한 24 MiB.
- 일반 Windows/SetupAPI 구조화 이력은 합계 100,000행입니다. `mvGenICamForEthernet`은 일반 System에서 제외하고 전용 파일·작업으로 수집하며 일반 채널 뒤에 남은 공유 예산을 사용합니다.
- EVTX: 파일당 32MiB, 합계 64MiB. 덤프: 메타데이터 읽기 4MiB/파일, 최대 4,096개 모듈. 덤프 첨부는 별도 ZIP이므로 분석기의 기존 일반 번들 크기 제한을 늘리지 않습니다.
- 타임라인 CSV는 최대 64MiB와 남은 일반 번들 예산 안에서 요약합니다. 제한 도달은 부분 수집으로 표시하며 등록된 원본 JSONL은 그대로 유지합니다.

## 개발과 검증

Visual Studio 2022의 C++ 빌드 도구, Windows SDK, CMake 3.24 이상이 필요합니다. 외부 의존성은 소스에 고정되어 있으므로 빌드 시 자동 다운로드가 없습니다. 고객 PC에는 빌드 도구나 C++ Redistributable이 필요하지 않습니다.

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
python tools/verify_safety.py
```

기능 시험은 인자·경로 거부, 원본 보존, 작업 시간 초과·응답 제한·불완전 증거, 타임라인, ZIP을 검증합니다. 실제 고객 설정을 변경해 이벤트를 만들지 않습니다.

개발 PC에서 조회 API와 설정 불변을 추가 확인하려면:

```powershell
powershell -NoProfile -File tools/validate-readonly.ps1
```

현재 권한으로 설정을 전후 비교하고 테스트 전용 EXE의 실제 조회 API를 실행합니다. 테스트 EXE의 일반 권한 조회 지원은 제품 EXE의 관리자 필수 조건을 변경하지 않습니다. 결과·비교 파일은 `test-results`에 저장됩니다.

배포 패키지:

```powershell
powershell -NoProfile -File tools/package.ps1
```

`dist/FetchNetworkConfig-1.4.0-win-x64.zip`과 체크섬을 생성합니다. 고객에게 테스트 EXE나 빌드 도구를 전달하지 않습니다. 코드 서명 인증서는 포함되어 있지 않아 EXE는 서명되지 않았습니다. 고객 보안 정책이 서명을 요구하면 배포 담당자의 인증서로 서명한 후 체크섬과 배포 ZIP을 다시 생성합니다. 프로그램에서 보안 정책을 완화하지 않습니다.

실제 관리자 권한 실행, Windows 10/11 각각의 호환성, 운용 중인 카메라 프레임 손실 및 CPU 부하는 고객 배포 전 별도 시험 장비에서 확인합니다. 도구가 자동으로 NIC 설정을 바꾸거나 장비 장애를 재현하지 않습니다.

현재까지의 실제 검증 결과와 미검증 조건은 [VALIDATION.md](docs/VALIDATION.md)에 기록되어 있습니다.
