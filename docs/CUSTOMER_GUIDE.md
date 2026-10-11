# FetchNetworkConfig — 사용 안내

Windows 10/11 x64용 설치 없는 콘솔 프로그램입니다. NIC·네트워크 현재 설정과 이미 존재하는 이력을 읽어 진단 자료를 저장합니다. Jumbo Packet, EEE, 절전·Wake, 필터 드라이버 설정을 함께 기록합니다.

## 고객 PC에서 수집

1. ZIP을 쓰기 가능한 로컬/외장 폴더에 풉니다. 네트워크 드라이브와 junction·symlink 경로는 지원하지 않습니다.
2. 관리자 권한의 PowerShell 또는 명령 프롬프트에서 실행합니다.

```powershell
.\FetchNetworkConfig.exe
```

옵션 없이 한 번 실행하며 최근 30일의 기존 이력을 조회합니다. EXE 옆에 고유 결과 폴더를 생성하고 기존 파일을 덮어쓰지 않습니다. 다른 위치에 저장하려면 먼저 만들어진 기존 폴더를 지정합니다.

```powershell
.\FetchNetworkConfig.exe --output "D:\CameraDiagnostics"
```

Sapera Log Server의 기존 로그는 옵션 없이 자동 수집합니다. `HKLM\SOFTWARE\Teledyne DALSA\Sapera Log Server`의 `LogFile` 값을 우선 사용하고, 값이 없으면 `%WINDIR%\System32\Logs.dat`를 읽습니다. 최대 64 MiB까지 전체를 `sapera-Logs.dat`로 ZIP에 포함합니다. 초과·파일 없음·권한 부족·잠금은 수집 상태에 기록됩니다. 서비스나 로그 설정은 변경하지 않습니다. 파일에는 날짜 필터나 텍스트 분석을 적용하지 않으며 Sapera Log Viewer에서 별도로 확인합니다.

Huaray MVSDK 로그도 `%USERPROFILE%\MVSDK\<Application 이름>\*.log`에서 자동 수집합니다. 최근 수정된 파일부터 최대 192개, 파일마다 마지막 16 MiB, 합계 64 MiB까지 원본 바이트를 보존합니다. 합계 예산이 적게 남으면 남은 범위만 복사합니다. ZIP의 `mvsdk-log-*.log`와 `mvsdk-index.json`에는 원래 앱 이름·파일명·경로·수정 시각·복사 범위·개별 결과가 기록됩니다. 파일 잠금이나 제한은 나머지 수집을 중단하지 않습니다. `--days`로 파일을 거르지 않으며 앱 폴더 한 단계만 조회합니다. ZIP·덤프·중첩 폴더와 junction/symlink는 제외합니다. 다른 계정으로 실행하면 해당 실행 계정의 프로필을 사용합니다.

선택 옵션: `--days 1~3650`, `--incident-time ISO8601`, `--camera-mac`, `--expected-camera-ip`, `--log-file`. 사용자 로그는 최대 16개, 각각 마지막 16 MiB를 복사합니다. 카메라 MAC/IP 옵션은 사용자가 제공한 조사 기준이며 카메라에 접속하거나 실제 IP를 조회하지 않습니다. `--help`, `--version`은 관리자 권한 없이 실행할 수 있습니다.

자동 수집 MVSDK 로그 외에 카메라 앱의 장애 기록과 기존 SDK 로그를 함께 지정할 수 있습니다. 아래 오프셋은 원본 로그가 한국 시간일 때의 예입니다.

```powershell
.\FetchNetworkConfig.exe --app-name MVviewer.exe --log-file "D:\CameraApp\2026-10-09.123.MVSDK.log" --log-utc-offset +09:00
```

`--include-evtx`는 선택한 System/Application 이벤트의 EVTX 복사본을 추가합니다. `--dump-file "D:\Dumps\existing.dmp"`는 기존 덤프의 메타데이터만 읽습니다(최대 8개, 각각 1GiB). 원본까지 전달하려면 `--attach-dumps`를 추가합니다(합계 2GiB). 덤프를 새로 생성하거나 프로세스를 열지 않습니다.

수집은 작업별 최대 30초, 전체 수집 최대 5분입니다. 이후 보고서·해시·ZIP 생성 시간이 추가됩니다. 보존 기간·비활성 채널·권한·크기/건수·시간 제한 때문에 요청한 기간 전체를 수집하지 못할 수 있습니다.

덤프 원본 첨부에는 별도 최대 5분이 추가됩니다. 선택 첨부/EVTX 실패도 기본 진단 ZIP을 유지하며 부분 수집으로 표시합니다.

## 결과 전달

콘솔에 표시된 결과 폴더의 `diagnostics.zip`과 `diagnostics.zip.sha256`을 고객이 허용한 방법으로 전달합니다. ZIP은 암호화되지 않으며 PC 이름, IP/MAC, 설정, 경로 및 이벤트 정보가 포함됩니다. 프로그램은 자동 업로드나 메일 전송을 하지 않습니다.

| 종료 코드 | 조치 |
|---|---|
| 0 | 수집 완료. `summary.txt`의 범위와 누락도 확인합니다. |
| 1 | 일부 누락·시간 초과·미지원. 생성된 ZIP을 그대로 전달하고 `summary.txt`도 확인합니다. |
| 2 | 입력·저장·패키징 실패. 오류 메시지와 남은 결과 폴더를 전달합니다. 설정을 바꾸며 반복 실행하지 않습니다. |
| 3 | 관리자 권한 부족. 관리자 콘솔에서 실행해야 하며 결과 폴더는 생성되지 않습니다. |

`snapshot.json`에는 현재 설정과 수집 상태, `events-*.jsonl`에는 원본 XML, `timeline.csv`에는 시각과 원본 파일/행 번호, `manifest.json`에는 파일 해시가 있습니다. 해시는 손상 확인 수단이며 자료 출처를 인증하는 서명이 아닙니다.

자동·명시 SDK 로그의 분석 결과는 `sdk-events.jsonl`과 `sdk-summary.json`에 포함합니다. 덤프를 지정하면 `dump-*-metadata.json`을 포함합니다. 원본 첨부를 요청한 경우 `dump-attachments.zip`과 체크섬은 `diagnostics.zip`과 별도입니다. 프로세스 메모리가 포함될 수 있으므로 고객이 허용한 범위에서 함께 전달합니다.

## 저장된 자료 분석

분석은 관리자 권한이나 Python 설치 없이 실행합니다. 원본 폴더/ZIP은 수정하지 않습니다.

```powershell
.\FetchNetworkConfig.exe analyze "D:\Received\diagnostics.zip"
.\FetchNetworkConfig.exe analyze "D:\Received\diagnostics.zip" --date 2026-10-08
```

일반 분석은 새 결과 폴더에 `analysis.html`, `findings.json`, `llm-context.json`을 생성합니다. 보고서는 종합 판정(심각/주의/판단 불가/정상), 주요 문제와 권장 조치, 카메라 NIC 체크리스트(링크 속도·Jumbo·MTU·수신 버퍼·EEE·전원·필터·방화벽·오류 카운터), 카메라·SDK 세션 품질, 링크·SDK·앱 오류 상관 타임라인 순으로 보여 줍니다. 연결되지 않은 NIC와 전체 원본 표는 부록에 접어 둡니다. 판정은 수집값 기반의 규칙 판정이며 "추정" 표시는 시간·이름 일치에 근거한 것입니다. `llm-context.json`은 컴퓨터명·사용자명·카메라 시리얼·MAC 일부·공인 IP를 마스킹한 요약이며 프로그램이 외부로 보내지 않습니다. 날짜 추출은 `selected-events.csv`와 원래 JSON/XML을 보존하는 `selected-events.jsonl`도 생성합니다.

날짜 기준은 기본 UTC+09:00입니다. UTC 날짜는 `--utc-offset +00:00`을 추가합니다. NIC 설정은 수집 시점의 상태이며 지정 날짜의 과거 설정을 복원하지 않습니다. 분석 종료 코드 1도 보고서는 생성되며 일부 누락/미해석 상태를 뜻합니다.

값이 없거나 형식이 불명확한 필터 상태와 알 수 없는 링크 속도는 미확인으로 표시합니다. 동일 설명의 NIC가 여러 개면 해당 링크 이벤트를 특정 NIC에 연결하지 않고 모호한 후보를 표시합니다. MVSDK/CamClient 로그는 실행 버전·카메라·MTU/패킷·세션·통계를 구조화합니다. 기타 로그는 원본 증거로 보존합니다. ERROR 개수만으로 장애 원인을 판정하지 않으며 덤프 스택 분석은 수행하지 않습니다.

SDK 로그 시각은 명시한 `--log-utc-offset`으로만 UTC를 확정합니다. 수집 때 빠뜨렸으면 분석 명령에 추가할 수 있으며 저장된 값보다 우선합니다. 오프셋이 없으면 원래 시각을 표시하고 날짜 추출에서 제외 횟수를 표시합니다. 날짜 기준 `--utc-offset`과는 별개입니다. SDK 기록은 Windows 이벤트 건수와 분리합니다.

## 실행 조건과 보장 범위

- NIC/IP/전원/방화벽/감사 설정 변경, 카메라 검색·ForceIP·SDK·ping·패킷 캡처 기능이 없습니다.
- 결과 파일을 저장하고 CPU·메모리·디스크 자원을 사용합니다. Windows·보안 제품·WMI 제공자가 자체 실행 흔적을 남길 수 있습니다. 카메라 운용 중 영향은 해당 시험 환경에서 확인해야 합니다.
- 이력 부재는 변경 부재의 증거가 아닙니다. 카메라의 IP 변경 이력과 PC의 DHCP/NIC 이력은 서로 다른 자료입니다.
- `RELEASE_STATUS.json`에 실행 파일 버전·해시·서명 상태와 환경 검증 기록 유무를 표시합니다. 이 패키지는 인증서 없이 제공할 수 있습니다. 실행 허용 여부는 고객의 기존 정책을 따릅니다.
- 상세 동작 범위: [읽기 전용 계약](docs/READ_ONLY_CONTRACT.md). 변경 내용: [버전 안내](docs/RELEASE_NOTES.md).
