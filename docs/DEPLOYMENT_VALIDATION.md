# 배포 환경 검증 절차 — 내부용

고객용 EXE에는 추적·부하 생성·카메라 제어 기능을 추가하지 않습니다. 아래 절차는 시험 장비에서 최종 배포할 파일을 검증하는 용도입니다. 내부 결과와 이 문서는 고객용 ZIP에 포함하지 않습니다.

## 관리자 권한 제품 수집 전후 비교

관리자 권한 시험 콘솔에서 다음을 실행합니다. 기존 도구의 기본 모드는 테스트 EXE의 조회 API 검증이며, `-ProductCollection`을 지정해야 실제 제품 EXE를 실행합니다. 스크립트는 자동 권한 상승이나 설정 변경을 하지 않습니다.

```powershell
powershell -NoProfile -File tools/validate-readonly.ps1 -ProductCollection
```

`test-results/readonly-…`에 전후 설정, 실제 제품 출력·ZIP, 제품 버전·SHA-256, OS 빌드 및 부모 프로세스의 시간·CPU·메모리 표본을 기록합니다. 종료 코드 1도 부분 수집 ZIP을 검증합니다. 접근 불가 항목은 검증 완료로 취급하지 않습니다. 차이가 있으면 자연적인 DHCP/정책/동시 작업 변화와 프로그램 동작을 조사하며 자동으로 되돌리지 않습니다.

부모 프로세스 표본만으로 전체 부하를 판단하지 않습니다. 자식 수집기와 WMI 제공자, 디스크·네트워크·카메라 통계를 별도 측정해야 합니다. 스크립트는 직접 시작한 제품 프로세스에만 시험용 10분 상한을 적용하며 이미 생성한 자료를 보존합니다.

## 대상 환경과 카메라 운용 시험

1. 지원할 Windows 10/11 x64의 OS 빌드, NIC 제조사·드라이버 버전, 카메라 앱 버전과 운용 조건을 기록합니다.
2. 동일한 앱·카메라 조건에서 수집 전, 수집 중, 수집 후의 프레임 수·프레임 손실·연결 오류와 전체 CPU/메모리/디스크 통계를 비교합니다. 허용 기준은 현장 요구에 맞게 미리 정합니다.
3. 시험실에서 준비된 관찰 도구로 실제 파일·레지스트리·프로세스·네트워크 동작을 확인합니다. 추적 도구를 고객용 EXE에 포함하거나 고객 PC의 정책을 바꾸지 않습니다.
4. 고객의 기존 실행 정책에서 EXE 및 동일 EXE의 자식 수집 작업이 허용되는지 확인합니다. 코드 서명 없이 배포하는 경우에도 이 사실을 기록합니다.

성공한 관리자 실행 결과가 있다는 것과 전후 설정 동일성·운용 중 무영향이 검증됐다는 것은 별도로 기록합니다.

## 패키지 생성

```powershell
powershell -NoProfile -File tools/package.ps1
```

인증서 없이도 생성합니다. 실행 파일의 메타데이터·서명 상태·최종 해시·허용 파일 목록·고객용 문서 내용·ZIP CRC를 검사합니다. 서명이 요구되는 배포에는 `-RequireSignature`를 지정할 수 있습니다.

환경 검증 완료 기록을 포함하려면 아래 형식의 내부 JSON을 만들어 `-ValidationRecord <path>`로 지정합니다. 실제 증거를 검토한 항목만 true로 바꿉니다. 패키징은 버전과 최종 EXE 해시가 일치하고 모든 항목이 true인지 확인합니다. 원시 기록은 ZIP에 복사하지 않으며 완료 기록 제공 여부만 `RELEASE_STATUS.json`에 남깁니다.

```json
{
  "schema_version": 1,
  "tool_version": "1.4.0",
  "exe_sha256": "최종 EXE의 SHA-256",
  "completed_checks": {
    "administrator_before_after": false,
    "windows10_compatibility": false,
    "windows11_compatibility": false,
    "camera_load": false,
    "runtime_access_trace": false,
    "customer_policy": false
  }
}
```

검증 기록을 지정하지 않은 패키지의 `environment_validation`은 `pending`입니다. 이 상태를 자동으로 완료로 바꾸지 않습니다. 파일 버전의 publisher 표시명은 기본 프로젝트 이름이며 실제 서명된 회사 신원과는 다릅니다. 필요하면 빌드 시 `-DFNC_PUBLISHER="회사명"`으로 표시명을 지정합니다.
