# nFTDClient 개선 내용 (2026-06-30 ~ )

> 파일 전송 프로젝트의 **원격 측(nFTDClient)** 개선 이력 상세 기술 정리.
> nFTDClient 는 원격 호스트에서 도는 서비스로, nFTDServer(GUI) 의 명령을 받아 **파일 송수신 + 원격 파일시스템 조작**(폴더 생성/이름변경/삭제/이동/복사, 목록 열거)을 수행한다.
> GUI/트리·리스트/드래그 등 UI 개선은 `nFTDServer 개선 내용.md` 참조. 커밋 해시는 nFTDClient 저장소 기준(Common 은 별도 표기).
>
> ※ 아래 **요약**은 한 줄씩, 상세는 §0 이하 참조.

---

## 한눈에 보기 (요약)

- **소켓 감사 Batch1**: `RecvFile`/`SendFile` 파일 핸들 누수(CODE-* 경로 `CloseHandle`) — 취소 시 파일 잠김/전송 fail 원인 + ReadFile/WriteFile 검증·4GiB 배수 오판 수정.
- **소켓 감사 Batch2(CRITICAL)**: 네트워크 미검증 length 버퍼 오버플로 방지 — 경로 `RecvExact` 앞 length 가드 18곳.
- **소켓 감사 Batch3**: 수신 `CreateFile` 공유모드 `FILE_SHARE_READ` + 상시누수 경로버퍼 `new[]`→스택(5곳) + `run()` default 미지명령 로깅.
- **원격 이름변경/삭제**: `SHARING_VIOLATION(32)` 실패 + `FindFirstFile` 핸들릭 수정.
- **원격 이동/복사**: `SHFileOperation` 이중 null 종료 버그 수정 + 복사 충돌 자동 리네임(`FOF_RENAMEONCOLLISION`).
- **역할**: 서버의 로컬 파일기능(삭제/이동/복사/이름변경)을 원격 대상에 반영하는 실제 조작 담당.

---

## 0. 이 기간의 전체 방향

- **소켓 송수신 계층의 보안·안정성 감사**(서버와 대칭) — 네트워크에서 받은 length 미검증으로 인한 버퍼 오버플로, 파일 핸들 누수, 힙 버퍼 상시 누수, 공유모드 문제를 3배치로 정리.
- **원격 파일 조작을 로컬 수준으로 확장** — 폴더 이동/복사/이름변경/삭제, 이름충돌 자동 리네임, 공유위반/핸들 릭 수정.

> 서버가 로컬에서 하는 이동/복사/삭제/이름변경을 **원격 대상에도** 적용하려면, 실제 파일 조작은 이 nFTDClient 가 원격 호스트에서 수행해야 한다. 그래서 서버의 '로컬/원격 분기' 기능마다 대응하는 클라이언트 처리가 이 기간에 함께 구현됨.

---

## 1. 소켓 보안 / 안정성 감사 (Batch 1~3)

nFTDServer 와 대칭으로 진행. 클라이언트는 **네트워크에서 경로/길이를 받아 파일시스템에 직접 반영**하므로 미검증 입력의 위험이 특히 크다.

### 1.1 핸들 누수 / 검증 (Batch1 계열)
- **`RecvFile` 파일 핸들 누수 수정**(CODE-6/7/8/9 경로 `CloseHandle`) — 전송 취소 시 파일이 잠긴 채 남아 이후 전송이 fail 하던 원인. (`454b825`)
- **`SendFile` 핸들 누수**(CODE-5/6/7/9) + **4GiB 배수 크기 오판** + `ReadFile` 반환 검증. (`454b825`)
- `RecvFile` 의 `WriteFile` 반환 검증, `get_subfolder_count` 예외 가드. (`454b825`)

### 1.2 네트워크 length 미검증 버퍼 오버플로 (Batch2, CRITICAL)
- 경로 `RecvExact` **직전에 length 가드**(수신 길이가 버퍼 한계 이내인지 검증) 를 **18곳**에 삽입:
  `create_directory` / `Rename` / `delete_directory` / `DeleteFile` / `change_directory` / `ExecuteFile` / `FileInfo` / `FileList2,3` / `filelist_all` / `folderlist_all` / `get_subfolder_count` / `new_folder_index` / `file_command`. (`1ae7be3`)
- 미검증 시 원격에서 조작된 과대 length 로 스택/힙 버퍼를 넘겨 쓸 수 있었음 → 원격 코드 실행/크래시 위험 차단.

### 1.3 공유모드 / 상시 누수 / 미지명령 (Batch3, HIGH-safe)
- 수신 `CreateFile` 공유모드 `FILE_SHARE_READ`(수신 중 파일을 다른 프로세스가 읽기 가능 — 탐색기 미리보기 등과 충돌 완화). (`9924964`)
- **상시 누수 경로 버퍼**(`lpPathName`/`path`) `new[]` → 스택 전환 5곳(매 호출마다 힙 누수하던 것 제거). (`9924964`)
- `RecvFile` 의 `FindClose` 가드 및 `cFileName` bounded 복사. (`9924964`)
- `run()` switch 에 `default` 추가 — 미지원/미지명령 수신 시 로깅(무시하고 조용히 넘어가던 것). (`9924964`)

---

## 2. 원격 파일 조작 (폴더 이름변경 · 삭제 · 이동 · 복사)

서버의 로컬 파일 관리 기능을 원격 대상에도 적용하기 위한 클라이언트 측 실제 조작.

### 2.1 이름변경 / 삭제 실패 수정
- **원격 폴더 이름변경/삭제가 `SHARING_VIOLATION(32)` 로 실패**하던 것 수정 + **`FindFirstFile` 핸들 릭** 정리. (`de61936`)
  - 열거 등으로 잡고 있던 핸들 때문에 대상 폴더가 잠겨 이름변경/삭제가 거부되던 문제.

### 2.2 이동 / 복사 처리
- **원격 폴더 이동/복사 처리**: 클라이언트 측 `SHFileOperation` 배치 + **이중 null 종료 버그 수정**. (`05b8373`)
  - `SHFileOperation` 의 `pFrom`/`pTo` 는 **이중 null(`\0\0`) 종료**된 문자열 목록을 요구한다. 이 종료 처리가 잘못돼 있던 것을 수정.
- **원격 복사 시 이름충돌 자동 리네임**(`FOF_RENAMEONCOLLISION`) — 대상에 같은 이름이 있으면 "복사본" 식으로 자동 리네임(탐색기 복사와 동일). (`59b3fbb`)

---

## 3. Common 라이브러리 연관분

nFTDClient 가 공유하는 Common/공통 코드 관련.

- **bounded 복사 패턴 / 경로 처리**: 서버·클라이언트 공통으로 무경계 `_tcscpy`/`_stprintf` 를 `_sntprintf_s(_TRUNCATE)` 등 bounded 로 교체하는 정리(긴 경로·미검증 length 대응). 세부는 각 저장소 커밋 참조.
- **주석 작성자 마커 형식 통일**(`//YYYYMMDD by claude.`) — Common `claude.md` §2F.2 규칙에 맞춤. (Common `c90da9e`, `ece6156`)

> 트리·리스트·드래그·다이얼로그 등 **UI 성격의 Common 개선은 GUI 앱인 nFTDServer 에만 관계**되므로, 해당 목록은 `nFTDServer 개선 내용.md` §8 을 참조. nFTDClient 는 이들 UI 컨트롤을 사용하지 않는다.

---

## 4. 서버-클라이언트 대칭 관계 요약

| 기능 | nFTDServer(로컬/GUI) | nFTDClient(원격/서비스) |
|---|---|---|
| length 가드(Batch2) | 서버 경로 7곳 | 경로 18곳 (`1ae7be3`) |
| 핸들 누수/검증(Batch1·3) | send/recv ReadFile·WriteFile·공유모드 | RecvFile/SendFile CODE-* CloseHandle, 상시누수 버퍼 (`454b825`,`9924964`) |
| 폴더 삭제 | 로컬/원격 분기, 휴지통 | 원격 실제 삭제(SHARING_VIOLATION·핸들릭 수정) (`de61936`) |
| 폴더 이동/복사 | 로컬=move, 원격=클라이언트 처리 | SHFileOperation 배치·이중null·충돌 자동리네임 (`05b8373`,`59b3fbb`) |
| 이름변경 | F2/메뉴, MoveFile(로컬) | 원격 rename(SHARING_VIOLATION 수정) (`de61936`) |

---

## 5. 미커밋/진행 중

- 현재 nFTDClient 측 미커밋 변경 없음(위 커밋들은 반영·푸시됨).

> 후속: 원격 이동/복사의 진행률·에러 리포팅 정교화, remote→remote move(서버 측 보류 중)의 안전한 구현은 추후 과제.
