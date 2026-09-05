# Caldera Lab 세션 인수인계

작성일: 2026-07-30 (Asia/Seoul)

## 1. 프로젝트와 원격 저장소

- 로컬 경로: `/home/mintkangaroo/Project/AI_Security_Lab/Caldera_Lab`
- GitHub: <https://github.com/MintKangaroo/Caldera-Lab>
- 기본 브랜치: `main`
- 현재 커밋: `ddb10ed fix: run lab agents as non-root`
- 작업 트리: clean
- 대시보드 저장소: <https://github.com/MintKangaroo/AI-Security-Lab-Dashboard>
- 대시보드 등록 커밋: `74324f2 feat: register caldera lab portfolio`

## 2. 이번 세션에서 완료한 것

- `Caldera_Lab` 신규 프로젝트 생성 및 GitHub 저장소 생성/푸시
- allowlist 기반 `catalog/abilities.json` 추가
- 규칙 planner와 선택적 LLM planner 추가
- tabular Q-learning policy 추가
- orchestrator의 계획 → 승인 → 실행 → 보상 → 감사 이벤트 루프 추가
- Docker executor 추가
  - `--network none` (정책에서 네트워크를 허용하지 않는 기본값)
  - `--read-only`
  - `--user 65534:65534` (non-root)
  - `--cap-drop ALL`
  - `--security-opt no-new-privileges:true`
  - `--pids-limit 64`
- dry-run과 명시적 `--allow-local` 개발 executor 추가
- JSONL 감사 로그(`.runtime/run.jsonl`) 추가
- 6개 테스트, Ruff, Python 3.10/3.12 GitHub Actions 통과
- Docker 이미지 빌드 및 실제 2단계 실행 성공 확인
- 기존 대시보드에 `caldera-lab` 프로젝트 등록
- README에 현재 상태와 검증 결과 추가

## 3. 현재 실행 방법

```bash
cd /home/mintkangaroo/Project/AI_Security_Lab/Caldera_Lab
python3 -m pip install -e ".[dev]"
make check

# Docker 이미지 빌드
docker build -t caldera-lab-agent:latest .

# 실제 격리 실행 (기본 권장)
PYTHONPATH=src python3 -m caldera_lab run \
  --executor docker --planner hybrid --steps 4

# API 키 없이도 rules planner로 fallback됨
PYTHONPATH=src python3 -m caldera_lab run \
  --executor docker --planner rules --steps 2

# 흐름만 확인
make run
```

LLM planner를 사용하려면 `OPENAI_API_KEY`를 설정합니다. 선택 환경 변수:

- `CALDERA_LLM_MODEL` (기본값: `gpt-4.1-mini`)
- `CALDERA_LLM_ENDPOINT` (기본값: OpenAI Responses endpoint)

LLM은 command를 생성하지 않고 allowlist의 `ability_id`만 제안합니다. 키가 없거나
응답이 잘못되면 rules planner로 fallback합니다.

## 4. 현재 파일별 역할

- `catalog/abilities.json`: 현재 허용된 4개 discovery 능력
- `src/caldera_lab/catalog.py`: catalog 스키마·allowlist 검증
- `src/caldera_lab/planner.py`: `RulePlanner`, `LLMPlanner`
- `src/caldera_lab/rl.py`: seed 가능한 tabular `QPolicy`
- `src/caldera_lab/policy.py`: 최대 단계·timeout·risk 정책
- `src/caldera_lab/executor.py`: Docker, local-dev, dry-run executor
- `src/caldera_lab/orchestrator.py`: 전체 실행 루프와 JSONL 이벤트 기록
- `src/caldera_lab/cli.py`: `run` 명령과 executor 안전 게이트
- `tests/test_caldera_lab.py`: 6개 단위/통합 성격 테스트

## 5. 설계상 안전 경계

- 임의 shell 문자열을 받지 않습니다. catalog에 선언된 argv 배열만 실행합니다.
- 기본 네트워크는 끊겨 있습니다.
- 기본 Docker 실행은 non-root입니다.
- 기본 능력은 정보 수집(discovery)만 제공하며, 자격 증명·지속성·외부 스캔·임의 파일 변경
  능력은 없습니다.
- `local` executor는 개발용이며 `--allow-local` 없이는 CLI에서 거부됩니다.
- 반드시 소유하거나 명시적으로 허가된 격리 랩에서만 사용합니다.

## 5-1. 후속 세션(2026-08-29)에서 수정한 것

- `collect-workspace-files`가 항상 실패하던 문제 수정: Docker executor가 `/workspace`를
  read-only 바인드 마운트합니다(`--workspace` CLI 플래그, 기본 `.runtime/workspace`).
- 감사 로그를 덮어쓰기(`write_text`)에서 append로 변경하고 이벤트마다 `run_id`를 부여했습니다.
- `__main__.py`의 import 시점 `main()` 실행을 `if __name__ == "__main__"` 가드로 교체했습니다.
- `policy.py`의 도달 불가능한 승인 조건을 실제 게이트로 교체했습니다:
  `allowed_risks`, `Ability.requires_network` + `allow_network`, `approved_abilities`.
- Docker 인자에 `--pull never`, `--memory 256m`, `--cpus 1.0`을 추가했습니다.
- `cli.main(argv)`로 테스트 가능하게 만들고 `--steps` 양수 검증을 추가했습니다.
- 이름과 다른 것을 검증하던 CLI 게이트 테스트를 실제 게이트 테스트로 교체하고,
  LLM이 catalog 밖 ID/shell 문자열을 반환하는 경우의 negative test를 추가했습니다.
- RL state를 관측 해시에서 "완료한 능력 집합 비트마스크 + 마지막 결과"로 추상화했습니다.
  도달 가능한 고유 state가 633 -> 31로 줄고, 실행 간 동일 항목이 재방문되어 값이 수렴합니다.
- Q table을 JSON으로 영속화했습니다(`--q-table`, `--no-q-table`). catalog 지문이 다르거나
  손상되었거나 catalog 밖 action이 있으면 로드를 거부하고 빈 table로 시작합니다.
- 사용되지 않던 마지막 replan 호출을 제거했습니다(LLM 모드에서 실행당 1회 절약).
- 보상을 재설계했습니다. 기존 성공 +1 / 실패 -1은 모든 능력이 성공하는 카탈로그에서
  상수 신호라 Q값이 실행 순서만 인코딩했습니다. 이제
  `total = outcome + information_gain - cost`이며 정보 이득은 stdout에서 새로 관측한
  사실의 비율입니다(에피소드 단위로 초기화). 항별 분해는 `reward.scored` 이벤트로 남깁니다.
- `ExecutionResult.duration_seconds`를 추가하고 시간 비용을 정책 timeout 대비로 상한했습니다.
- 알려진 한계: 실행마다 변하는 출력(hostname, PID)은 novel로 집계됩니다. 테스트로 고정됨.
- LLM planner 계약을 강화했습니다. Responses API의 `json_schema` strict 출력으로 catalog ID만
  허용하고, 재시도(기본 2회)·요청 timeout·지연·토큰 사용량을 기록합니다. 기존 `except: pass`로
  삼켜지던 실패는 이제 `Plan.diagnostics`를 거쳐 `plan.created`/`plan.replanned` 이벤트에
  사유와 함께 남습니다. 거부된 ID 문자열도 함께 기록합니다.
- CI에 `docker-smoke` 잡을 추가했습니다. 이미지 빌드 -> 4개 능력 실제 실행 ->
  `.github/scripts/check_smoke.py`로 감사 로그 검증 -> `/workspace` 쓰기 거부 확인 ->
  감사 로그 artifact 업로드. 체커는 종료 코드뿐 아니라 마운트된 파일이 실제로 나열되었는지와
  모든 실행의 `isolation`이 `docker`인지 확인합니다(회귀 3종 시뮬레이션으로 검증함).
- Dockerfile 베이스 이미지를 digest로 고정했습니다.
- `SECURITY.md`와 `.dockerignore`를 추가했습니다.
- `report` 서브커맨드를 추가했습니다. 감사 로그를 run 단위로 집계하고, 그동안 쓰이지 않던
  catalog의 `technique` 필드로 ATT&CK 커버리지 표를 만듭니다. 미실행 technique은 `!` 표시.
  `--json`으로 기계 판독 출력도 지원합니다.
- 작성 중 두 개의 버그를 잡았습니다: (1) dry-run의 `planned` 상태를 실패로 집계하던 문제 ->
  `executor.SUCCESS_STATUSES`로 정의를 공유. (2) `dataclasses.asdict`가 Counter를 items에서
  재구성해 키를 튜플로 망가뜨리던 문제 -> `RunSummary.as_dict()`로 명시적 직렬화.
- GitHub Actions 액션 버전을 갱신했습니다(Node 20 deprecation).
- 보상의 변동성 출력 문제를 해결했습니다. catalog에 `volatile_patterns`(능력별 정규식)를
  추가해 일치 부분을 `<volatile>`로 치환한 뒤 비교합니다. `collect-system-info`는 컨테이너
  hostname, `collect-process-list`는 CPU·시각 컬럼을 선언했습니다. 전역 휴리스틱을 쓰지 않은
  이유는 `uid=65534` 같은 실제 발견까지 지워지기 때문입니다. 잘못된 정규식은 로드 시 거부됩니다.
  실측: 8단계 실행에서 반복된 4개 능력 모두 정보 이득 1.0/0.5 -> 0.0.
- 에이전트 통신 계층을 추가했습니다(`beacon.py`, `agent.py`, `caldera-lab serve`).
  - `127.0.0.1` 전용 바인드. `0.0.0.0`/`::`/외부 IP/빈 문자열 모두 `BeaconRefused`로 거부.
  - 실행마다 토큰 발급, 디스크에 저장 안 함. 토큰 없는 요청은 401.
  - **서버는 명령이 아니라 ability ID만 전달합니다.** 에이전트가 로컬 catalog에서 해석하고
    정책 검증을 다시 통과시킵니다. 서버가 장악되어도 명령 주입이 불가능합니다.
  - beacon 주체는 컨테이너가 아니라 랩 측 supervisor라, 컨테이너는 `--network none` 유지.
    실제 Docker 실행 4/4 성공으로 확인함.
  - 미등록 에이전트(403)와 catalog 밖 ability(400)를 구분합니다. 초기 구현에서 두 KeyError가
    섞여 catalog 오류가 인증 오류로 보고되던 것을 수정했습니다.
- beacon 다중 에이전트 지원과 감사 이벤트를 추가했습니다.
  - `HTTPServer` -> `ThreadingHTTPServer`. 핸들러가 HTTP/1.1 keep-alive를 쓰는데 서버가
    단일 스레드라, 유휴 연결 하나가 다른 모든 에이전트를 막고 있었습니다(재현: B가 5초
    타임아웃 -> 수정 후 1ms). 연결 타임아웃 10초를 함께 걸었습니다.
  - 클라이언트 연결 종료 시 stderr로 쏟아지던 traceback을 억제했습니다(`handle_error`).
  - `agent.registered` / `agent.tasked` / `agent.reported` 이벤트를 `run_id`와 함께 감사
    로그에 append합니다. `agent.reported`는 수집한 출력을 복제하지 않고 크기만 기록합니다.
  - `serve --agents N`으로 동시 구동. 실측: 3 에이전트가 4개 큐를 중복 없이 분배.
  - `report`가 beacon 이벤트를 집계하도록 확장했습니다.
- `Coordinator`를 추출해 실행 경로 이중화를 제거했습니다. `serve`가 `catalog.ids()[:steps]`
  단순 큐를 쓰면서 planner와 RL을 통째로 우회하고 있었습니다. 이제 beacon 서버가
  `Coordinator.next_ability`를 task source로 쓰고, 결과는 `record_result`로 흘러 보상과
  Q table 갱신까지 이어집니다. `Orchestrator`도 같은 Coordinator 위에서 다시 작성했습니다.
- `report`의 이중 집계 버그를 수정했습니다. beacon 실행은 `ability.completed`와
  `agent.reported`를 모두 남기므로 실행 수가 두 배로 세어졌습니다. 이제 분리 집계하고,
  coordinator 이벤트가 없는 로그에서만 beacon 결과를 폴백으로 씁니다.
- 알려진 특성: 동시 dispatch에서는 RL이 배정 시점 state를 보므로 동시에 나간 능력들이 같은
  state를 공유합니다. 학습 관찰 시 `--agents 1` 권장. README에 문서화함.
- catalog을 4개 -> 8개 능력으로 확장했습니다. 모두 read-only discovery이며 technique이
  겹치지 않습니다: T1087.001(`/etc/passwd`), T1613(`/proc/self/cgroup`),
  T1016(`/proc/net/dev`), T1518(`apk info`). 8개 전부 실제 컨테이너에서 성공 확인.
- SECURITY.md의 범위를 테스트로 강제했습니다: 쓰기/네트워크/셸 명령, shell 메타문자,
  자격 증명 경로를 거부하고, technique 고유성과 기본 step 예산 적합성을 검사합니다.
- CI 스모크가 `/proc/net/dev`를 읽어 loopback 외 인터페이스가 있으면 실패합니다.
  네트워크 격리를 주장이 아니라 증거로 검증합니다(eth0 노출 시뮬레이션으로 검증함).
- timeout 처리의 실제 버그 두 개를 수정했습니다.
  - 컨테이너 누수: timeout 시 docker CLI만 죽고 컨테이너는 계속 실행됐습니다(`sleep 120`이
    running 상태로 잔존). `--rm`은 클라이언트가 살아있어야 동작합니다. 이제 `--name`을 붙이고
    timeout 시 `docker rm --force`로 제거합니다. 실측: 누수 1건 -> 0건, 15.6s -> 5.4s.
  - `timed-out`을 `failed`와 구분하는 상태로 분리했습니다. `SUCCESS_STATUSES`에 없으므로
    보상·report·CI 어디서나 실패로 취급됩니다.
- 에이전트별 정책을 추가했습니다(`Coordinator(agent_policies=...)`). 허용되지 않는 능력은
  배정 자체를 하지 않고 `ability.withheld`로 남깁니다. 제한된 에이전트가 예외를 던져 실행
  전체를 중단시키던 동작을 바꿨습니다.
- 동시 실행 RL 신용 할당을 수정했습니다. state를 완료 집합이 아니라 **배정 집합**으로
  계산합니다(`QPolicy.state_from`). 순차 실행에서는 두 집합이 일치하므로 동작이 그대로이고,
  동시 실행에서는 배정이 서로 다른 state로 분리됩니다.
  실측 고유 state 수: agents=2에서 4->8, agents=4에서 2->8, agents=6에서 3->8.
  주의: 동시 실행 state는 마지막 결과가 `|none`이라 순차 학습 Q table이 그대로 전이되지 않습니다.
- 제한된 에이전트의 굶주림을 완화했습니다. 대안이 있는 에이전트는 다른 선언된 에이전트에게
  희소한(선택지가 1개 이하인) 능력을 양보하고 `ability.deferred`를 남깁니다.
  실측: 200회 시행에서 굶는 비율 98% -> 0%. CLI 5회 반복에서도 안정적.
  예약은 선호일 뿐 락이 아니어서, 제한 에이전트가 나타나지 않으면 결국 배정되어 교착이 없습니다.
- 테스트 6개 -> 106개.

## 6. 다음 세션 우선순위

1. ~~**에이전트 통신 계층**~~: 완료(5-1 참고). 에이전트별 정책, CLI 표면, 재시도, 동시 실행
   신용 할당, 굶주림 완화까지 완료. 남은 것: 순차 학습 Q table의 동시 실행 전이(state의
   마지막 결과 성분이 `|none`이라 키가 어긋남).
2. ~~**LLM planner 계약 강화**~~: 완료(5-1 참고). 실제 API 키로의 end-to-end 검증은 아직
   수행하지 않았습니다. 스텁 기반 테스트만 있습니다.
3. ~~**RL 학습 지속성**~~, ~~**보상 설계**~~, ~~**변동성 출력 정규화**~~: 완료(5-1 참고).
4. ~~**능력 catalog 확장**~~: 8개까지 확장 완료(5-1 참고). 더 늘리려면 `LabPolicy.max_steps`
   기본값(8)도 함께 올려야 합니다. timeout 처리와 테스트도 완료.
5. ~~**대시보드 연동**~~: 완료. 랩이 `.runtime/status.json`(`lab-status/1`)을 게시하고
   `ai-security-lab-dashboard`가 `status_file`로 읽습니다. 대시보드는 이 파일을 신뢰하지
   않는 입력으로 다룹니다(스키마 확인, 프로젝트 밖 경로·심볼릭 링크 거부, 길이·개수 제한).
   두 저장소를 각각 커밋해야 합니다.
6. ~~**CI Docker smoke test**~~: 완료. GitHub Actions에서 통과 확인함(run 33231936058,
   docker-smoke 15s).

7. ~~**순차↔동시 Q table 전이**~~: 완료. state의 두 번째 성분을 "직전 결과"에서 "지금까지
   실패 여부"(`clean`/`degraded`)로 바꿔 두 모드가 같은 key를 씁니다. 적중률 38% -> 75%
   (남은 차이는 탐험 경로 분기). `Q_TABLE_VERSION` 2로 상승, 버전 1 table은 거부됩니다.

8. ~~**능력 선행 조건**~~: 완료. catalog가 trait을 선언하고, 능력이 `produces`/`requires`로
   의존을 표현합니다. 발견한 값은 argv 원소에 치환되며 anchor된 trait 패턴에 완전히
   일치해야 합니다. 11개 능력 / 8개 technique. beacon은 ID와 값만 전달하고 에이전트가
   자기 catalog로 재검증합니다. `LabPolicy.max_steps` 기본값 8 -> 12.

9. ~~**보상이 순서를 구분하지 못함**~~: 깊이 보상으로 해결. 능력마다 depth(선행 발견 사슬의
   길이)를 부여하고 `depth_weight * depth`를 보상에 더합니다. 총 보상은 여전히 집합
   함수지만, 할인된 수익은 순서에 따라 달라집니다.
   (그 과정에서 발견한 별개 버그 3개도 수정: 계획의 whitelist화, future 항의 전체 max,
   0 초기화.)

9-1. **RL이 최적에 도달하지 못함**: 2^11 부분집합 DP로 정확한 최적(7.8650)과 최악(7.2615,
   = catalog 순서)을 계산했습니다. 학습은 여지의 56.1%까지 갑니다(25000 에피소드, 여전히
   상승 중). 25000 시점에 "생산자 실행 후 곧바로 후속 수확" 세 쌍이 모두 올바르게
   짝지어집니다. 최적과의 차이는 앞의 표면 능력 두 개를 먼저 실행하는 것뿐입니다. 측정 장치(`optimal`/`range` DP)가 갖춰져 있으므로
   상태 표현이나 탐험 전략을 바꿔가며 비교할 수 있습니다.

   주의: 이전 문서에 있던 "59%에서 정체"는 틀린 수치였습니다. 무작위 300개 표본의 최고값을
   상한으로 삼았고(실제 최적이 아님), 시뮬레이션 출력이 능력 간에 줄을 공유해 보상을
   왜곡했습니다. 지금 수치는 실제 docker 실행 출력과 DP 최적 기준입니다.

10. **LICENSE 미정**: 아직 없습니다. 공개 저장소이므로 선택이 필요합니다.

## 7. 시작 전 확인 명령

```bash
cd /home/mintkangaroo/Project/AI_Security_Lab/Caldera_Lab
git status --short --branch
git log -3 --oneline
ruff check .
PYTHONPATH=src pytest -q
```

새 세션에서 기존 사용자 변경이 보이면 되돌리거나 덮어쓰지 말고 먼저 상태를 확인합니다.
