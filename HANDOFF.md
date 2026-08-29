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
- 테스트 6개 -> 40개.

## 6. 다음 세션 우선순위

1. **에이전트 통신 계층**: 현재는 CLI가 Docker executor를 직접 호출합니다. 다음 단계로
   loopback 전용 heartbeat/result protocol을 추가하되, 외부 bind와 임의 command 전달은 금지합니다.
2. ~~**LLM planner 계약 강화**~~: 완료(5-1 참고). 실제 API 키로의 end-to-end 검증은 아직
   수행하지 않았습니다. 스텁 기반 테스트만 있습니다.
3. ~~**RL 학습 지속성**~~, ~~**보상 설계**~~: 완료(5-1 참고). 남은 것은 변동성 출력의
   정규화입니다.
4. **능력 catalog 확장**: 새로운 low-risk discovery 능력부터 추가하고 각 항목에 negative test,
   timeout test, Docker 실행 검증을 함께 추가합니다.
5. **대시보드 연동**: 현재 대시보드는 `make test`만 제공합니다. Caldera 전용 `run` action과
   `.runtime/run.jsonl` 로그 표시를 추가할지 검토합니다.
6. **CI Docker smoke test**: GitHub Actions에서 이미지 빌드와 최소 1개 능력 실행을 추가합니다.

## 7. 시작 전 확인 명령

```bash
cd /home/mintkangaroo/Project/AI_Security_Lab/Caldera_Lab
git status --short --branch
git log -3 --oneline
ruff check .
PYTHONPATH=src pytest -q
```

새 세션에서 기존 사용자 변경이 보이면 되돌리거나 덮어쓰지 말고 먼저 상태를 확인합니다.
