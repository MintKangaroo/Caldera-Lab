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

## 6. 다음 세션 우선순위

1. **에이전트 통신 계층**: 현재는 CLI가 Docker executor를 직접 호출합니다. 다음 단계로
   loopback 전용 heartbeat/result protocol을 추가하되, 외부 bind와 임의 command 전달은 금지합니다.
2. **LLM planner 계약 강화**: Responses API의 구조화 출력(JSON schema)을 사용하고, timeout·재시도·
   사용량 메타데이터를 감사 이벤트에 기록합니다.
3. **RL 학습 지속성**: 현재 Q table은 실행 프로세스 메모리에만 있습니다. 허용된 state/action만
   저장하는 버전 관리 가능한 JSON artifact와 재현성 테스트를 추가합니다.
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
