.PHONY: check test lint run

test:
	PYTHONPATH=src python3 -m pytest

lint:
	python3 -m ruff check .

check: lint test

run:
	PYTHONPATH=src python3 -m caldera_lab run --executor dry-run --planner hybrid --steps 4
