.PHONY: setup test smoke run-demo serve-local lint bench cve-repro cve-test

setup:
	uv sync
	bash scripts/build_llamacpp.sh
	bash scripts/fetch_model.sh

test:
	uv run pytest -m "not smoke"

smoke:
	uv run pytest -m smoke

# 阶段 A 验收场景（依赖本地 llama.cpp 或 AGENT_GUARD_PROVIDER=ark）
run-demo:
	uv run python examples/scenarios/runner.py examples/scenarios/a_readme.yaml
	uv run python examples/scenarios/runner.py examples/scenarios/a_escape.yaml

serve-local:
	bash scripts/serve_local.sh

lint:
	uv run ruff check guard examples tests

# 阶段 D：跑对抗语料并产出指标报告
bench:
	uv run python scripts/bench.py

# CVE 复现（独立工作场景：专用策略/审计库/工作区，不影响默认测试）
cve-repro:
	uv run python scripts/cve_repro.py

cve-test:
	uv run pytest tests/test_cve_scenarios.py -v
