.PHONY: setup test smoke run-demo serve-local lint bench cve-repro cve-test

setup:
	uv sync
	bash scripts/build_llamacpp.sh
	bash scripts/fetch_model.sh

test:
	uv run pytest -m "not smoke"

smoke:
	uv run pytest -m smoke

# Demo 默认 Kimi 执行任务、DeepSeek 语义审计；.env 配置两个模型的密钥。
run-demo:
	uv run --env-file .env python examples/scenarios/runner.py examples/scenarios/a_readme.yaml
	uv run --env-file .env python examples/scenarios/runner.py examples/scenarios/a_escape.yaml

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
