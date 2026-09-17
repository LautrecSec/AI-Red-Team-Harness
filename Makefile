.PHONY: install test lint demo docker-build
install:
	python -m pip install -e .[dev]

test:
	pytest --cov=redteam_harness

lint:
	ruff check .
	mypy redteam_harness

demo:
	redteam run config/campaign.example.yaml --output-dir results

docker-build:
	docker build -t ai-redteam-harness:local -f docker/Dockerfile .
