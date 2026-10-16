PYTHON ?= python
ROOT := $(abspath .)
export TEMP := $(ROOT)/.tmp
export TMP := $(ROOT)/.tmp
export TMPDIR := $(ROOT)/.tmp
export PYTHONDONTWRITEBYTECODE := 1
export PIP_CACHE_DIR := $(ROOT)/.tmp/pip-cache
export CARGO_HOME := $(ROOT)/dist/development/cargo
export CARGO_TARGET_DIR := $(ROOT)/dist/build-target
export PYTHONPATH := $(ROOT)/src:$(ROOT)

.PHONY: prepare install test rust-test native probes bench verify
prepare:
	$(PYTHON) -c "from pathlib import Path; Path('.tmp').mkdir(exist_ok=True)"
install: prepare
	$(PYTHON) -m pip install -e ".[test]"
test: prepare
	$(PYTHON) -m pytest -v
rust-test: prepare
	cargo test --workspace
native: prepare
	$(PYTHON) scripts/build_native.py
probes: prepare
	$(PYTHON) scripts/build_probes.py --output .tmp/verikernel_probes.bpf.o
bench: prepare
	$(PYTHON) -m benchmarks.run_benchmarks
verify: native test
