FROM rust:1.90-bookworm AS rust
FROM python:3.12-bookworm
WORKDIR /workspace/VeriKernel
COPY --from=rust /usr/local/cargo .cargo
COPY --from=rust /usr/local/rustup .rustup
ENV TEMP=/workspace/VeriKernel/.tmp \
    TMP=/workspace/VeriKernel/.tmp \
    TMPDIR=/workspace/VeriKernel/.tmp \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_CACHE_DIR=/workspace/VeriKernel/.tmp/pip-cache \
    CARGO_HOME=/workspace/VeriKernel/.cargo \
    RUSTUP_HOME=/workspace/VeriKernel/.rustup \
    CARGO_TARGET_DIR=/workspace/VeriKernel/.tmp/target \
    PATH=/workspace/VeriKernel/.venv/bin:/workspace/VeriKernel/.cargo/bin:$PATH
COPY . .
RUN mkdir -p .tmp && python -m venv .venv
RUN .venv/bin/python -m pip install '.[test,native]'
RUN .venv/bin/python scripts/build_native.py && .venv/bin/python -m pytest -v
CMD ["python", "-m", "verikernel.cli.main", "--help"]
