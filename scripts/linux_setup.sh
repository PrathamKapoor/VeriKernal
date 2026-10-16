#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
VK_ROOT=$(pwd)
mkdir -p .tmp
export TEMP="$VK_ROOT/.tmp" TMP="$VK_ROOT/.tmp" TMPDIR="$VK_ROOT/.tmp" PYTHONDONTWRITEBYTECODE=1
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PIP_CACHE_DIR="$VK_ROOT/.tmp/pip-cache"
/usr/bin/python3 -m venv --without-pip --system-site-packages .venv
.venv/bin/python -m pip install blake3 dilithium-py
export PYTHONPATH="$VK_ROOT/src:$VK_ROOT"
if [ -f "$VK_ROOT/libverikernel_core.so" ]; then
    export VERIKERNEL_NATIVE_LIBRARY="$VK_ROOT/libverikernel_core.so"
fi
.venv/bin/python -m pytest -v
