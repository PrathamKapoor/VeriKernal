$VeriKernelRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $VeriKernelRoot
New-Item -ItemType Directory -Force -Path "$VeriKernelRoot\.tmp", "$VeriKernelRoot\.venv" | Out-Null
$env:TEMP = "$VeriKernelRoot\.tmp"
$env:TMP = $env:TEMP
$env:TMPDIR = $env:TEMP
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:PIP_CACHE_DIR = "$VeriKernelRoot\.tmp\pip-cache"
$env:CARGO_HOME = "$VeriKernelRoot\dist\development\cargo"
$env:RUSTUP_HOME = "$VeriKernelRoot\dist\development\rustup"
$env:CARGO_TARGET_DIR = "$VeriKernelRoot\dist\build-target"
$env:XDG_CACHE_HOME = "$VeriKernelRoot\.tmp\cache"
$env:GIT_CONFIG_GLOBAL = "$VeriKernelRoot\.tmp\gitconfig"
$env:PYTHONPATH = "$VeriKernelRoot\src;$VeriKernelRoot"
$env:PATH = "$VeriKernelRoot\dist\development\cargo\bin;" + $env:PATH
