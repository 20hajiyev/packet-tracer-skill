param(
    [string]$VenvPath = ".venv",
    [switch]$Dev
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $VenvPath)) {
    python -m venv $VenvPath
}

$python = Join-Path $VenvPath "Scripts\\python.exe"
if (-not (Test-Path $python)) {
    throw "Virtual environment python not found at $python"
}

& $python -m pip install --upgrade pip
& $python -m pip install -r "requirements.txt"

if ($Dev) {
    & $python -m pip install -r "requirements-dev.txt"
}

Write-Output "Setup complete."
Write-Output "Venv python: $python"
Write-Output "If you use Packet Tracer 9.x encoding/decoding, also set PKT_TWOFISH_LIBRARY or PKT_TWOFISH_SEARCH_ROOTS."
Write-Output "Run python .\scripts\runtime_doctor.py to verify donor, Packet Tracer path, and Twofish readiness."
