# API PRIVACY GUARD - setup local (sem privilégio administrativo)
# Apenas cria .venv, instala dependências e inicializa arquivo de configuração.
$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot
Write-Host '=== API PRIVACY GUARD MVP v0.1 ==='
py -3 -c "import sys; assert sys.version_info >= (3,11), 'Python 3.11+ required'; print(sys.version)"
if ($LASTEXITCODE -ne 0) { throw 'Instale Python 3.11 ou superior.' }
if (-not (Test-Path '.venv\Scripts\python.exe')) {
    py -3 -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw 'Falha ao criar ambiente virtual.' }
}
& '.\.venv\Scripts\python.exe' -m pip install -e '.[test]'
if ($LASTEXITCODE -ne 0) { throw 'Falha ao instalar dependencias.' }
$configPath = Join-Path $env:LOCALAPPDATA 'APIPrivacyGuard\config.json'
if (-not (Test-Path $configPath)) {
    & '.\.venv\Scripts\python.exe' -m api_privacy_guard.cli init
    if ($LASTEXITCODE -ne 0) { throw 'Falha ao criar configuracao.' }
} else {
    Write-Host 'Configuracao existente preservada.'
}
& '.\.venv\Scripts\python.exe' -m pytest -q
if ($LASTEXITCODE -ne 0) { throw 'Os testes locais falharam.' }
Write-Host 'Instalacao concluida. Os perfis de exemplo continuam DESABILITADOS.'
Write-Host "Abra: $configPath"
Write-Host 'Leia README.md antes de conectar qualquer IDE ou credencial.'
