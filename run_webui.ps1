param(
    [int]$Port = 8765,
    [string]$BindAddress = "127.0.0.1",
    [switch]$Reload,
    [switch]$OpenBrowser
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

# Resolve the interpreter at runtime instead of hard-coding install paths:
# project venv first, then a real Python on PATH, then the bundled
# codex-runtimes runtime. The WindowsApps python.exe stub is skipped because it
# only opens the Microsoft Store.
$venvPython = Join-Path $projectRoot ".venv\Scripts\python.exe"
$pathPython = (Get-Command python.exe -ErrorAction SilentlyContinue | Select-Object -First 1).Source
if ($pathPython -like "*\WindowsApps\*") { $pathPython = $null }
$bundledPython = Join-Path $HOME ".cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
$python = if (Test-Path -LiteralPath $venvPython) { $venvPython }
          elseif ($pathPython) { $pathPython }
          elseif (Test-Path -LiteralPath $bundledPython) { $bundledPython }
          else { $null }

if (-not $python) {
    throw "Python not found. Install Python 3.12, or run: python -m venv .venv"
}

Set-Location -LiteralPath $projectRoot
$env:PYTHONPATH = $projectRoot

# QuickJS sentinel path needs node; it only affects OTP retrieval during
# registration, not WebUI startup.
$pathNode = (Get-Command node.exe -ErrorAction SilentlyContinue | Select-Object -First 1).Source
$bundledNode = Join-Path $HOME ".cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe"
$node = if ($pathNode) { $pathNode } elseif (Test-Path -LiteralPath $bundledNode) { $bundledNode } else { $null }
if ($node) { $env:OPENAI_SENTINEL_NODE_PATH = $node }

$args = @("start_webui.py", "--host", $BindAddress, "--port", "$Port")
if (-not $OpenBrowser) { $args += "--no-browser" }
if ($Reload) { $args += "--reload" }

& $python @args
exit $LASTEXITCODE
