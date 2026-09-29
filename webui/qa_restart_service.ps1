$ErrorActionPreference = "Continue"
$projectRoot = "C:\Users\Administrator\Documents\ChatGPT\zc\gpt-reg-review"
$listener = Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue
if ($listener) {
    Stop-Process -Id $listener.OwningProcess -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}
$proc = Start-Process -FilePath "powershell.exe" -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", (Join-Path $projectRoot "run_webui.ps1")) -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru
Write-Output ("launcher PID: " + $proc.Id)
