@echo off
chcp 65001 >nul
setlocal
set "ROOT=%~dp0"
set "PY=%ROOT%.venv\Scripts\python.exe"

rem 优先复用项目内 .venv；没有就用 PATH 上的 python 建一个，避免装到全局环境。
if not exist "%PY%" (
  echo 创建项目虚拟环境 .venv ...
  python -c "import sys" >nul 2>nul
  if errorlevel 1 (
    echo 未找到可用的 Python，请安装 Python 3.12 并勾选 Add to PATH 后重试。
    pause
    exit /b 1
  )
  python -m venv "%ROOT%.venv"
)

echo 使用解释器：%PY%
"%PY%" -m pip install -r "%ROOT%requirements.txt"
pause
