@echo off
cd /d "%~dp0"
if not exist .venv (py -3 -m venv .venv)
call .venv\Scripts\activate.bat
python -m pip install -r requirements.txt
if errorlevel 1 (echo Dependency installation failed. & pause & exit /b 1)
echo When the server starts, open http://127.0.0.1:8080 in your browser.
python run.py
pause
