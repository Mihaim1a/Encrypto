@echo off
setlocal
cd /d "%~dp0"
echo Encrypto verified frontend v2.1.1
where node >nul 2>&1
if errorlevel 1 (
  echo ERROR: Node.js 22 or newer is required.
  pause
  exit /b 1
)
if not exist "server\node_modules\express\package.json" (
  echo Installing backend dependencies ^(first run^)...
  call npm run setup
  if errorlevel 1 (
    echo Installation failed. Check the error above.
    pause
    exit /b 1
  )
)
echo Opening http://localhost:3000 with npm start.
echo If port 3000 is already in use, stop your OLD Encrypto server first.
call npm start
pause
