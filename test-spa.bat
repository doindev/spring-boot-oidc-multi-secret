@echo off
echo Starting SPA Test Demo...
echo.
echo This will demonstrate the SPA forwarding behavior.
echo.
echo Configuration:
echo - spa.enabled=true
echo - spa.not-found-url=/not-found?page={notFoundUrl}
echo - security.type=none
echo.
echo Starting Spring Boot application...
start /B mvn spring-boot:run -Dspring-boot.run.arguments="--spa.enabled=true --spa.not-found-url=/not-found?page={notFoundUrl} --security.type=none"

echo.
echo Waiting for application to start (15 seconds)...
timeout /t 15 /nobreak > nul

echo.
echo Testing URLs:
echo.
echo 1. Testing home page (should work):
curl -s -o nul -w "   GET / : HTTP Status %%{http_code}\n" http://localhost:8080/

echo.
echo 2. Testing non-existent path (should forward to /not-found and return 200):
curl -s -o nul -w "   GET /products : HTTP Status %%{http_code}\n" http://localhost:8080/products

echo.
echo 3. Testing API path (should return 404):
curl -s -o nul -w "   GET /api/users : HTTP Status %%{http_code}\n" http://localhost:8080/api/users

echo.
echo 4. Testing static resource (should return 404):
curl -s -o nul -w "   GET /unknown.js : HTTP Status %%{http_code}\n" http://localhost:8080/unknown.js

echo.
echo 5. Testing direct access to /not-found:
curl -s -o nul -w "   GET /not-found?page=/test : HTTP Status %%{http_code}\n" "http://localhost:8080/not-found?page=/test"

echo.
echo Test complete. Press any key to stop the application...
pause > nul

echo.
echo Stopping application...
tasklist /FI "WINDOWTITLE eq spring-boot-oidc-multi-secret*" | findstr /i "java.exe" > nul
if %errorlevel% equ 0 (
    for /f "tokens=2" %%a in ('tasklist /FI "WINDOWTITLE eq spring-boot-oidc-multi-secret*" ^| findstr /i "java.exe"') do (
        taskkill /PID %%a /F > nul 2>&1
    )
)

:: Alternative method to kill Java processes
for /f "tokens=2" %%i in ('jps -l ^| findstr "spring-boot"') do (
    taskkill /PID %%i /F > nul 2>&1
)

echo Application stopped.