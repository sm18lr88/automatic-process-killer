@echo off
setlocal EnableExtensions DisableDelayedExpansion

REM ============================================================================
REM build.bat — Interactive build + sign (no external accounts required)
REM ----------------------------------------------------------------------------
REM A) Dev self-signed (no trust changes)   -> signed, but publisher untrusted (expected)
REM B) Self-signed + add trust (CurrentUser) -> installs to CurrentUser trust stores (prompt)
REM ============================================================================

set "EXE=pk.exe"
set "SRC=entry_point.c"
set "SUBJECT=CN=Win32ProcessKiller"
set "PFX=codesign.pfx"
set "CER=codesign.cer"
set "PFXPASS=StrongPfxPassword!"
set "DIGI_TS=http://timestamp.digicert.com"
set "SECTIGO_TS=http://timestamp.sectigo.com"

REM -- Tool checks -------------------------------------------------------------------------
where cl.exe        >nul 2>nul || (echo [ERROR] cl.exe not found. Use a VS Developer Command Prompt. & exit /b 1)
where signtool.exe  >nul 2>nul || (echo [ERROR] signtool.exe not found. Install Windows SDK/VS. & exit /b 1)
where powershell.exe>nul 2>nul || (echo [ERROR] PowerShell not found. & exit /b 1)

echo.
echo ========================= BUILD AND SIGN =========================
echo   Choose an option:
echo     [A] Dev self-signed  - no trust changes (safest; shows "Unknown Publisher")
echo     [B] Self-signed PLUS - add trust to Current User only (NOT for public)
echo     [X] Cancel
echo ================================================================
choice /C ABX /N /M "Select A, B, or X: "
set "SEL=%ERRORLEVEL%"

if "%SEL%"=="3" goto :cancel
if "%SEL%"=="2" set "MODE=WITH_TRUST" & goto :run
set "MODE=DEV_ONLY"

:run
call :build             || goto :fail
call :ensure_pfx        || goto :fail
if /I "%MODE%"=="WITH_TRUST" (
  call :warn_and_add_trust || goto :fail
)
call :sign_with_ts      || goto :fail
if /I "%MODE%"=="WITH_TRUST" (
  call :verify_strict   || goto :fail
) else (
  call :verify_relaxed
)
goto :end

REM ----------------------------------------------------------------------------
:build
echo === Building %EXE% ===
cl /nologo /O2 /W4 /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN "%SRC%" /Fe"%EXE%" /link /SUBSYSTEM:WINDOWS
if errorlevel 1 (echo [ERROR] Build failed.& exit /b 1)
exit /b 0

REM ----------------------------------------------------------------------------
:ensure_pfx
if exist "%PFX%" exit /b 0
echo === Creating self-signed Code Signing certificate DEV ===
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$cert = New-SelfSignedCertificate -Subject '%SUBJECT%' -Type CodeSigning -CertStoreLocation 'Cert:\CurrentUser\My' -HashAlgorithm 'sha256' -KeyExportPolicy Exportable; $pwd = ConvertTo-SecureString '%PFXPASS%' -AsPlainText -Force; Export-PfxCertificate -Cert $cert -FilePath '%PFX%' -Password $pwd | Out-Null"
if errorlevel 1 (echo [ERROR] Failed to create/export self-signed cert.& exit /b 1)
exit /b 0

REM ----------------------------------------------------------------------------
:warn_and_add_trust
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$c = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq '%SUBJECT%' } | Select-Object -First 1; if(-not $c){ throw 'Cert not found in CurrentUser\My: %SUBJECT%' }; Export-Certificate -Cert $c -FilePath '%CER%' | Out-Null"
if errorlevel 1 (echo [ERROR] Failed to export CER.& exit /b 1)

for /f "usebackq tokens=1" %%T in (`powershell -NoProfile -Command "(Get-ChildItem Cert:\CurrentUser\My ^| Where-Object { $_.Subject -eq '%SUBJECT%' } ^| Select-Object -First 1).Thumbprint"`) do set "THUMB=%%T"

echo.
echo ------------------- WARNING: Add Trust (Option B) -------------------
echo You are about to install a self-signed certificate into:
echo   - CurrentUser\Trusted Root Certification Authorities
echo   - CurrentUser\Trusted Publishers
echo Subject   : %SUBJECT%
echo Thumbprint: %THUMB%
echo
echo This grants trust to code signed with this certificate on THIS user profile only.
echo Do NOT use this for public distribution. Use a publicly trusted code-signing cert instead.
echo ---------------------------------------------------------------------
choice /C YN /N /M "Proceed with installing this certificate (Y/N)? "
if errorlevel 2 (echo Skipped trust installation.& exit /b 1)

where certutil.exe >nul 2>nul || (echo [ERROR] certutil.exe not found.& exit /b 1)
echo Adding to CurrentUser Trusted Root ...
certutil -user -addstore Root "%CER%" >nul
if errorlevel 1 (echo [ERROR] Failed adding to Trusted Root (user).& exit /b 1)

echo Adding to CurrentUser Trusted Publishers ...
certutil -user -addstore TrustedPublisher "%CER%" >nul
if errorlevel 1 (echo [ERROR] Failed adding to Trusted Publishers (user).& exit /b 1)
exit /b 0

REM ----------------------------------------------------------------------------
:sign_with_ts
echo === Signing %EXE% ===
signtool sign /fd SHA256 /tr "%DIGI_TS%" /td SHA256 /f "%PFX%" /p "%PFXPASS%" "%EXE%"
if errorlevel 1 (
  echo Timestamp ^(DigiCert^) failed. Trying Sectigo...
  signtool sign /fd SHA256 /tr "%SECTIGO_TS%" /td SHA256 /f "%PFX%" /p "%PFXPASS%" "%EXE%"
  if errorlevel 1 (
    echo Both TSAs failed. Signing without timestamp ...
    signtool sign /fd SHA256 /f "%PFX%" /p "%PFXPASS%" "%EXE%"
    if errorlevel 1 (echo [ERROR] Signing failed.& exit /b 1)
  )
)
exit /b 0

REM ----------------------------------------------------------------------------
:verify_relaxed
echo === Verify (DEV mode) ===
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$sig = Get-AuthenticodeSignature -FilePath '%EXE%';" ^
  "$status = $sig.Status.ToString();" ^
  "$explain = switch ($status) {" ^
  "  'Valid'          { 'Signature is valid.' }" ^
  "  'UntrustedRoot'  { 'Signed with a self-signed or untrusted root. Expected in DEV.' }" ^
  "  'NotTrusted'     { 'Signed, but signer not trusted on this machine. Expected in DEV.' }" ^
  "  'UnknownError'   { 'Signed; Windows could not fully validate the chain (often offline CRL/OCSP). Expected in DEV.' }" ^
  "  default          { 'Signed; status = ' + $status }" ^
  "};" ^
  "Write-Host ('Signature Status: ' + $status + ' — ' + $explain);" ^
  "if ($sig.SignerCertificate) { Write-Host ('Signer: ' + $sig.SignerCertificate.Subject) };" ^
  "$h = (Get-FileHash -Algorithm SHA256 -LiteralPath '%EXE%').Hash; Write-Host ('SHA256: ' + $h);"
exit /b 0

REM ----------------------------------------------------------------------------
:verify_strict
echo === Verify (WITH TRUST) ===
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$sig = Get-AuthenticodeSignature -FilePath '%EXE%';" ^
  "if ($sig.Status -ne 'Valid') { throw ('Signature not valid. Status: ' + $sig.Status) };" ^
  "Write-Host ('Signature Status: ' + $sig.Status);" ^
  "if ($sig.SignerCertificate) { Write-Host ('Signer: ' + $sig.SignerCertificate.Subject) };" ^
  "$h = (Get-FileHash -Algorithm SHA256 -LiteralPath '%EXE%').Hash; Write-Host ('SHA256: ' + $h);"
if errorlevel 1 (echo [ERROR] Validation failed.& exit /b 1)
exit /b 0

REM ----------------------------------------------------------------------------
:cancel
echo Cancelled.
goto :end

REM ----------------------------------------------------------------------------
:fail
echo [FAILED]
goto :end

:end
endlocal
exit /b 0
