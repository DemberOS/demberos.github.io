# Heimdall · instala el puente PRTG en esta PC (Windows)
# Uso: clic derecho > "Ejecutar con PowerShell", o:  powershell -ExecutionPolicy Bypass -File instalar.ps1
#      -SiempreActivo: corre al encender la PC aunque no haya sesión iniciada (necesita administrador; no pide contraseñas)
# No guarda contraseñas en archivos: las lee de las variables de entorno del usuario.
param([switch]$SiempreActivo)
$ErrorActionPreference = "Stop"
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Host "Heimdall · instalando el puente PRTG en $dir" -ForegroundColor Cyan

# 1. Node.js 20 o superior
$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) { throw "Falta Node.js. Instálalo con:  winget install OpenJS.NodeJS.LTS  y vuelve a ejecutar este script." }
$ver = [int]((node -v).TrimStart("v").Split(".")[0])
if ($ver -lt 20) { throw "Node.js $ver es muy viejo; hace falta 20 o superior (winget upgrade OpenJS.NodeJS.LTS)." }
Write-Host "  Node.js $(node -v) OK"

# 2. cloudflared (túnel de salida, sin abrir puertos)
$cf = Join-Path $dir "cloudflared.exe"
if (-not (Test-Path $cf)) {
  Write-Host "  Descargando cloudflared..."
  Invoke-WebRequest "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe" -OutFile $cf -UseBasicParsing
}
Write-Host "  cloudflared OK"

# 3. Variables (solo se comprueba que existan; no se muestran)
$faltan = @()
foreach ($v in "PRTG_USUARIO", "PRTG_PASSWORD", "HEIMDALL_USUARIO", "HEIMDALL_CONTRASENA") {
  if (-not [Environment]::GetEnvironmentVariable($v, "User") -and -not (Test-Path (Join-Path $dir ".env"))) { $faltan += $v }
}
if ($faltan.Count) {
  Write-Host "Faltan estas variables. Créalas con setx (una por línea) y vuelve a ejecutar:" -ForegroundColor Yellow
  $faltan | ForEach-Object { Write-Host "  setx $_ `"...`"" }
  exit 1
}
Write-Host "  Variables OK"

# 4. Tarea programada: arranca al iniciar sesión, oculta, y se reinicia sola
$nombre = "Heimdall Puente"
Get-ScheduledTask -TaskName $nombre -ErrorAction SilentlyContinue | ForEach-Object {
  Stop-ScheduledTask -TaskName $nombre -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $nombre -Confirm:$false
}
Get-CimInstance Win32_Process -Filter "Name='node.exe'" | Where-Object { $_.CommandLine -like "*puente.mjs*" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
$accion = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "`"$(Join-Path $dir 'iniciar.vbs')`"" -WorkingDirectory $dir
$ajustes = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
$desc = "Lee PRTG en solo lectura y alimenta el mapa de Heimdall"
$normal = { Register-ScheduledTask -TaskName $nombre -Action $accion -Trigger (New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME) -Settings $ajustes -Description $desc | Out-Null }
if ($SiempreActivo) {
  # S4U: Windows la ejecuta con esta cuenta sin guardar su contraseña (solo accede a la red sin credenciales de Windows, que es lo que hace falta)
  try {
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType S4U -RunLevel Limited
    Register-ScheduledTask -TaskName $nombre -Action $accion -Trigger (New-ScheduledTaskTrigger -AtStartup) -Settings $ajustes -Principal $principal -Description $desc | Out-Null
    # Que la PC no se duerma enchufada (si duerme, el mapa se queda sin datos)
    powercfg /change standby-timeout-ac 0
    powercfg /change hibernate-timeout-ac 0
    Write-Host "  Modo siempre activo: arranca al encender la PC, sin sesión iniciada, y la PC no se suspende enchufada"
  } catch {
    Write-Host "  No se pudo activar el modo siempre activo: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "  Se deja en modo normal (arranca al iniciar sesión)."
    & $normal
  }
} else {
  & $normal
}
Start-ScheduledTask -TaskName $nombre
Write-Host "  Tarea '$nombre' creada e iniciada"

Start-Sleep -Seconds 12
$log = Join-Path $dir "puente.log"
if (Test-Path $log) { Write-Host "`nÚltimas líneas del registro:" -ForegroundColor Cyan; Get-Content $log -Tail 8 }
Write-Host "`nListo. Para detenerlo: Stop-ScheduledTask '$nombre'  ·  Para quitarlo: Unregister-ScheduledTask '$nombre'" -ForegroundColor Green
