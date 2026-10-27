# Puente PRTG

Lleva el estado de PRTG al mapa de Heimdall en tiempo real, **solo lectura**.

- Cada 5 s hace una sola consulta a PRTG: la lista de sensores con problema (caídos, advertencia). Cada 10 min, la lista de equipos. Nada más; no edita, reconoce ni pausa nada.
- Cifra el estado con la clave del sitio (la misma que abre el login) y lo sirve por un túnel de Cloudflare de salida. No se abre ningún puerto en el router.
- Anuncia la dirección del túnel, cifrada, en ntfy.sh. El mapa la encuentra solo.

## Instalar en Windows

1. Node.js 20 o superior (`winget install OpenJS.NodeJS.LTS`).
2. Variables de usuario, una vez (nunca en archivos del repo):
   ```
   setx PRTG_USUARIO "usuario-de-prtg"
   setx PRTG_PASSWORD "..."
   setx HEIMDALL_USUARIO "tu-usuario-de-heimdall"
   setx HEIMDALL_CONTRASENA "..."
   ```
   Lo ideal es un usuario de PRTG propio, de solo lectura (por ejemplo `heimdall`).
3. Cierra y abre PowerShell, y ejecuta `powershell -ExecutionPolicy Bypass -File instalar.ps1`.

Queda como la tarea programada **Heimdall Puente**: arranca al iniciar sesión, sin ventana, y se reinicia si se cierra. El registro está en `puente.log`.

## Avisos por Telegram

1. En Telegram, habla con **@BotFather**, envía `/newbot` y sigue los pasos. Te da un **token**.
2. Abre tu bot nuevo y envíale `/start`.
3. En la PC: `setx TELEGRAM_TOKEN 'tu_token'`. El número de chat se obtiene con `https://api.telegram.org/bot<token>/getUpdates` (campo `chat.id`) y se guarda con `setx TELEGRAM_CHAT_ID '123456789'` (varios separados por coma). Reinicia el puente.

## Avisos por WhatsApp

Con [CallMeBot](https://www.callmebot.com/blog/free-api-whatsapp-messages/) (gratis, solo a tu propio número):

1. Guarda el número de CallMeBot en tus contactos y mándale `I allow callmebot to send me messages`. Te responde con tu apikey.
2. En la PC: `setx WHATSAPP_TELEFONO '+1809XXXXXXX'` y `setx WHATSAPP_APIKEY 'tu_apikey'`, y reinicia el puente.

Avisa cuando un sensor cae o se recupera (tras 2 lecturas seguidas, para no avisar por parpadeos), cuando un servicio de internet importante falla y cuando PRTG deja de responder. Agrupa los avisos: como mucho un mensaje cada 30 s.

## Backups de los switches (Drive)

Cada nodo del mapa muestra el backup de su switch. El puente lee la carpeta de Drive cada 30 min (solo los nombres, nunca abre los archivos) y asocia cada archivo por la IP que lleva en el nombre, por ejemplo `COPEY 10.9.9.63.txt`. Se pueden usar subcarpetas por mes.

1. Comparte la carpeta con "Cualquier persona con el enlace" (lector).
2. En PowerShell: `setx DRIVE_RESPALDOS 'id-o-enlace-de-la-carpeta'`
3. Reinicia el puente.

## Opciones

| Variable | Por defecto |
|---|---|
| `PRTG_URL` | `https://168.196.125.68` |
| `INTERVALO_SEGUNDOS` | `5` |
| `HEIMDALL_SITIO` | `https://demberos.github.io` |
| `PUERTO` | `8787` (solo en la PC, 127.0.0.1) |
