# Guía de uso rápida

LassiNet es una consola de visibilidad y respuesta para **tu propia LAN**.
No es un IPS/IDS enterprise, no sustituye a Suricata/Zeek y no está pensada
para escanear redes de terceros.

> **Regla de oro:** modo live solo en una red que controlas. En el colegio,
> una Wi-Fi pública o una red de cliente, usa demo o pide autorización escrita.

---

## 0. Instalación de un clic

**Windows**

```powershell
git clone https://github.com/bryanherflo/lassinet.git
cd lassinet
.\install.bat
```

**Linux / macOS**

```bash
git clone https://github.com/bryanherflo/lassinet.git
cd lassinet
bash install.sh
```

El instalador crea `.env` con tokens aleatorios de operator/viewer, lanza la app y abre el navegador cuando `/healthz` responde. En Windows también crea un acceso directo. **Guarda los tokens** que imprime; `.env` está en `.gitignore`. Si ya existe `.env`, no lo sobrescribe. Para Android, el servidor sigue en el PC/Raspberry Pi y el móvil es el cliente; ver la sección 12.

---

## 1. Arranque en 1 minuto (demo, sin red real)

```powershell
git clone https://github.com/bryanherflo/lassinet.git
cd lassinet
python run.py
```

Abre **http://127.0.0.1:8000**.

- La primera vez crea `.venv`, instala dependencias y entrena el modelo demo.
- No captura tráfico, no escanea, no toca el firewall.
- En Windows también puedes usar `start.bat`; en Linux/macOS, `bash start.sh`.

Si prefieres gestionar tú el entorno:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

---

## 2. Antes de usar live: LassiVet

```powershell
python -m lassi.vet
python -m lassi.vet --json --report pilot.md
```

Revisa, **sin capturar ni escanear**:

- que tu IP esté dentro de `LASSI_LIVE_ALLOW`;
- tokens y `LASSI_SECRET`;
- firewall y privilegios;
- ruta de Suricata EVE;
- webhook;
- disco, backups y cadena de auditoría.

`FAIL` = no arranques live. `WARN` = decisión consciente.

---

## 3. Live monitor-only (recomendado para empezar)

Sustituye el CIDR por **tu** red:

```powershell
$env:LASSI_MODE="live"
$env:LASSI_LIVE_ALLOW="192.168.0.0/24"
$env:LASSI_DRY_RUN="1"          # registra, no bloquea
$env:LASSI_FW="mock"            # sin reglas reales
$env:LASSI_AUTO_BLOCK="0"
$env:LASSI_TOKEN_OPERATOR="<token-largo-y-aleatorio>"
$env:LASSI_TOKEN_VIEWER="<otro-token-largo>"
$env:LASSI_SECRET="<secreto-largo>"
python run.py --live
```

Linux/macOS:

```bash
LASSI_MODE=live \
LASSI_LIVE_ALLOW=192.168.0.0/24 \
LASSI_DRY_RUN=1 LASSI_FW=mock LASSI_AUTO_BLOCK=0 \
LASSI_TOKEN_OPERATOR='<random>' LASSI_TOKEN_VIEWER='<random>' LASSI_SECRET='<random>' \
python run.py --live
```

Notas:

- **Live exige `LASSI_LIVE_ALLOW`**; sin él se niega a arrancar. `LASSI_LIVE_ALLOW_ANY=1` es solo para un laboratorio explícito.
- `LASSI_DRY_RUN=1` mantiene el firewall en mock aunque pongas `LASSI_FW=windows`.
- `LASSI_PASSIVE=1` observa sin ARP ni probes de puertos (mapa menos completo).
- `LASSI_AUTO_BLOCK=0` es el default en live; no lo subas hasta validar.
- En Windows live necesitas Npcap y permisos de captura; para reglas reales, Administrador.

---

## 4. Entrar al panel

Abre **http://127.0.0.1:8000**.

- Si configuraste tokens, aparece el modal **Sign in**.
- `LASSI_TOKEN_OPERATOR`: puede bloquear, desbloquear, confiar, renombrar, hacer triage y descartar.
- `LASSI_TOKEN_VIEWER`: solo lectura.
- El token se cambia por una cookie de sesión; no se guarda en el navegador.
- Si actualizas la UI, pulsa **Ctrl+F5**.

Si no ves el panel: comprueba `python -m lassi.vet`, el puerto y `/healthz`.

---

## 5. Uso básico del panel

### Mapa

- Cada nodo es un dispositivo; el color del anillo indica estado/tipo.
- **Click** selecciona y abre la barra de acciones.
- **Click derecho** abre el menú de confianza.
- **Doble click** renombra.
- `B` bloquea el seleccionado; `R` reencuadra; `M` minimiza; `L` leyenda; `D` puntos; `/` busca; `?` ayuda.

### Alertas

- Cada tarjeta muestra severidad, origen → destino, motor y confianza.
- **Block source** bloquea el **origen**, nunca la víctima.
- **Ack / False positive / Reopen / Note** guarda el triage en SQLite.
- **×** descarta la tarjeta; el log de auditoría conserva el evento.
- El router, Internet, este PC, `LASSI_PROTECT` y los dispositivos de confianza **nunca** se bloquean.

### Firewall

- Con `LASSI_DRY_RUN=1` o `LASSI_FW=mock`, los bloqueos se **registran pero no se aplican**.
- Para respuesta real: `LASSI_FW=opnsense`, `windows` o `nftables`, sin dry-run.
- Prueba primero con una IP de laboratorio (`203.0.113.x`) y verifica que la regla aparece y se retira.
- Los auto-bloqueos expiran con `LASSI_AUTO_BLOCK_TTL` (1 h por defecto); los manuales aceptan `ttl_s` por API.

---

## 6. Webhooks (avisos)

Slack:

```powershell
$env:LASSI_WEBHOOK_URL="https://hooks.slack.com/services/..."
$env:LASSI_WEBHOOK_FORMAT="slack"
$env:LASSI_WEBHOOK_MIN_SEVERITY="high"
```

- También `teams`, `discord` y `generic`.
- Solo envía tarjetas nuevas; no repite las colapsadas.
- Cola acotada: un webhook caído no bloquea la captura.
- HTTPS por defecto; HTTP solo con `LASSI_WEBHOOK_ALLOW_HTTP=1` en laboratorio.
- La URL es un secreto; el payload contiene IPs y firmas internas.

---

## 7. Suricata y sensores remotos

### Suricata en el mismo host

```powershell
$env:LASSI_SURICATA_EVE="C:\suricata\eve.json"
```

Las alertas EVE aparecen con motor `suricata`. **No auto-bloquean.**

### Sensor en otro segmento

Central:

```powershell
$env:LASSI_SENSOR_TOKEN="<token-largo-compartido>"
```

Agente (junto al EVE del segmento):

```powershell
$env:LASSI_SENSOR_URL="https://lassinet.example/api/v1/ingest/alerts"
$env:LASSI_SENSOR_TOKEN="<el-mismo-token>"
$env:LASSI_SENSOR_ID="office-1"
$env:LASSI_SENSOR_EVE="C:\suricata\eve.json"
python -m lassi.sensor_agent
```

- Reenvía **alertas**, no paquetes.
- El token de sensor no puede leer ni bloquear.
- Si el central cae, guarda en `data/sensor_spool.jsonl` y reintenta.
- Para todo el tráfico de un segmento necesitas SPAN/mirror + Suricata allí.

---

## 8. API v1 rápida

```powershell
$h=@{Authorization="Bearer $env:LASSI_TOKEN_OPERATOR"}

Invoke-RestMethod http://127.0.0.1:8000/api/v1/version -Headers $h
Invoke-RestMethod "http://127.0.0.1:8000/api/v1/alerts?severity=high&status=open&limit=20" -Headers $h
Invoke-RestMethod http://127.0.0.1:8000/api/v1/sensors -Headers $h
Invoke-RestMethod http://127.0.0.1:8000/api/v1/audit/verify -Headers $h
```

- Lecturas paginadas/filtrables; escrituras en `/api/v1/firewall/*`, `/alerts/*`, `/devices/*`.
- Requiere operador para escribir; viewer solo lee.
- El dashboard sigue usando `/api/*`; v1 es la superficie estable.

---

## 9. Backup, auditoría y actualización

```powershell
python -m lassi.backup create
python -m lassi.backup verify backups\lassinet-....zip
python -m lassi.backup restore backups\lassinet-....zip --target C:\restore-lassinet

curl http://127.0.0.1:8000/api/logs/verify
curl -X POST http://127.0.0.1:8000/api/logs/checkpoint
```

- El backup incluye `data/` y `logs/`, con checksums; `.env` es opt-in porque contiene secretos.
- Restaura siempre en un directorio nuevo primero.
- La cadena de auditoría detecta ediciones/inserciones; un prefijo/sufijo borrado o una reescritura completa necesitan una copia externa.
- Guarda `LASSI_CHECKPOINT_KEY` fuera del sensor y copia el checkpoint.

Actualizar:

```powershell
git pull
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -q
```

---

## 10. Seguridad mínima

- No expongas el panel directamente a Internet.
- `LASSI_HOST=127.0.0.1` + Caddy/Nginx/TLS delante.
- Tokens largos y distintos para operator/viewer; `LASSI_SECRET` estable.
- Para OIDC, usa Authelia/oauth2-proxy y `LASSI_PROXY_AUTH=1` con `LASSI_PROXY_AUTH_SECRET`; no inventes un cliente OIDC dentro de la app.
- No actives auto-bloqueo ni firewall real hasta validar 24–48 h en monitor-only.
- No ejecutes live en el colegio ni en redes de terceros.
- No subas `.env`, backups, logs ni capturas reales al repo.

---

## 11. Problemas típicos

| Síntoma | Qué mirar |
|---|---|
| “live mode refused” | `LASSI_LIVE_ALLOW` no contiene tu IP; ejecuta LassiVet |
| `capture_error` / readyz 503 | scapy/Npcap, permisos, `LASSI_IFACE` |
| Firewall “mock” | es esperado en demo/dry-run; no hay reglas reales |
| No llegan webhooks | URL HTTPS, formato, severidad, `/metrics` |
| Alertas remotas no aparecen | token de sensor, URL, EVE, agent logs |
| Panel vacío tras actualizar | Ctrl+F5 y `/healthz` |
| Log no verifica | línea parcial/tamper, retención o checkpoint; exporta antes de tocar |

---

## 12. Android (PWA)

LassiNet no es un APK ni está en Play Store: es una **PWA**. El sensor sigue en el PC/Raspberry Pi; el móvil solo muestra el panel.

### Misma Wi-Fi (solo laboratorio)

1. En el PC: `$env:LASSI_HOST="0.0.0.0"` (o usa Tailscale), configura tokens y arranca `python run.py`.
2. Permite el puerto 8000 **solo** en tu LAN.
3. En Chrome Android abre `http://IP-DEL-PC:8000` e inicia sesión con el token.
4. Menú de Chrome → **Añadir a pantalla de inicio**. En HTTP simple será un acceso directo, sin prompt PWA, service worker ni shell offline; los navegadores exigen HTTPS para eso.

### PWA completa (HTTPS, recomendado)

- **Tailscale** en PC y móvil + Tailscale Serve: URL HTTPS privada sin abrir el puerto a Internet.
- **Cloudflare Tunnel** para una URL HTTPS temporal; es pública, así que usa tokens fuertes y no la dejes abierta.
- Caddy/Nginx con TLS local también funciona, pero Android debe confiar en la CA.
- Con HTTPS, Chrome muestra **Install app** y el botón del header. El service worker cachea **solo** el shell estático: nunca API, alertas, logs, `/metrics` ni el WebSocket.
- El móvil no captura tráfico; no hay notificaciones push nativas ni app de Play Store. Una TWA/APK sería un proyecto aparte.

Detalles y comandos: [docs/android.md](docs/android.md).

---

## 13. Historial de flows

LassiNet guarda un **historial de flows** en SQLite: `data/flows.db`. Un flow es una conversación agregada entre una IP origen y una IP destino durante una ventana de 10 s; se guardan contadores y veredicto, **nunca el contenido de los paquetes**.

Pulsa **Flows** en la cabecera o la tecla `F`. El panel tiene tres vistas:

- **Flows**: buscar por IP, nombre o veredicto; filtrar con **All / Benign / Attacks**; seleccionar un flow para ver origen, destino, rol/tipo de cada dispositivo, protocolos, puertos, paquetes, bytes, duración, SYN, packet rate y veredicto.
  - El botón **Flows** de la barra de un dispositivo abre el historial filtrado por esa IP.
  - El botón **Flows** de una alerta abre el mismo origen/destino en una ventana de **±5 minutos**.
- **Top talkers**: ranking de dispositivos por bytes y flows en **15 min / 1 h / 24 h**. Muestra **↑ out** (como origen) y **↓ in** (como destino), además del total combinado. Al pulsar un dispositivo vuelves a sus flows.
- **Timeline**: flows por minuto con marcas de alertas y bloqueos para **1 h / 6 h / 24 h**. Los eventos se guardan en SQLite (`flow_events`) y se rellenan desde el log de auditoría una vez; ya no dependen de las 200 alertas / 50 reglas en memoria.

En el pie tienes el uso del historial —filas, tamaño de la base, retención y tope—, **Export CSV** con los filtros actuales y **Clear history** (solo operator; pide confirmación y queda auditado). Clear borra filas y eventos sin `VACUUM`, así que es rápido, aunque el archivo SQLite puede no encogerse de inmediato. Los flows anteriores a la captura de puertos muestran `not recorded`; no se pueden reconstruir.

Los dispositivos que ya no están en el mapa salen como `not on current map`. Retención por defecto: **72 h** y **1.000.000 filas**; se puede ajustar con `LASSI_FLOW_RETENTION_HOURS`, `LASSI_FLOW_MAX_ROWS`, `LASSI_FLOW_DB` o desactivar con `LASSI_FLOW_HISTORY=0`. El historial contiene IPs y nombres: trátalo como dato sensible y no lo subas al repositorio.

---

## 14. Para profundizar

- [Arquitectura](docs/architecture.md)
- [API v1](docs/api-v1.md)
- [Sensores remotos](docs/remote-sensors.md)
- [OIDC / proxy](docs/oidc.md)
- [Despliegue](docs/deployment.md)
- [Android (PWA)](docs/android.md)
- [Runbook](docs/runbook.md)
- [Threat model](docs/threat-model.md)
- [Límites reales](docs/benchmarks.md)

**No es** HA, gigabit, SOC 24/7 ni cumplimiento formal. Es una consola útil
para una LAN pequeña, con Suricata/OPNsense como piezas serias alrededor.
