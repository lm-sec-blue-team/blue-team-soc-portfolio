# SOC250 — APT35 HyperScrape Data Exfiltration Tool Detected

**Plataforma:** LetsDefend  
**Categoría:** Data Leakage / APT  
**Dificultad:** Media  
**Fecha de resolución:** 2023-12-27  
**Técnicas MITRE ATT&CK:**
- [T1589 — Gather Victim Identity Information](https://attack.mitre.org/techniques/T1589/)
- [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [T1539 — Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
- [T1114 — Email Collection](https://attack.mitre.org/techniques/T1114/)
- [T1041 — Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)

**Tácticas MITRE:** Reconnaissance · Initial Access · Credential Access · Collection · Exfiltration


## 🧩 Contexto del caso

> Alerta por ejecución de un binario vinculado a HyperScrape, la herramienta de exfiltración de correo asociada a APT35 (Charming Kitten), grupo de ciberespionaje patrocinado por Irán. El proceso se ejecutó en el host Arthur tras un acceso RDP previo desde una IP externa.

**Tipo de alerta:** SOC250 — APT35 HyperScrape Data Exfiltration Tool Detected  
**Severidad inicial:** Medium  
**Event ID:** 212  
**Fecha y hora del evento:** Dec 25, 2023 — 11:22 AM

**Activos implicados:**
- Host: `Arthur` (IP: `172.16.17.72`)
- Usuario: `EC2AMAZ-ILGVOIN\Arthur` / `arthur@letsdefend.io`
- Proceso sospechoso: `EmailDownloader.exe` (`C:\Users\LetsDefend\Downloads\EmailDownloader.exe`)


## 🔍 Proceso de investigación

### 1. Triage inicial

Lo primero, como siempre con un hash en la alerta, fue llevarlo a VirusTotal. El resultado fue contundente: **50 de 72 motores** marcaron el archivo como malicioso, y varios vendors lo etiquetaron directamente como **Hyperscrap**. En la pestaña Community aparecía vinculado a colecciones de IOCs de APT35/Charming Kitten, lo que coincidía con el trigger reason de la propia alerta.

En el Threat Intel de LetsDefend, el hash también estaba catalogado con el tag `APT35, Charming...`. Con esto ya había suficiente para descartar falso positivo y pasar a confirmar si el archivo se había llegado a ejecutar.


### 2. Análisis de evidencias

**Hallazgo 1 — Ejecución confirmada del binario malicioso**

> En Endpoint Security, dentro de los procesos del host Arthur, aparece `EmailDownloader.exe` ejecutándose con `explorer.exe` como proceso padre — es decir, lo lanzó el propio usuario, probablemente tras descargarlo manualmente. Esto confirma que el malware no solo llegó al sistema, sino que se ejecutó.

| Campo | Valor |
|-------|-------|
| Fecha/hora | `2023-12-27 11:21:37.051` |
| Process ID | `6315` |
| Proceso | `EmailDownloader.exe` |
| Ruta | `C:\Users\LetsDefend\Downloads\EmailDownloader.exe` |
| Proceso padre | `explorer.exe` |
| Usuario | `EC2AMAZ-ILGVOIN\Arthur` |
| Hash (SHA256) | `cd2ba296828660ecd07a36e8931b851dda0802069ed926b3161745aae9aa6daa` |

**Hallazgo 2 — Acceso RDP previo desde IP externa vinculada a APT35**

> Antes de la ejecución del malware, los logs muestran un login exitoso (Event ID 4624, Logon Type 10 — RemoteInteractive) desde la IP `173.209.51.54` hacia el puerto 3389 de Arthur. Esa misma IP aparece reportada en AbuseIPDB como IOC de Charming Kitten desde 2022. Es decir, el atacante no llegó por phishing ni por un drive-by: entró directamente por RDP con una cuenta válida.

| Campo | Valor |
|-------|-------|
| IP origen | `173.209.51.54` (Attacker IP) |
| Puerto destino | `3389` (RDP) |
| Event ID | `4624` — Logon exitoso |
| Logon Type | `10` (RemoteInteractive) |
| Usuario | `Arthur` |
| Reputación | AbuseIPDB — IOC for Charming Kitten (2022) |

**Hallazgo 3 — Exfiltración de correo confirmada vía Exchange y tráfico a C2**

> El log de auditoría de Exchange registra una descarga masiva desde la carpeta `\Mails\Inbox` del buzón de Arthur, con el asunto literal *"Notification of Multiple Mail Download"* — una alerta nativa de Exchange que avisa de esta misma actividad anómala. Justo después, el firewall registra tráfico saliente desde el proceso `EmailDownloader.exe` hacia el puerto 80 de una segunda IP, que actúa como servidor C2.

| Campo | Valor |
|-------|-------|
| Owner del buzón | `EC2AMAZ-ILGVOIN\Arthur` |
| Operación | `Download` — Succeeded |
| Carpeta afectada | `\Mails\Inbox` |
| Cliente | `OWA` (Action: ViaProxy) |
| IP origen (exfil) | `172.16.17.72` (Arthur) |
| IP destino (C2) | `136.243.108.14` |
| Puerto destino | `80` |
| Proceso origen | `EmailDownloader.exe` |
| Acción firewall | `SUCCESS` (permitido) |

### 3. Correlación de eventos

```
[11:17 AM] — Login exitoso (4624) desde 173.209.51.54 hacia Arthur vía RDP (puerto 3389)
[11:21 AM] — Ejecución de EmailDownloader.exe (PID 6315), lanzado por explorer.exe
[11:21:48] — Exchange registra descarga masiva de correos desde \Mails\Inbox
[11:22 AM] — Tráfico saliente de EmailDownloader.exe hacia 136.243.108.14:80 (C2)
```

La secuencia es limpia y rápida: acceso, ejecución, recolección y exfiltración en menos de 5 minutos. Todo permitido por el firewall, sin ninguna acción de bloqueo intermedia.

### 4. Verificación de IOCs

| IOC | Tipo | Herramienta | Resultado |
|-----|------|-------------|-----------|
| `cd2ba296828660ecd07a36e8931b851dda0802069ed926b3161745aae9aa6daa` | SHA256 | VirusTotal | 50/72 — Malware, familia HyperScrape |
| `cd2ba296...aa6daa` | SHA256 | LetsDefend TI | Tag: `APT35, Charming...` |
| `173.209.51.54` | IP | AbuseIPDB | IOC for Charming Kitten — reportada desde 2022 |
| `136.243.108.14` | IP (C2) | AbuseIPDB | IOC for Charming Kitten — Phishing, Hacking, SSH |


## ✅ Conclusión y respuesta

**Veredicto:** Verdadero positivo

**Resumen del ataque:**
Un actor vinculado a APT35 (Charming Kitten) accedió al host Arthur vía RDP usando credenciales válidas, y una vez dentro ejecutó `EmailDownloader.exe`, una variante de la herramienta HyperScrape diseñada específicamente para exfiltrar correos de cuentas comprometidas. El propio Exchange detectó y registró la descarga masiva de emails desde la bandeja de entrada, y poco después se observó tráfico de salida del mismo proceso hacia una IP de C2 también vinculada al grupo. Todo el flujo —acceso, ejecución y exfiltración— fue permitido sin bloqueos por parte del firewall.

**Acciones de respuesta tomadas:**
1. Aislar el host `Arthur` (`172.16.17.72`) desde Endpoint Security
2. Resetear las credenciales de la cuenta `Arthur` / `arthur@letsdefend.io`
3. Bloquear las IPs `173.209.51.54` (acceso RDP) y `136.243.108.14` (C2) en el firewall
4. Revisar el buzón de Arthur para determinar el alcance exacto de los correos exfiltrados
5. Eliminar el binario `EmailDownloader.exe` del sistema
6. Revisar si la cuenta de Arthur tiene MFA habilitado y, si no, activarlo de inmediato
7. Cerrar la alerta como True Positive tras la contención

**Clasificación final:** True Positive — Incident

## 🗺️ Mapeo MITRE ATT&CK

| Táctica | Técnica | ID | Descripción |
|---------|---------|-----|-------------|
| Reconnaissance | Gather Victim Identity Information | T1589 | Recolección previa de identidades/correos como parte del reconocimiento de APT35 |
| Initial Access | Valid Accounts | T1078 | Acceso RDP a Arthur usando credenciales válidas |
| Credential Access | Steal Web Session Cookie | T1539 | Técnica asociada al modus operandi de HyperScrape para mantener sesión sobre OWA |
| Collection | Email Collection | T1114 | Descarga masiva de correos desde `\Mails\Inbox` vía OWA |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | Envío de los datos recolectados al servidor C2 `136.243.108.14` |


## 📚 Lecciones aprendidas

- **¿Qué aprendí técnicamente?** HyperScrape no es malware "tradicional" que infecta y se propaga: es una herramienta de exfiltración dirigida que actúa sobre cuentas ya comprometidas, automatizando la descarga de correo vía OWA. Lo interesante es que Exchange genera su propia alerta nativa (*"Notification of Multiple Mail Download"*) cuando detecta este patrón, así que vale la pena tenerla monitorizada como señal temprana independientemente del EDR.

- **¿Qué haría diferente?** Habría comprobado también el Browser History de Arthur para ver si hubo interacción manual con OWA antes de la ejecución del exfiltrador, y revisado si existían reglas de reenvío de correo configuradas (T1114.003), ya que es una táctica habitual de APT35 para mantener acceso persistente al buzón incluso después de perder el acceso RDP.

*Writeup elaborado con fines educativos y de práctica en entorno controlado.*
