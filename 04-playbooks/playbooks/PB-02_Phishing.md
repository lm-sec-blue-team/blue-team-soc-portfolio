# PB-02 · Phishing

| Campo | Valor |
|-------|-------|
| **ID** | PB-02 |
| **Categoría** | Acceso Inicial |
| **Severidad base** | Alta (Crítica si hubo ejecución de adjunto o robo de credenciales) |
| **Fases PICERL (L1)** | Identificación · Contención · Erradicación parcial |
| **Dominio BTL1** | Phishing Analysis |
| **Última revisión** | 2025-05 |


## MITRE ATT&CK

| Técnica | ID | Subtécnica |
|---------|----|-----------|
| Phishing | T1566 | — |
| Spearphishing Attachment | T1566.001 | Adjunto malicioso |
| Spearphishing Link | T1566.002 | URL maliciosa en cuerpo |
| Malicious File | T1204.002 | Usuario ejecuta adjunto |


## 1. Identificación · Artefactos a examinar

El objetivo es determinar si el correo es malicioso y, si lo es, extraer **IoCs** para detección, bloqueo y threat intel. El análisis sigue cuatro bloques de artefactos según el dominio BTL1 de Phishing Analysis.

### 1.1 Cabeceras (Headers)

- `From`, `Reply-To`, `Return-Path` — frecuentemente divergen en phishing.
- `Received` — se lee de **abajo arriba** para trazar la ruta real del correo.
- `Authentication-Results` — verificar **SPF / DKIM / DMARC**. Un FAIL es bandera roja.
- IP de origen real (último `Received`) → comprobar reputación.
- `X-Originating-IP` — si está presente, IP del cliente de correo del remitente.

### 1.2 Cuerpo (Body)

- Urgencia o amenaza ("tu cuenta será bloqueada en 24h").
- Errores gramaticales, saludos genéricos ("Estimado cliente").
- Peticiones inusuales (credenciales, transferencias bancarias, datos fiscales).
- Estilo inconsistente con comunicaciones previas del supuesto remitente.
- Logos pixelados o desalineados (copia visual de marca).

### 1.3 URLs y enlaces

- Dominios engañosos: `paypaI.com` (I mayúscula), typosquatting (`micr0soft.com`).
- Acortadores que ocultan destino (Bitly, TinyURL, t.co).
- IPs directas en lugar de dominios (`http://185.x.x.x/login`).
- Parámetros que identifican a la víctima (`?uid=usuario@empresa.com`).
- **Defang** siempre al documentar: `hxxps://malicious[.]com/path`.

### 1.4 Adjuntos

| Tipo | Extensiones | Riesgo |
|------|------------|--------|
| Ejecutables | `.exe .scr .bat .ps1 .js .vbs .hta .msi` | Crítico |
| Office con macros | `.docm .xlsm .pptm .dotm` | Alto |
| Doble extensión | `factura.pdf.exe` | Crítico |
| Archivos comprimidos cifrados | `.zip .7z .rar` (password en body) | Alto (evaden AV) |
| Disco virtual | `.iso .img .vhd` | Alto (evaden Mark-of-the-Web) |
| Shortcuts | `.lnk` | Alto |

> ⚠️ **NUNCA** abras un adjunto sospechoso en tu equipo. Análisis siempre en **sandbox** (Any.run, Hybrid Analysis, Joe Sandbox) o VM aislada sin red corporativa.


## 2. Workflow de análisis paso a paso

```
1. Aislar el email (.eml / .msg) sin reenviar inline
         │
2. Cabeceras → MXToolbox Header Analyzer / Google Admin Toolbox
         │       └─ Verificar SPF / DKIM / DMARC
         │       └─ Extraer IP de origen real
         │
3. URLs → Defang → expandir acortadores (urlscan.io)
         │       └─ Reputación: VirusTotal + URLhaus + PhishTank
         │
4. Adjuntos → Calcular hash (MD5/SHA256) → VirusTotal
         │       └─ Si no aparece o <5 detecciones → sandbox
         │
5. Extraer IoCs: IPs, dominios, hashes, asuntos, emails del remitente
         │
6. Pivotar en SIEM:
         │   └─ ¿Quién más recibió este correo?
         │   └─ ¿Alguien hizo clic en la URL?
         │   └─ ¿Alguien ejecutó el adjunto?
         │
7. Clasificar: TP → Contener  /  FP → Cerrar ticket documentado
```


## 3. Detección · SPL (Splunk)

### Buscar quién más recibió el mismo email

```spl
index=email (sender="atacante@dominio-falso.com" OR subject="Factura urgente pendiente")
| stats count values(recipient) as destinatarios values(subject) as asuntos by sender
| sort - count
```

### Detectar usuarios que hicieron clic en la URL maliciosa (proxy logs)

```spl
index=proxy url="*malicious-site.com*" OR url="*phishing-domain.tld*"
| stats count earliest(_time) as first_click latest(_time) as last_click by user, src_ip, url
| sort - count
```

### Conexiones a dominios recién resueltos tras la entrega del correo

```spl
index=dns OR index=proxy query="*.tld-sospechoso.*"
| stats count values(src_ip) as origenes by query
| where count > 0
| sort - count
```

### Ejecución de adjunto — Office spawneando shell (cruzar con PB-03)

```spl
index=sysmon EventCode=1
  ParentImage IN ("*winword.exe","*excel.exe","*powerpnt.exe","*outlook.exe")
  Image IN ("*cmd.exe","*powershell.exe","*wscript.exe","*cscript.exe","*mshta.exe")
| table _time host User ParentImage Image CommandLine
```


## 4. Detección · KQL (Microsoft Sentinel / Defender)

### Rastreo de destinatarios del email malicioso

```kql
EmailEvents
| where TimeGenerated > ago(7d)
| where SenderFromAddress == "atacante@dominio-falso.com"
   or Subject contains "Factura urgente"
| join kind=leftouter EmailUrlInfo on NetworkMessageId
| project TimeGenerated, RecipientEmailAddress, Subject, Url, DeliveryAction
| order by TimeGenerated desc
```

### ¿Alguien hizo clic en una URL del email?

```kql
UrlClickEvents
| where TimeGenerated > ago(7d)
| where Url contains "malicious-site.com"
| project TimeGenerated, AccountUpn, Url, ActionType, IPAddress
```


## 5. Contención y erradicación

- [ ] **Purgar correo** de todos los buzones (M365: *Threat Explorer → Take action → Soft/Hard delete*).
- [ ] **Bloquear remitente y dominio** en gateway de correo (Defender, Proofpoint, Mimecast).
- [ ] **Bloquear URLs/IPs** maliciosas en proxy / firewall / DNS sinkhole.
- [ ] **Bloquear hash** de adjunto en EDR / AV.
- [ ] **Si alguien hizo clic e introdujo credenciales:**
  - [ ] Reset de contraseña inmediato.
  - [ ] Revocar todas las sesiones activas y tokens OAuth.
  - [ ] MFA enrollment forzado si no estaba activo.
  - [ ] Revisar reglas de bandeja de entrada (forwarding malicioso es típico post-compromiso).
  - [ ] Revisar actividad reciente de la cuenta: emails enviados, accesos a SharePoint/OneDrive, login desde IPs nuevas.
- [ ] **Si alguien ejecutó el adjunto:**
  - [ ] Aislar endpoint desde EDR (network containment).
  - [ ] Pivotar a → **[PB-03 Malware](PB-03_Malware.md)** y/o **[PB-04 Ransomware](PB-04_Ransomware.md)**.

> ⚠️ **Reglas de forwarding:** tras comprometer una cuenta, muchos atacantes crean reglas de reenvío automático a un correo externo para mantener acceso a la información aunque se cambie la contraseña. Siempre revisa `New-InboxRule`, `Set-InboxRule` y `Set-Mailbox` con `ForwardTo` / `RedirectTo`.


## 6. IoCs a extraer y registrar

| IoC | De dónde | Dónde bloquear |
|-----|----------|----------------|
| IP de origen | Cabecera `Received` | Firewall, mail gateway |
| Dominio remitente | `From`, `Return-Path` | Mail gateway |
| Dominios enlazados | Body / URLs | Proxy, DNS sinkhole |
| URLs completas | Body / HTML source | Proxy, mail gateway |
| Hashes (MD5/SHA256) | Adjuntos | EDR, AV |
| Asunto | Header `Subject` | Regla SIEM / mail gateway |
| Nombre de adjunto | Email | Regla SIEM |

Todos los IoCs se registran **defanged** en el ticket y en la plataforma de TI (MISP, OpenCTI, hoja de cálculo interna según la organización).

## 7. Criterio de escalado a L2

Escalar **inmediatamente** si se cumple cualquiera de estas condiciones:

- Confirmado que un usuario **introdujo credenciales** en la página de phishing.
- Confirmado que un usuario **ejecutó el adjunto** y hay indicios de ejecución (procesos anómalos, C2).
- La campaña es **masiva** (>50 destinatarios) y varios hicieron clic.
- El phishing es **dirigido** (spearphishing) contra ejecutivos, finanzas o IT (BEC / whaling).
- Indicios de **movimiento lateral** post-compromiso → ver **[PB-05](PB-05_Lateral_Movement.md)**.


## 8. Herramientas de apoyo

| Herramienta | Uso |
|-------------|-----|
| **MXToolbox Header Analyzer** | Parseo de cabeceras, ruta del email |
| **Google Admin Toolbox** | Verificación SPF/DKIM/DMARC |
| **urlscan.io** | Screenshot y análisis de URLs sin visitarlas |
| **VirusTotal** | Reputación de URLs, dominios, IPs y hashes |
| **URLhaus** (abuse.ch) | Base de datos de URLs maliciosas |
| **PhishTank** | Verificar si la URL ya está reportada como phishing |
| **Any.run** | Sandbox interactivo para adjuntos |
| **Hybrid Analysis** | Sandbox automatizado |
| **CyberChef** | Decodificar base64, URLs, extraer strings |
| **Whois / dig** | Fecha de registro del dominio, nameservers |
