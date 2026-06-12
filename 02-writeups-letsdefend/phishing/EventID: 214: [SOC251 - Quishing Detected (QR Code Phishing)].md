# SOC251 — Quishing Detected (QR Code Phishing)

**Plataforma:** LetsDefend  
**Categoría:** Phishing  
**Dificultad:** Media  
**Fecha de resolución:** 2024-01-01  
**Técnicas MITRE ATT&CK:**
- [T1598 — Phishing for Information](https://attack.mitre.org/techniques/T1598/)
- [T1566 — Phishing](https://attack.mitre.org/techniques/T1566/)
- [T1204 — User Execution](https://attack.mitre.org/techniques/T1204/)
- [T1656 — Impersonation](https://attack.mitre.org/techniques/T1656/)
- [T1027 — Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)

**Tácticas MITRE:** Reconnaissance · Initial Access · Execution · Defense Evasion

---

## 🧩 Contexto del caso

> Email de phishing enviado a la usuaria Claire suplantando a Microsoft. El correo contenía un QR code malicioso que redirigía a una página falsa de Webmail para robar credenciales. El producto de seguridad no bloqueó el email.

**Tipo de alerta:** SOC251 — Quishing Detected (QR Code Phishing)  
**Severidad inicial:** Medium  
**Event ID:** 214  
**Fecha y hora del evento:** Jan 01, 2024 — 12:00 PM

**Activos implicados:**
- Host: `Claire` (IP: `172.16.17.181`)
- Usuario objetivo: `claire@letsdefend.io`
- Remitente malicioso: `security@microsecmfa.com`
- SMTP IP atacante: `158.69.201.47`


## 🔍 Proceso de investigación

### 1. Triage inicial

Lo primero fue revisar el email en el módulo de **Email Security**. El correo llegó con acción `Allowed`, es decir, no fue bloqueado. El asunto era *"New Year's Mandatory Security Update: Implementing Multi-Factor Authentication (MFA)"*, claro intento de crear urgencia y suplantar una comunicación corporativa de Microsoft.

El dominio remitente `microsecmfa.com` no tiene relación con Microsoft: es un dominio fraudulento creado para parecer legítimo a simple vista.


### 2. Análisis de evidencias

**Hallazgo 1 — Email de phishing con QR code embebido**

> El email contenía un QR code en lugar de un enlace directo, técnica conocida como *Quishing*. Este método elude los filtros de seguridad tradicionales que analizan URLs en texto plano pero no procesan imágenes QR.

| Campo | Valor |
|-------|-------|
| Fecha | `Jan 01, 2024 — 12:00 PM` |
| Remitente | `security@microsecmfa.com` |
| Destinatario | `claire@letsdefend.io` |
| SMTP IP | `158.69.201.47` |
| Asunto | `New Year's Mandatory Security Update: Implementing MFA` |
| Acción del sistema | `Allowed` |


**Hallazgo 2 — URL maliciosa extraída del QR code (CyberChef)**

> Usando CyberChef con la operación *Parse QR Code* se extrajo la URL embebida en el código QR. La URL utiliza IPFS (InterPlanetary File System) como infraestructura de hosting, lo que dificulta el takedown del contenido malicioso.

| Campo | Valor |
|-------|-------|
| URL extraída | `hxxps://ipfs[.]io/ipfs/Qmbr8wmr41C35c3K2GfiP2F8YGzLhYpKpb4K66KU6mLmL4#` |
| Plataforma de hosting | IPFS (`ipfs.io`) |
| Detecciones VirusTotal | 7/91 — Phishing / Malicious |


**Hallazgo 3 — Página de credential harvesting y exfiltración**

> Al analizar la URL en sandbox (Any.run), se observó una página falsa de *Webmail Sign-in*. El análisis del código fuente reveló un script jQuery que envía las credenciales introducidas por la víctima via POST a un servidor externo.

| Campo | Valor |
|-------|-------|
| Página destino | Fake Webmail Sign-in |
| Endpoint de exfiltración | `hxxps://www.nsggroup[.]it/fhfh/ffftt/hhnew.php` |
| Detecciones VT (nsggroup.it) | 9/89 — Phishing / Malicious |
| Sandbox | [Any.run — bd464486](https://app.any.run/tasks/bd464486-10a1-443b-ac9a-9adad3922167/) |


### 3. Correlación de eventos

```
[12:00 PM] — Email recibido por Claire desde security@microsecmfa.com (Allowed)
[12:00 PM] — QR code embebido en el email apunta a URL en IPFS
[??:??]    — Claire escanea el QR con su móvil (sin registro en logs corporativos)
[??:??]    — Víctima accede a la página falsa de Webmail y potencialmente introduce credenciales
[??:??]    — Credenciales enviadas via POST a nsggroup[.]it/fhfh/ffftt/hhnew.php
```

> El gap de logs se debe a que el escaneo QR se realizó con el móvil personal de Claire, que no pasa por el proxy corporativo, dejando sin trazabilidad la actividad posterior al click.


### 4. Verificación de IOCs

| IOC | Tipo | Herramienta | Resultado |
|-----|------|-------------|-----------|
| `158.69.201.47` | IP (SMTP) | AbuseIPDB | Reportada 298 veces — Phishing activo |
| `158.69.201.47` | IP (SMTP) | LetsDefend TI | Tag: **Phishing** |
| `hxxps://ipfs[.]io/ipfs/Qmbr8wmr41...` | URL | VirusTotal | 7/91 — Phishing / Malicious |
| `nsggroup[.]it` | Dominio | VirusTotal | 9/89 — Phishing / Malicious / Suspicious |
| `hxxps://nsggroup[.]it/fhfh/ffftt/hhnew.php` | URL (C2 exfil) | Análisis de código fuente | Endpoint receptor de credenciales |


## ✅ Conclusión y respuesta

**Veredicto:** Verdadero positivo

**Resumen del ataque:**
El atacante envió un email suplantando a Microsoft con un QR code que redirigía a una página falsa de Webmail alojada en IPFS. La víctima (Claire) presumiblemente escaneó el código con su móvil, accedió a la página y pudo haber introducido sus credenciales, que serían exfiltradas automáticamente a `nsggroup[.]it`. El uso de IPFS y QR codes es una técnica deliberada para evadir filtros de email y herramientas de análisis de URLs.

**Acciones de respuesta tomadas:**
1. Aislar el host `Claire` (`172.16.17.181`) de la red desde Endpoint Security
2. Eliminar el email malicioso del buzón de Claire desde Email Security
3. Resetear las credenciales de `claire@letsdefend.io`
4. Bloquear los dominios `microsecmfa.com`, `ipfs.io` (hash específico) y `nsggroup.it` en el proxy/firewall
5. Bloquear la IP SMTP `158.69.201.47` en el gateway de correo
6. Notificar al usuario y realizar sesión de concienciación

**Clasificación final:** True Positive — Incident


## 🗺️ Mapeo MITRE ATT&CK

| Táctica | Técnica | ID | Descripción |
|---------|---------|-----|-------------|
| Reconnaissance | Phishing for Information | T1598 | Email de quishing para recopilar credenciales |
| Initial Access | Phishing | T1566 | Email malicioso con QR code como vector de entrada |
| Execution | User Execution | T1204 | La víctima escanea el QR y accede a la URL |
| Defense Evasion | Obfuscated Files or Information | T1027 | URL ocultada dentro de una imagen QR para evadir filtros |
| Defense Evasion | Impersonation | T1656 | Suplantación de Microsoft en el email y en la página web |

---

*Writeup elaborado con fines educativos y de práctica en entorno controlado.*
