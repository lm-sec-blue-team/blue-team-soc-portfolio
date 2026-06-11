# SOC257 — VPN Connection Detected from Unauthorized Country

**Plataforma:** LetsDefend  
**Categoría:** Network Anomaly / Credential Access  
**Dificultad:** Media  
**Fecha de resolución:** 2024-02-13  
**Técnicas MITRE ATT&CK:**
- [T1133 — External Remote Services](https://attack.mitre.org/techniques/T1133/)
- [T1595 — Active Scanning](https://attack.mitre.org/techniques/T1595/)
- [T1111 — Multi-Factor Authentication Interception](https://attack.mitre.org/techniques/T1111/)

**Tácticas MITRE:** Reconnaissance · Initial Access · Credential Access


## 🧩 Contexto del caso

> Se recibió una alerta por detección de un intento de login VPN desde un país no
> autorizado. La conexión provenía de una IP vietnamita pero fue registrada
> inicialmente con geolocalización en EE.UU. El acceso se intentó con las
> credenciales de la usuaria **Monica**, empleada de la organización.

**Tipo de alerta:** SOC257 — VPN Connection Detected from Unauthorized Country  
**Severidad inicial:** Security Analyst (Media)  
**Event ID:** 225  
**Fecha y hora del evento:** Feb 13, 2024 — 02:04 AM

**Activos implicados:**
- Host destino (VPN Gateway): `33.33.33.33`
- URL VPN: `hxxps://vpn-letsdefend[.]io`
- Usuario objetivo: `monica@letsdefend.io` (IP interna: `172.16.17.163`)
- IP atacante: `113.161.158.12` (Vietnam — VNPT)

## 🔍 Proceso de investigación

### 1. Triage inicial

Al recibir la alerta se identificaron los siguientes puntos clave:

- La alerta indicaba una conexión VPN desde país no autorizado hacia el usuario `monica@letsdefend.io`.
- La IP de origen reportada en la alerta era `113.161.158.12`, catalogada como ubicada en EE.UU. en el sistema, pero la verificación WHOIS reveló que pertenece a **Vietnam**.
- Se accedió a **Log Management** para buscar todos los registros asociados a dicha IP.
- Se encontraron logs de tipo **Firewall** y **Proxy** con destino `33.33.33.33:443`.

```
# Búsqueda en Log Management
Source IP: 113.161.158.12
Rango temporal: Feb 13, 2024 01:58 AM – 02:04 AM
Tipos de log encontrados: Firewall, Proxy
```

El primer indicador destacado fue una petición **HTTP POST** exitosa (código `200`) al endpoint `/logon.html` de `vpn-letsdefend.io` a las **02:01 AM**, lo que confirmó que el atacante logró autenticarse con la contraseña correcta de Monica.


### 2. Análisis de evidencias

**Hallazgo 1 — Acceso exitoso al portal VPN con credenciales válidas**

> El log de proxy muestra que el atacante realizó un POST al endpoint de login VPN con las credenciales de Monica y recibió respuesta HTTP `200 OK`. Esto confirma que la contraseña era correcta, pero no implica acceso completo a la VPN.

| Campo | Valor |
|-------|-------|
| Fecha | `Feb 13, 2024 02:01 AM` |
| IP origen | `113.161.158.12` |
| IP destino | `33.33.33.33` |
| Puerto destino | `443` |
| URL | `hxxps://vpn-letsdefend[.]io/logon.html` |
| Método | `POST` |
| Protocolo | `HTTP/1.0` |
| Código respuesta | `200` |
| Usuario | `monica@letsdefend.io` |


**Hallazgo 2 — MFA activo: OTP introducido incorrectamente en 3 intentos**

> A pesar de que el atacante conocía la contraseña de Monica, el sistema de MFA envió un código OTP al correo de la usuaria. Los logs de Firewall muestran la acción **"Incorrect OTP Code"** en los tres intentos (02:01, 02:02 y 02:03 AM), lo que indica que el atacante no tuvo acceso al buzón de correo de Monica ni al canal de entrega del OTP.

| Campo | Valor |
|-------|-------|
| Fecha intento 1 | `Feb 13, 2024 02:01 AM` |
| Fecha intento 2 | `Feb 13, 2024 02:02 AM` |
| Fecha intento 3 | `Feb 13, 2024 02:03 AM` |
| Acción Firewall | `Incorrect OTP Code` |
| Destino | `vpn-letsdefend.io` |
| Usuario | `monica@letsdefend.io` |

Se verificó en **Email Security** que se enviaron 3 correos desde `security@letsdefend.io` a `monica@letsdefend.io` con el asunto *"Your One-Time Passcode (OTP) for MFA Activation"*, todos con estado `Allowed`, confirmando que los OTPs fueron generados y entregados correctamente al buzón legítimo.


**Hallazgo 3 — Port Scan previo al intento VPN**

> En los logs de Firewall previos al intento de login (desde las 01:56 AM), se observaron múltiples conexiones desde la misma IP atacante hacia puertos aleatorios del host `33.33.33.33`. El patrón de puertos de destino variados (443, 46107, 52328, 11121, etc.) es consistente con un **escaneo de puertos activo** para reconocimiento previo al ataque.

| Campo | Valor |
|-------|-------|
| IP origen | `113.161.158.12` |
| IP destino | `33.33.33.33` |
| Puertos destino observados | `443, 46107, 52328, 46960, 31254, 11121, 40900, 49628, 23215, 40530` |
| Tipo de log | Firewall |
| Horario | `01:56 AM – 01:59 AM` |


### 3. Correlación de eventos

```
[01:56 AM] — Inicio del port scan desde 113.161.158.12 hacia 33.33.33.33
[01:59 AM] — Últimas peticiones del escaneo de puertos (Firewall logs)
[02:01 AM] — POST a /logon.html → HTTP 200 (contraseña correcta, OTP generado)
[02:01 AM] — Firewall: "Incorrect OTP Code" — primer intento fallido de MFA
[02:02 AM] — Segunda solicitud VPN → OTP generado (2º email enviado a Monica)
[02:02 AM] — Firewall: "Incorrect OTP Code" — segundo intento fallido de MFA
[02:03 AM] — Tercera solicitud VPN → OTP generado (3º email enviado a Monica)
[02:03 AM] — Firewall: "Incorrect OTP Code" — tercer intento fallido de MFA
[02:04 AM] — Alerta SOC257 disparada
```

La secuencia muestra un ataque estructurado: **reconocimiento → acceso remoto con credenciales comprometidas → intento de bypass MFA fallido**.


### 4. Verificación de IOCs

| IOC | Tipo | Herramienta de verificación | Resultado |
|-----|------|-----------------------------|-----------|
| `113.161.158.12` | IP | AbuseIPDB | Reportada **1.246 veces** — Confianza de abuso: **100%** |
| `113.161.158.12` | IP | VirusTotal | **16/90** vendors la marcan como maliciosa |
| `113.161.158.12` | IP | LetsDefend TI | Etiquetada como **Brute Force** (AbuseIPDB, Dec 2023) |
| `113.161.158.12` | IP | WHOIS | ISP: *Vietnam Posts and Telecommunications Group* — Ha Noi, VN |
| `hxxps://vpn-letsdefend[.]io` | URL | Verificación manual | SSL VPN Service legítimo de la organización |

**Categorías de abuso históricas:** Brute Force · SSH · Web Attack · Malicious


## ✅ Conclusión y respuesta

**Veredicto:** Verdadero positivo

**Resumen del ataque:**
Un atacante desde Vietnam (IP `113.161.158.12`, ISP VNPT) con historial conocido de actividad maliciosa realizó un escaneo de puertos previo contra la infraestructura de la organización. A continuación, intentó acceder a la VPN corporativa mediante las credenciales comprometidas de la usuaria Monica, logrando superar la primera capa de autenticación (contraseña correcta). Sin embargo, el sistema de MFA mediante OTP actuó como barrera efectiva: el atacante falló en los tres intentos al no tener acceso al canal de entrega del OTP (correo corporativo de Monica). La cuenta de Monica debe considerarse **comprometida a nivel de contraseña**.

**Acciones de respuesta tomadas:**
1. Confirmar que el atacante **no obtuvo acceso a la VPN** (MFA bloqueó el acceso efectivamente)
2. Marcar la cuenta `monica@letsdefend.io` como **cuenta comprometida**
3. **Resetear la contraseña** de la usuaria Monica inmediatamente
4. **Bloquear la IP** `113.161.158.12` en el firewall perimetral
5. Notificar a Monica para que revise si ha reutilizado esa contraseña en otros servicios
6. Cerrar la alerta como **True Positive — No Incident** (acceso VPN no consumado)

**Clasificación final:** True Positive — No Incident *(VPN connection detected but login not completed)*


## 🗺️ Mapeo MITRE ATT&CK

| Táctica | Técnica | ID | Descripción |
|---------|---------|-----|-------------|
| Reconnaissance | Active Scanning | T1595 | Port scan previo contra `33.33.33.33` desde la IP atacante |
| Initial Access | External Remote Services | T1133 | Intento de acceso a VPN corporativa con credenciales válidas |
| Credential Access | Multi-Factor Authentication Request Generation | T1111 | El atacante triggereó la generación de OTPs al conocer la contraseña |


*Writeup elaborado con fines educativos y de práctica en entorno controlado.*
