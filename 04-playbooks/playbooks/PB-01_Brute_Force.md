# PB-01 · Brute Force

| Campo | Valor |
|-------|-------|
| **ID** | PB-01 |
| **Categoría** | Acceso Inicial |
| **Severidad base** | Media (Crítica si hay login exitoso) |
| **Fases PICERL (L1)** | Identificación · Contención inicial |
| **Última revisión** | 2025-05 |

## MITRE ATT&CK

| Técnica | ID | Subtécnica |
|---------|----|-----------|
| Brute Force | T1110 | — |
| Password Guessing | T1110.001 | Intentos contra una cuenta |
| Password Spraying | T1110.003 | Pocos intentos × muchas cuentas |
| Credential Stuffing | T1110.004 | Credenciales filtradas reutilizadas |

## 1. Identificación · Triaje inicial

Lo primero ante una alerta de brute force es confirmar si es **TP o FP**. Muchos FP vienen de usuarios con contraseñas caducadas, apps con credenciales hardcodeadas o scanners legítimos. La clave está en el **patrón**: una IP única intentando 50 cuentas distintas (spraying) es muy distinto de un usuario fallando 10 veces (probable olvido).

### Preguntas clave del triaje

- ¿Cuántos intentos fallidos? ¿En qué ventana de tiempo?
- ¿Una IP origen o muchas? ¿Geolocalización (impossible travel)?
- ¿Una cuenta objetivo o varias?
  - **1 IP → muchas cuentas** = Password Spraying
  - **Muchas IPs → 1 cuenta** = Password Guessing / Credential Stuffing
- ¿Hubo **algún éxito (4624)** tras los fallos (4625)? → Esto cambia la severidad a **CRÍTICA**
- ¿La cuenta atacada es privilegiada (Domain Admin, cuenta de servicio crítica)?

### Event IDs de referencia (Windows)

| Event ID | Significado |
|----------|-------------|
| 4625 | Logon fallido |
| 4624 | Logon exitoso |
| 4740 | Cuenta bloqueada (lockout) |
| 4771 | Kerberos pre-auth fallida |

## 2. Detección · SPL (Splunk)

### Brute force clásico contra Windows

10+ fallos (4625) de la misma IP origen contra una cuenta en 10 minutos.

```spl
index=wineventlog EventCode=4625
| bin _time span=10m
| stats count dc(Account_Name) as users_targeted values(Account_Name) as accounts by _time, src_ip
| where count >= 10
| sort - count
```

### Password Spraying

Misma IP intentando muchas cuentas distintas con pocos intentos cada una (evade lockouts).

```spl
index=wineventlog EventCode=4625
| bin _time span=30m
| stats dc(Account_Name) as users_targeted count by src_ip
| where users_targeted >= 5 AND count >= 10
| sort - users_targeted
```

### Brute force exitoso (TP confirmado — ESCALAR)

Serie de 4625 seguidos de un 4624 desde la misma IP/cuenta. Esto **siempre escala**.

```spl
index=wineventlog (EventCode=4624 OR EventCode=4625) Logon_Type IN (3,10)
| transaction src_ip Account_Name maxspan=15m
| where eventcount > 10 AND searchmatch("EventCode=4624")
| table _time src_ip Account_Name eventcount
```

### Brute force contra SSH

```spl
index=linux source="/var/log/auth.log" "Failed password"
| rex "Failed password for (invalid user )?(?<user>\S+) from (?<src_ip>\S+)"
| bin _time span=10m
| stats count dc(user) as users by _time, src_ip
| where count >= 15
```


## 3. Detección · KQL (Microsoft Sentinel)

### Fallos masivos de autenticación

```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(1h)
| summarize FailedCount = count(),
            TargetedAccounts = dcount(TargetUserName),
            Accounts = make_set(TargetUserName, 20)
  by IpAddress, bin(TimeGenerated, 10m)
| where FailedCount >= 10
| order by FailedCount desc
```

### Brute force exitoso en M365 / Entra ID

Sign-ins fallidos seguidos de un éxito en la misma ventana.

```kql
SigninLogs
| where TimeGenerated > ago(6h)
| summarize Failed = countif(ResultType != "0"),
            Success = countif(ResultType == "0")
  by UserPrincipalName, IPAddress, bin(TimeGenerated, 30m)
| where Failed >= 10 and Success >= 1
| order by TimeGenerated desc
```

## 4. Contención inmediata

- [ ] **Bloquear IP origen** en firewall perimetral / WAF si es externa.
- [ ] **Forzar reset de contraseña** de la cuenta si hubo éxito o si es privilegiada.
- [ ] **Habilitar MFA** si no estaba activo (especialmente OWA/M365).
- [ ] **Desactivar la cuenta** temporalmente si hay sospecha alta de compromiso.
- [ ] **Revisar sesiones activas** (token theft, sesiones desde la IP atacante) y revocarlas.


## 5. Criterio de escalado a L2

Escalar **inmediatamente** si se cumple cualquiera de estas condiciones:

- Hubo **autenticación exitosa** (4624) después del ataque.
- La cuenta es **privilegiada** (Domain Admin, Enterprise Admin, cuenta de servicio crítica).
- Patrón **sostenido en el tiempo** (>24h) o desde múltiples IPs coordinadas.
- Indicios de **movimiento lateral** o ejecución posterior al login → ver **[PB-05 Lateral Movement](PB-05_Lateral_Movement.md)**.

## 6. Evidencia a recoger

| Artefacto | Origen | Para qué |
|-----------|--------|----------|
| Eventos 4624 / 4625 / 4740 | Windows Security log | Pivote temporal y por cuenta |
| Logs sshd / auth.log | Linux `/var/log/auth.log` | SSH brute force |
| SigninLogs | Entra ID / Azure AD | Spray contra M365 |
| Logs VPN / Firewall | Concentrador VPN, perimetral | Brute force externo |
| Geolocalización IP | VirusTotal, AbuseIPDB | Atribución y bloqueo |

## 7. Herramientas de apoyo

| Herramienta | Uso |
|-------------|-----|
| **AbuseIPDB** | Reputación de IP, reportes de abuso |
| **VirusTotal** | Reputación IP/dominio |
| **Shodan** | Contexto del origen (hosting, proxy, Tor exit) |
| **Have I Been Pwned** | Verificar si la cuenta atacada tiene credenciales filtradas |

