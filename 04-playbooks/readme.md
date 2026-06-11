
# 🛡️ SOC L1 Playbooks — BTL1 Aligned

Playbooks operativos para los **12 tipos de ataque** más comunes en la cola de alertas de un SOC L1. Cada uno sigue el ciclo **PICERL** (NIST SP 800-61), incluye queries de detección en **Splunk (SPL)** y **Microsoft Sentinel (KQL)**, mappings **MITRE ATT&CK** y checklists de contención accionables.

> **Enfoque:** un analista L1 se concentra en **Identificación** (triaje, clasificación TP/FP, extracción de IoCs) y **Contención inicial**. La erradicación completa, la recuperación y las lecciones aprendidas son responsabilidad de L2/L3 e IR Manager.

---

## 📋 Catálogo de playbooks

| #  | Playbook | Fase ATT&CK | Severidad base |
|----|----------|-------------|----------------|
| 01 | [Brute Force](playbooks/PB-01_Brute_Force.md) | Acceso Inicial | Media |
| 02 | [Phishing](playbooks/PB-02_Phishing.md) | Acceso Inicial | Alta |
| 03 | [Malware](playbooks/PB-03_Malware.md) | Ejecución | Alta |
| 04 | [Ransomware](playbooks/PB-04_Ransomware.md) | Impacto | **Crítica** |
| 05 | [Lateral Movement](playbooks/PB-05_Lateral_Movement.md) | Movimiento | Alta |
| 06 | [Data Exfiltration](playbooks/PB-06_Data_Exfiltration.md) | Impacto | **Crítica** |
| 07 | [Web Attacks](playbooks/PB-07_Web_Attacks.md) | Explotación | Alta |
| 08 | [Insider Threat](playbooks/PB-08_Insider_Threat.md) | Interno | Media-Alta |
| 09 | [Command & Control](playbooks/PB-09_C2.md) | C2 | Alta |
| 10 | [Privilege Escalation](playbooks/PB-10_Privilege_Escalation.md) | Escalada | Alta |
| 11 | [DDoS](playbooks/PB-11_DDoS.md) | Disponibilidad | Variable |
| 12 | [Supply Chain](playbooks/PB-12_Supply_Chain.md) | Acceso Inicial | **Crítica** |

---

## 🔄 Marco PICERL

Todas las respuestas a incidentes se estructuran en **seis fases** (NIST SP 800-61 / PICERL). Cada playbook indica qué fases son responsabilidad directa del L1.

```
┌─────────────────┐    ┌─────────────────┐    ┌───────────────┐
│ 1. PREPARACIÓN  |───▶│ 2. IDENTIFICIÓN │───▶│ 3. CONTENCIÓN │
│                 │    │   ★ L1 CORE     │    │  ★ L1 INIT    │
└─────────────────┘    └─────────────────┘    └─────────┬─────┘
                                                        │
┌──────────────┐    ┌─────────────────┐    ┌────────────▼────┐
│ 6. LECCIÓN   │◀───│ 5. RECUPERACIÓN │◀───│ 4. ERRCICACIÓN  │
│   APRENDIDA  │    │                 │    │                 │
└──────────────┘    └─────────────────┘    └─────────────────┘
```

### Fase 1 — Preparation (Preparación)

Fase continua y previa a cualquier incidente. Incluye el desarrollo de planes IRP, la creación y actualización de playbooks (este repositorio), formación del equipo CSIRT, configuración de herramientas (SIEM, EDR, IDS/IPS), definición de procedimientos de escalado y hardening de sistemas.

### Fase 2 — Identification (Identificación) ⭐

**Fase central del L1.** Detectar el incidente, determinar su naturaleza y alcance. Monitorizar alertas SIEM/EDR, analizar logs, realizar triaje (clasificar como TP o FP), recolectar evidencia inicial respetando el orden de volatilidad y documentar hallazgos.

### Fase 3 — Containment (Contención) ⭐

Limitar el impacto y evitar la propagación. El L1 ejecuta la **contención a corto plazo**: aislamiento de hosts desde EDR, bloqueo de cuentas, bloqueo de IPs/dominios en firewall/proxy/DNS. La contención a largo plazo (preparar entorno limpio para recovery) suele coordinarse con L2.

### Fase 4 — Eradication (Erradicación)

Eliminar la causa raíz y todos los artefactos del atacante: malware, cuentas no autorizadas, backdoors, mecanismos de persistencia. Parchear las vulnerabilidades explotadas. A menudo implica reimaginar los sistemas afectados desde imagen limpia. Responsabilidad de L2/L3.

### Fase 5 — Recovery (Recuperación)

Restaurar servicio normal: backups limpios, sistemas reconstruidos en producción, pruebas exhaustivas y monitorización intensiva de los hosts recuperados para detectar reinfección. Responsabilidad de L2/L3 y Sistemas.

### Fase 6 — Lessons Learned (Lecciones aprendidas)

Reunión post-incidente, informe final, análisis de causa raíz, identificación de brechas en controles y procedimientos. Actualización de playbooks, reglas SIEM y configuraciones. Cierra el ciclo y alimenta la fase de Preparación.

---

## ⚡ Orden de volatilidad

Al recoger evidencia, siempre se va de lo más volátil a lo más persistente:

```
Registros CPU  →  Memoria RAM  →  Estado de red/procesos  →  Disco  →  Logs remotos  →  Backups
(más volátil)                                                          (más persistente)
```

Todo se documenta con hashing (MD5/SHA256) y cadena de custodia.

---

## 🧰 Stack de detección

| Herramienta | Rol | Queries en playbooks |
|-------------|-----|---------------------|
| **Splunk** | SIEM primario | SPL (principal) |
| **Microsoft Sentinel** | SIEM cloud / entrevistas | KQL (secundario) |
| **Sysmon** | Telemetría de endpoint Windows | Fuente de logs para SPL/KQL |
| **EDR** (CrowdStrike, Defender, etc.) | Contención + telemetría | Acciones de aislamiento |
| **VirusTotal / MalwareBazaar** | Reputación de hashes/IPs/dominios | Triaje de IoCs |

---

## 📚 Frameworks de referencia

- **MITRE ATT&CK** — Mapping de técnicas en cada playbook
- **PICERL / NIST SP 800-61** — Ciclo de respuesta a incidentes
- **NIST CSF** — Marco de ciberseguridad
- **ENS** (Esquema Nacional de Seguridad) — Regulación española
- **RGPD / LOPDGDD** — Protección de datos (notificación 72h a AEPD)

---

## 📂 Estructura del repositorio

```
.
├── README.md                          ← Este archivo
├── playbooks/
│   ├── PB-01_Brute_Force.md
│   ├── PB-02_Phishing.md
│   ├── PB-03_Malware.md
│   ├── PB-04_Ransomware.md
│   ├── PB-05_Lateral_Movement.md
│   ├── PB-06_Data_Exfiltration.md
│   ├── PB-07_Web_Attacks.md
│   ├── PB-08_Insider_Threat.md
│   ├── PB-09_C2.md
│   ├── PB-10_Privilege_Escalation.md
│   ├── PB-11_DDoS.md
│   └── PB-12_Supply_Chain.md
└── assets/
    └── playbooks_soc_btl1.html        ← Dashboard interactivo (versión navegable)
```

---

## 🎓 Certificaciones alineadas

- **BTL1** (Blue Team Level 1) — Security Blue Team
- **CompTIA Security+**

---

## 📄 Licencia

Este repositorio es material de estudio y portfolio profesional. Uso libre con atribución.
