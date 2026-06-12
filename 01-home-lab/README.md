# 🏠 Homelab — Entorno de Ciberseguridad

Laboratorio personal para práctica de detección, análisis y respuesta ante incidentes (Blue Team / Red Team).


## Descripción general

Este homelab simula un entorno corporativo básico con capacidad de monitorización centralizada. El objetivo es practicar técnicas de ataque y defensa en un entorno controlado: desde la generación de eventos maliciosos hasta su detección e investigación mediante SIEM.

```
Red Team  ──►  Kali Linux  ──attack──►  Windows 11 (víctima)
                                               │
                                        logs / eventos
                                               │
                                               ▼
                                     Ubuntu Server (Splunk)
```


## Arquitectura

```
┌─────────────────────────────────────────────────────────────┐
│                        Red de Homelab                       │
│                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │  Kali Linux  │    │  Windows 11  │    │Ubuntu Server │   │
│  │              │───►│   (víctima)  │───►│    Splunk    │   │
│  │  Atacante    │    │              │    │    SIEM      │   │
│  │              │    │  Sysmon +    │    │              │   │
│  │  Red Team    │    │  Splunk UF   │    │  Blue Team   │   │
│  └──────────────┘    └──────────────┘    └──────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Topología de red

| Segmento | Descripción |
|----------|-------------|
| Red interna del hypervisor / switch | Comunicación entre todas las VMs |
| Acceso externo (opcional) | Solo Ubuntu Server, para gestión vía SSH |


## Máquinas del entorno

### Ubuntu Server — SIEM (Splunk)

| Parámetro | Valor |
|-----------|-------|
| **Rol** | Servidor de monitorización centralizada |
| **OS** | Ubuntu Server 22.04 LTS |
| **Software principal** | Splunk Enterprise (free tier) |
| **Función** | Recepción, indexación y análisis de logs |

**Responsabilidades:**
- Recibir logs del agente Splunk Universal Forwarder instalado en la víctima
- Crear dashboards de detección y alertas
- Correlacionar eventos para identificar comportamiento malicioso

**Puertos relevantes:**
- `8000` — Interfaz web de Splunk
- `9997` — Recepción de datos del Universal Forwarder
- `22` — SSH para administración


### 🔴 Kali Linux — Atacante

| Parámetro | Valor |
|-----------|-------|
| **Rol** | Máquina ofensiva (Red Team) |
| **OS** | Kali Linux (rolling release) |
| **Software principal** | Metasploit, Nmap, Impacket, etc. |
| **Función** | Generación de actividad maliciosa controlada |

**Responsabilidades:**
- Ejecutar ataques contra la máquina víctima
- Simular TTPs reales (MITRE ATT&CK)
- Generar tráfico y eventos que puedan ser detectados en Splunk

**Herramientas comunes:**
- Reconocimiento: `nmap`, `netdiscover`
- Explotación: `metasploit`, `msfvenom`
- Post-explotación: `impacket`, `mimikatz` (vía payload)
- C2 (opcional): `Covenant`, `Sliver`


### 🟡 Windows 11 — Víctima

| Parámetro | Valor |
|-----------|-------|
| **Rol** | Endpoint objetivo de los ataques |
| **OS** | Windows 11 |
| **Software principal** | Splunk Universal Forwarder + Sysmon |
| **Función** | Generar telemetría de eventos ante ataques |

**Responsabilidades:**
- Enviar logs al servidor Splunk via Universal Forwarder
- Tener Sysmon configurado para captura granular de eventos
- Simular un endpoint corporativo desprotegido

**Configuración utilizada:**
- Sysmon con configuración de [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config)
- Windows Defender **deshabilitado** (entorno de lab controlado)
- Splunk UF apuntando a la IP del Ubuntu Server (puerto 9997)


## Flujo de datos

```
1. Kali lanza ataque  ──►  Windows 11
                               │
                    Sysmon captura eventos
                    (procesos, red, registro...)
                               │
                    Splunk Universal Forwarder
                    envía logs en tiempo real
                               │
                               ▼
                    Ubuntu Server (Splunk)
                    indexa y correlaciona
                               │
                               ▼
                    Dashboard / Alertas / Hunts
```

### Ejemplos de eventos capturados

| Técnica ATT&CK | Evento Sysmon | ID Evento |
|----------------|---------------|-----------|
| Process Injection | CreateRemoteThread | 8 |
| Lateral Movement | Network Connection | 3 |
| Persistence | Registry modification | 12/13 |
| Credential Access | LSASS Access | 10 |
| Execution | Process Create | 1 |


## Casos de uso

- [ ] **Reconocimiento de red** — Nmap scan desde Kali, detección en Splunk
- [ ] **Reverse Shell** — Payload msfvenom ejecutado en Windows, alertas en SIEM
- [ ] **Pass the Hash** — Movimiento lateral con Impacket, logs de autenticación
- [ ] **Persistence** — Creación de tareas programadas, detección por Sysmon
- [ ] **Exfiltración simulada** — Transferencia de archivos, detección por volumen de red


*Laboratorio montado con fines educativos. Todo el tráfico malicioso se genera en una red aislada y controlada.*
