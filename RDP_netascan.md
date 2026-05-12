# RDP — `netascan` (net-audit-scanner)

### Aplicación de Auditoría de Seguridad de Red para Linux

**Versión:** 1.0  
**Fecha:** Mayo 2026  
**Estado:** Propuesta inicial  
**Audiencia:** Equipo de desarrollo, revisores técnicos  
**Repositorio:** `net-audit-scanner`  
**Binario:** `/usr/local/bin/netascan`

---

## 1. Resumen ejecutivo

netascan es una herramienta de línea de comandos y servidor web local para Linux que escanea redes domésticas y corporativas pequeñas, identifica dispositivos activos, detecta vulnerabilidades conocidas cruzando datos con la NVD (National Vulnerability Database) y genera reportes en HTML/JSON/PDF. El lenguaje principal es **Rust**, complementado con Python para integraciones de escaneo.

---

## 2. Problema que resuelve

La mayoría de usuarios con dispositivos IoT, cámaras IP, routers o NAS en su red doméstica o de oficina no tienen visibilidad sobre:

- Qué dispositivos están conectados a su red
- Si esos dispositivos tienen puertos innecesariamente expuestos
- Si el firmware o software de esos dispositivos tiene CVEs (vulnerabilidades públicas conocidas)
- Si se están usando contraseñas por defecto o protocolos inseguros (Telnet, FTP, HTTP sin cifrar)

No existe una herramienta de código abierto, unificada y fácil de usar para Linux que cubra todo el ciclo: **descubrir → identificar → cruzar con CVEs → reportar**.

---

## 3. Lenguaje y justificación técnica

### Lenguaje principal: Rust

| Criterio | Justificación |
|---|---|
| Rendimiento | El escaneo de puertos es intensivo en I/O concurrente. Rust con `tokio` maneja miles de conexiones asíncronas sin overhead |
| Seguridad de memoria | Sin garbage collector, sin data races. Crítico en una herramienta que opera con sockets raw |
| Binario único | Compila a un ejecutable estático sin dependencias. Instalación trivial en cualquier distro Linux |
| Ecosistema de red | Crates maduros: `tokio`, `pnet` (raw sockets), `reqwest` (HTTP async), `trust-dns` |
| CLI ergonómica | `clap` para parsing de argumentos es el estándar de facto |

### Componentes auxiliares en Python

El fingerprinting avanzado de dispositivos y la integración con `nmap` se delegan a Python mediante subprocess o una API interna, ya que el ecosistema de scripts de detección de `nmap` (NSE) y librerías como `scapy` son insuperables para esa tarea concreta.

### Stack completo

```
netascan (Rust)
├── scanner/        → tokio async TCP/UDP port scanner
├── fingerprint/    → MAC OUI lookup, banner grabbing, OS detection
├── cve/            → cliente NVD API v2, cache local SQLite
├── report/         → generador HTML/JSON, servidor web local
└── cli/            → interfaz clap, configuración TOML

helper/ (Python)
├── nmap_bridge.py  → invoca nmap -sV y parsea XML output
└── shodan_check.py → consulta opcional Shodan API
```

---

## 4. Funcionalidades requeridas

### 4.1 Módulo de descubrimiento de red

- Ping sweep (ICMP + TCP SYN) para detectar hosts activos en un rango CIDR
- Resolución de nombres de host (mDNS/DNS)
- Lectura de tabla ARP local para obtener MACs sin necesidad de root
- Detección del gateway y rango de red automáticamente

**Ejemplo de uso:**

```bash
netascan scan --network 192.168.1.0/24
netascan scan --network auto   # detecta la red local automáticamente
```

### 4.2 Módulo de escaneo de puertos y servicios

- Escaneo TCP de puertos comunes (top-1000 de nmap) y puertos críticos de IoT
- Detección de servicios por banner grabbing (HTTP, SSH, Telnet, FTP, RTSP, MQTT, UPnP)
- Identificación de protocolos inseguros activos

**Puertos de especial interés para IoT:**

| Puerto | Protocolo | Riesgo |
|---|---|---|
| 23 | Telnet | Crítico — credenciales en claro |
| 21 | FTP | Alto — transferencia sin cifrar |
| 554 | RTSP | Alto — streaming de cámaras sin auth |
| 1883 | MQTT | Medio — brokers IoT sin autenticación |
| 8080, 8888 | HTTP alternativo | Medio — paneles admin expuestos |
| 37777 | Dahua DVR | Crítico — protocolo propietario vulnerable |
| 34567 | HiSilicon DVR | Crítico — backdoor conocido |

### 4.3 Módulo de fingerprinting de dispositivos

- Lookup de fabricante por OUI (primeros 3 bytes de MAC) usando la base de datos IEEE
- Identificación de modelo y firmware por banner HTTP/SSH/Telnet
- Clasificación automática: router, cámara, NAS, smart TV, IoT genérico, PC, móvil

**APIs y fuentes usadas:**

```
https://api.macvendors.com/{MAC}           → fabricante por OUI
https://api.macaddress.io/v1?output=json   → alternativa con más datos
Tabla OUI local (IEEE, actualizable)        → fallback sin red
```

### 4.4 Módulo de correlación con CVEs

Esta es la pieza central del valor de la herramienta. El flujo es:

```
Dispositivo identificado
        ↓
Extraer: vendor + product + version
        ↓
Query NVD API v2:
GET https://services.nvd.nist.gov/rest/json/cves/2.0
    ?keywordSearch=hikvision+camera
    &cvssV3Severity=HIGH
        ↓
Parsear CVEs → CVSS score, descripción, fecha, parche disponible
        ↓
Caché local SQLite (TTL 24h para no saturar la API)
        ↓
Asociar CVEs al dispositivo en el reporte
```

**Otras fuentes de CVEs:**

| Fuente | URL | Notas |
|---|---|---|
| NVD (NIST) | `services.nvd.nist.gov/rest/json/cves/2.0` | Principal, gratuita, requiere API key para más de 5 req/30s |
| CVE Search (CIRCL) | `cve.circl.lu/api/search/{vendor}/{product}` | Más simple, sin API key, búsqueda por vendor/product |
| OSV (Google) | `api.osv.dev/v1/query` | Buena para software open source |
| Shodan | `api.shodan.io` | Opcional, requiere cuenta, muy potente |

### 4.5 Módulo de checks de seguridad

Además de los CVEs, la herramienta realiza comprobaciones activas:

- Intento de login con credenciales por defecto (lista curada por fabricante) en servicios detectados
- Verificación de cifrado: si un servicio HTTP no redirige a HTTPS, se marca
- Detección de WPS activo en routers vía UPnP
- Verificación de que el panel de administración del router no está expuesto en WAN
- Check de versión mínima de TLS en servicios HTTPS

> **Nota ética:** los intentos de login con credenciales por defecto se hacen con un único intento (sin brute force) y solo dentro del rango de red local del usuario.

### 4.6 Módulo de reportes

Tres formatos de salida:

**JSON** — para integración con otras herramientas:
```bash
netascan report --format json --output reporte.json
```

**HTML** — reporte visual auto-contenido (sin dependencias externas):
```bash
netascan report --format html --output reporte.html
```

**Servidor web local** — dashboard interactivo en `localhost:7070`:
```bash
netascan serve
# Abre http://localhost:7070 en el navegador
```

El reporte HTML incluye: resumen ejecutivo con score de riesgo global, tabla de dispositivos con sus CVEs, sección de recomendaciones priorizadas por severidad y línea de tiempo de escaneos anteriores.

---

## 5. Arquitectura del sistema

```
┌─────────────────────────────────────────────────────┐
│                    CLI (clap)                       │
│        netascan scan | report | serve | update      │
└────────────────────┬────────────────────────────────┘
                     │
        ┌────────────▼────────────┐
        │     Orchestrator        │
        │   (tokio async runtime) │
        └──┬──────┬──────┬───────┘
           │      │      │
    ┌──────▼─┐ ┌──▼───┐ ┌▼──────────┐
    │Scanner │ │Finger│ │CVE Engine  │
    │        │ │print │ │            │
    │TCP/UDP │ │OUI   │ │NVD API     │
    │ping    │ │banner│ │CVE Search  │
    │arp     │ │nmap  │ │SQLite cache│
    └──────┬─┘ └──┬───┘ └┬──────────┘
           │      │       │
        ┌──▼──────▼───────▼──┐
        │   Result Aggregator │
        └──────────┬──────────┘
                   │
        ┌──────────▼──────────┐
        │   Report Generator  │
        │  JSON / HTML / Web  │
        └─────────────────────┘
```

### Almacenamiento local

```
~/.netascan/
├── config.toml         → configuración del usuario
├── oui.db              → base de datos MAC OUI (actualizable)
├── cve_cache.db        → caché SQLite de CVEs consultados
└── reports/
    ├── 2026-05-12.json
    └── 2026-05-12.html
```

---

## 6. Permisos y seguridad

El escaneo de puertos TCP básico funciona sin root. Las siguientes funciones requieren `sudo` o `CAP_NET_RAW`:

| Función | Requiere root | Alternativa sin root |
|---|---|---|
| ICMP ping sweep | Sí | TCP SYN al puerto 80 |
| ARP scan (más fiable) | Sí | Leer `/proc/net/arp` |
| Raw packet crafting | Sí | No disponible |
| TCP connect scan | No | Disponible siempre |

La herramienta detecta automáticamente si tiene los permisos necesarios y degrada gracefully a las alternativas sin root cuando no los tiene, informando al usuario.

---

## 7. Configuración

Archivo `~/.netascan/config.toml`:

```toml
[scan]
default_network = "auto"
port_range = "top-1000"       # top-100 | top-1000 | full | custom
timeout_ms = 1500
concurrency = 512              # conexiones simultáneas

[cve]
nvd_api_key = ""               # opcional, aumenta rate limit
sources = ["nvd", "circl"]    # nvd | circl | osv | shodan
cache_ttl_hours = 24

[report]
default_format = "html"
open_browser = true            # abre el reporte al terminar

[credentials_check]
enabled = true
custom_list = ""               # ruta a lista adicional de credenciales
```

---

## 8. Interfaz de usuario (CLI)

```bash
# Escaneo completo con reporte HTML
netascan scan --network auto --report html

# Solo descubrir dispositivos, sin CVEs (rápido)
netascan scan --network 192.168.1.0/24 --no-cve

# Escanear un dispositivo concreto en profundidad
netascan scan --target 192.168.1.101 --full

# Lanzar el dashboard web
netascan serve --port 7070

# Actualizar base de datos OUI y credenciales por defecto
netascan update

# Ver el último reporte guardado
netascan report --last --format html
```

---

## 9. Roadmap de desarrollo

### Fase 1 — MVP (8 semanas)

- Descubrimiento de red (ping sweep + ARP)
- Escaneo de puertos TCP top-1000
- Lookup OUI (fabricante)
- Integración NVD API con caché SQLite
- Reporte JSON y HTML estático

### Fase 2 — Detección avanzada (6 semanas)

- Banner grabbing y fingerprinting de servicios
- Check de credenciales por defecto
- Integración con nmap -sV mediante subprocess
- Servidor web local con dashboard
- Reporte con histórico de escaneos

### Fase 3 — Productización (4 semanas)

- Integración opcional con Shodan API
- Notificaciones (email/webhook) cuando aparece nuevo dispositivo o CVE crítico
- Empaquetado: .deb, .rpm, AUR (Arch), Flatpak
- Documentación y página man

---

## 10. Dependencias principales

### Rust crates

| Crate | Versión | Uso |
|---|---|---|
| `tokio` | 1.x | Runtime async |
| `pnet` | 0.34 | Raw sockets, ICMP, ARP |
| `reqwest` | 0.12 | Cliente HTTP async para APIs |
| `sqlx` | 0.7 | SQLite async (caché CVE) |
| `clap` | 4.x | CLI parsing |
| `serde` / `serde_json` | 1.x | Serialización |
| `tera` | 1.x | Templates para HTML |
| `axum` | 0.7 | Servidor web del dashboard |
| `tracing` | 0.1 | Logging estructurado |

### Herramientas del sistema (opcionales)

- `nmap` — para fingerprinting avanzado (-sV)
- `python3` — para scripts NSE y scapy

---

## 11. Consideraciones legales y éticas

- La herramienta está diseñada exclusivamente para escanear **redes propias**. Escanear redes ajenas sin autorización es ilegal en la mayoría de jurisdicciones.
- El binario mostrará un aviso explícito en el primer uso solicitando confirmación de que el usuario es el propietario o administrador de la red a escanear.
- Los intentos de login con credenciales por defecto se limitan a **un único intento por dispositivo** para evitar bloqueos y no constituir un ataque de fuerza bruta.
- No se envía ningún dato a servidores externos excepto las queries a APIs públicas de CVEs (NVD, CIRCL), que solo contienen nombres de fabricantes/productos, nunca IPs privadas.

---

## 12. Criterios de aceptación del MVP

- Detecta todos los dispositivos activos en una red /24 en menos de 30 segundos
- Identifica correctamente el fabricante del 80% de dispositivos vía OUI
- Retorna CVEs de la NVD para al menos los fabricantes más comunes de IoT (Hikvision, TP-Link, Netgear, Dahua, D-Link, Xiaomi, Asus)
- Genera un reporte HTML válido que abre correctamente en Firefox/Chrome sin servidor
- El binario compilado ocupa menos de 15 MB y no requiere dependencias instaladas para las funciones básicas
- Funciona sin root con degradación graceful documentada

---

*RDP preparado para revisión técnica. Pendiente de aprobación antes de iniciar Fase 1.*
