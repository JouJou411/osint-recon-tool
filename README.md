# 🛡️ osint-recon-tool

Herramienta CLI modular de **reconocimiento OSINT y auditoría defensiva** (Blue Team / CTI) para investigar números telefónicos y correos electrónicos, detectar su exposición en filtraciones de datos y generar un **plan de remediación accionable**.

> ⚠️ **Uso ético:** utilízala únicamente sobre activos propios o con autorización expresa por escrito. El objetivo es proteger, no perfilar a terceros.

---

## ✨ Funcionalidades

| Módulo | Capacidades |
|---|---|
| `phone_recon.py` | Validación y normalización E.164 (`phonenumbers`), país, región/LADA, operadora original, zonas horarias, tipo de línea, variantes de formato y **Google Dorks** (redes sociales, mensajería, documentos, spam, marketplaces, pastes). Enriquecimiento opcional con **Numverify**. |
| `email_recon.py` | Usuario/alias de pivote y dominio, registros **MX / SPF / DMARC** (`dnspython`) con evaluación de seguridad, detección de proveedor, perfil **Gravatar** (MD5) y comprobaciones **asíncronas** (`httpx.AsyncClient`) en GitHub (usuarios y commits por correo, alias) y GitLab. |
| `username_recon.py` | Rastreo asíncrono de perfiles públicos para un alias en 12 plataformas (GitHub, GitLab, Reddit, Dev.to, Medium, Pinterest, Vimeo, About.me, Docker Hub, PyPI, Hacker News y Keybase). |
| `domain_recon.py` | Subdominios desde **Certificate Transparency (`crt.sh`)** sin duplicados e inteligencia **WHOIS** (registrador, creación, expiración, servidores DNS) con `python-whois`. |
| `graph_builder.py` | Visualizador interactivo de relaciones con `networkx` y `pyvis` (tema oscuro, nodos coloreados por categoría y leyenda) exportado en `reports/grafo_*.html`. |
| `breach_auditor.py` | **Pwned Passwords** con *k-Anonymity* (solo 5 caracteres del SHA-1), generador criptográfico (`secrets`) validado con 0 apariciones, **HIBP v3** (con API key) o catálogo público de brechas (sin llave), y **Motor de Remediación** por reglas. |
| `report_exporter.py` | Exporta la sesión completa a `reports/*.json` y `reports/*.html` (nunca se guardan contraseñas en texto plano). |

## 📁 Estructura

```
osint-recon-tool/
├── main.py
├── requirements.txt
├── .env.example
├── README.md
├── modules/
│   ├── __init__.py
│   ├── phone_recon.py
│   ├── email_recon.py
│   ├── username_recon.py
│   ├── domain_recon.py
│   ├── graph_builder.py
│   ├── breach_auditor.py
│   └── report_exporter.py
└── reports/            # se crea automáticamente
```

## ⚙️ Instalación

Requisitos: **Python 3.10+**

```powershell
# Windows (PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env      # opcional: añade tus API keys
```

```bash
# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

### Variables de entorno (opcionales)

| Variable | Uso |
|---|---|
| `HIBP_API_KEY` | Consulta brechas y pastes de un correo específico en HIBP v3. Sin ella se usa el catálogo público. |
| `NUMVERIFY_API_KEY` | Enriquece el tipo de línea (móvil / fija / VoIP). Sin ella se omite sin errores. |
| `HTTP_TIMEOUT` | Timeout en segundos para peticiones HTTP (por defecto `10`). |
| `DEFAULT_PHONE_REGION` | Región ISO para números sin `+` (por defecto `MX`). |

## 🚀 Uso

### Menú interactivo
```bash
python main.py
```

### Modo comandos
```bash
# Teléfono
python main.py phone "+52 55 1234 5678"
python main.py phone "5512345678" --region MX

# Correo (OSINT + DNS + pivote automático opcional a alias y dominio)
python main.py email usuario@dominio.com --chain --graph

# Rastreo de alias en plataformas públicas
python main.py alias octocat

# Inteligencia de dominio (crt.sh + WHOIS)
python main.py domain example.com

# Brechas de un correo
python main.py breaches usuario@dominio.com

# Verificar contraseña (entrada oculta, k-Anonymity)
python main.py password

# Generar contraseña segura verificada
python main.py genpass --length 24
python main.py genpass --length 16 --no-symbols

# Auditoría completa (pivotes + brechas + remediación + grafo interactivo + reporte)
python main.py audit --email usuario@dominio.com --phone "+525512345678" --check-password --export
```

Todos los subcomandos (excepto `password`) aceptan `--export` y `--output-dir <ruta>`.

## 🔐 Privacidad y seguridad del diseño

- **k-Anonymity:** a Pwned Passwords solo se envía el prefijo de 5 caracteres del SHA-1, con cabecera `Add-Padding` para dificultar el análisis de tráfico.
- Las contraseñas verificadas o generadas **no se escriben** en los reportes; solo metadatos (prefijo, conteo, entropía).
- Todas las peticiones tienen timeouts y manejo de errores (rate limit, 401, 404, timeouts DNS/HTTP).

## 🧭 Motor de remediación

Clasifica cada hallazgo por **severidad** (CRÍTICA, ALTA, MEDIA, BAJA) y **origen** (`confirmado`, `posible`, `hallazgo DNS`, `preventivo`):

| Dato expuesto | Ejemplos de acciones |
|---|---|
| Passwords | Rotación inmediata, gestor de contraseñas, MFA FIDO2/TOTP, revocar sesiones. |
| Phone numbers | NIP de portabilidad anti **SIM Swapping**, migrar 2FA de SMS a TOTP, PIN de WhatsApp, REPEP. |
| Email addresses | Alias por servicio, MFA en el correo, revisión de reglas de reenvío. |
| Credit cards | Bloqueo y reemisión, alertas de transacciones, tarjetas virtuales. |
| IP addresses | Renovar IP, firmware del router, revisar puertos en Shodan, VPN. |
| DNS del dominio | Publicar/endurecer SPF (`-all`) y DMARC (`p=reject`). |

## 📄 Reportes

Se generan en `reports/osint_report_YYYYMMDD_HHMMSS.{json,html}`. El HTML es autocontenido (CSS embebido) y puede abrirse en cualquier navegador.

## ⚠️ Limitaciones

- La operadora de `phonenumbers` es la **original** del bloque numérico (no refleja portabilidad).
- En México la numeración no distingue fijo/móvil desde 2019; usa Numverify para mayor precisión.
- Las APIs de búsqueda de GitHub sin autenticación tienen límites bajos (~10 req/min).
- Sin `HIBP_API_KEY` no es posible confirmar si un correo concreto aparece en brechas.
