"""Auditoría de brechas y motor de remediación.

- Pwned Passwords (k-Anonymity): solo se envían los 5 primeros caracteres del SHA-1.
- Generador criptográfico de contraseñas validado contra Pwned Passwords.
- Have I Been Pwned v3 (con API key) o catálogo público de brechas (sin llave).
- Motor de remediación basado en reglas por tipo de dato expuesto.
"""

from __future__ import annotations

import hashlib
import html
import math
import os
import re
import secrets
import string
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable
from urllib.parse import quote

import httpx

from modules import USER_AGENT

PWNED_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
HIBP_BASE_URL = "https://haveibeenpwned.com/api/v3"
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/~"


class BreachAuditorError(Exception):
    """Error controlado durante la auditoría de brechas."""


# --------------------------------------------------------------------------- #
# Pwned Passwords (k-Anonymity)
# --------------------------------------------------------------------------- #
def sha1_hex(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest().upper()


def check_password_pwned(password: str, timeout: float = 10.0, client: httpx.Client | None = None) -> dict[str, Any]:
    """Devuelve cuántas veces aparece la contraseña en filtraciones usando k-Anonymity.

    Nunca se envía la contraseña ni el hash completo: solo el prefijo de 5 caracteres.
    """
    if not password:
        raise BreachAuditorError("La contraseña está vacía.")

    digest = sha1_hex(password)
    prefix, suffix = digest[:5], digest[5:]
    headers = {"User-Agent": USER_AGENT, "Add-Padding": "true"}

    own_client = client is None
    http = client or httpx.Client(timeout=timeout, headers=headers)
    try:
        response = http.get(PWNED_RANGE_URL.format(prefix=prefix), headers=headers)
        response.raise_for_status()
    except httpx.TimeoutException as exc:
        raise BreachAuditorError("Timeout consultando Pwned Passwords.") from exc
    except httpx.HTTPError as exc:
        raise BreachAuditorError(f"Error consultando Pwned Passwords: {exc}") from exc
    finally:
        if own_client:
            http.close()

    count = 0
    for line in response.text.splitlines():
        candidate, _, hits = line.strip().partition(":")
        if candidate.upper() == suffix:
            count = int(hits or 0)
            break

    return {
        "sha1_prefix": prefix,
        "count": count,
        "exposed": count > 0,
        "candidates_in_range": len(response.text.splitlines()),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


def _password_entropy(length: int, alphabet_size: int) -> float:
    return round(length * math.log2(alphabet_size), 2)


def generate_secure_password(length: int = 20, use_symbols: bool = True, max_attempts: int = 10, timeout: float = 10.0) -> dict[str, Any]:
    """Genera una contraseña con ``secrets`` y la valida contra Pwned Passwords (0 apariciones)."""
    if length < 12:
        raise BreachAuditorError("La longitud mínima recomendada es 12 caracteres.")

    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if use_symbols:
        pools.append(SYMBOLS)
    alphabet = "".join(pools)
    rng = secrets.SystemRandom()

    last_error = ""
    with httpx.Client(timeout=timeout, headers={"User-Agent": USER_AGENT}) as client:
        for attempt in range(1, max_attempts + 1):
            chars = [secrets.choice(pool) for pool in pools]  # garantiza cada clase
            chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
            rng.shuffle(chars)
            candidate = "".join(chars)
            try:
                check = check_password_pwned(candidate, client=client)
            except BreachAuditorError as exc:
                last_error = str(exc)
                continue
            if check["count"] == 0:
                return {
                    "password": candidate,
                    "length": length,
                    "alphabet_size": len(alphabet),
                    "entropy_bits": _password_entropy(length, len(alphabet)),
                    "pwned_count": 0,
                    "verified": True,
                    "attempts": attempt,
                }

    return {
        "password": "",
        "length": length,
        "alphabet_size": len(alphabet),
        "entropy_bits": _password_entropy(length, len(alphabet)),
        "pwned_count": None,
        "verified": False,
        "attempts": max_attempts,
        "error": last_error or "No se obtuvo una contraseña con 0 apariciones.",
    }


# --------------------------------------------------------------------------- #
# Have I Been Pwned v3
# --------------------------------------------------------------------------- #
def _clean_html(text: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", text or "")).strip()


def _simplify_breach(b: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": b.get("Name", ""),
        "title": b.get("Title", ""),
        "domain": b.get("Domain", ""),
        "breach_date": b.get("BreachDate", ""),
        "added_date": b.get("AddedDate", ""),
        "pwn_count": b.get("PwnCount", 0),
        "data_classes": b.get("DataClasses", []) or [],
        "is_verified": b.get("IsVerified", False),
        "is_sensitive": b.get("IsSensitive", False),
        "description": _clean_html(b.get("Description", ""))[:400],
    }


def _hibp_get(client: httpx.Client, url: str, params: dict[str, Any] | None = None) -> httpx.Response:
    """GET con un reintento respetando Retry-After en caso de 429."""
    response = client.get(url, params=params)
    if response.status_code == 429:
        retry_after = int(response.headers.get("retry-after", "2") or 2)
        if retry_after <= 10:
            time.sleep(retry_after)
            response = client.get(url, params=params)
    return response


def check_email_breaches(email: str, api_key: str | None = None, timeout: float = 15.0, recent_limit: int = 10) -> dict[str, Any]:
    """Consulta HIBP v3 si hay llave; si no, devuelve el catálogo público de brechas recientes."""
    email_n = (email or "").strip().lower()
    if "@" not in email_n:
        raise BreachAuditorError("Correo inválido para auditoría de brechas.")
    domain = email_n.rsplit("@", 1)[1]
    key = (api_key or os.getenv("HIBP_API_KEY", "")).strip()

    result: dict[str, Any] = {
        "email": email_n,
        "mode": "authenticated" if key else "public_catalog",
        "status": "unknown",
        "breach_count": 0,
        "breaches": [],
        "pastes": [],
        "data_classes": [],
        "potential_data_classes": [],
        "recent_breaches": [],
        "domain_related_breaches": [],
        "message": "",
    }

    headers = {"User-Agent": USER_AGENT}
    if key:
        headers["hibp-api-key"] = key

    try:
        with httpx.Client(timeout=timeout, headers=headers) as client:
            if key:
                resp = _hibp_get(client, f"{HIBP_BASE_URL}/breachedaccount/{quote(email_n)}", {"truncateResponse": "false"})
                if resp.status_code == 404:
                    result["status"] = "clean"
                    result["message"] = "El correo no aparece en brechas conocidas de HIBP."
                elif resp.status_code == 200:
                    breaches = [_simplify_breach(b) for b in resp.json()]
                    result["breaches"] = sorted(breaches, key=lambda b: b["breach_date"], reverse=True)
                    result["breach_count"] = len(breaches)
                    result["data_classes"] = sorted({dc for b in breaches for dc in b["data_classes"]})
                    result["status"] = "breached"
                    result["message"] = f"El correo aparece en {len(breaches)} brecha(s)."
                elif resp.status_code == 401:
                    result["status"] = "error"
                    result["message"] = "HIBP_API_KEY inválida o expirada (HTTP 401)."
                    return result
                elif resp.status_code == 429:
                    result["status"] = "error"
                    result["message"] = "Límite de peticiones de HIBP alcanzado (HTTP 429)."
                    return result
                else:
                    result["status"] = "error"
                    result["message"] = f"Respuesta inesperada de HIBP: HTTP {resp.status_code}"
                    return result

                paste_resp = _hibp_get(client, f"{HIBP_BASE_URL}/pasteaccount/{quote(email_n)}")
                if paste_resp.status_code == 200:
                    result["pastes"] = [
                        {
                            "source": p.get("Source", ""),
                            "id": p.get("Id", ""),
                            "title": p.get("Title") or "",
                            "date": p.get("Date") or "",
                            "email_count": p.get("EmailCount", 0),
                        }
                        for p in paste_resp.json() or []
                    ]
            else:
                resp = client.get(f"{HIBP_BASE_URL}/breaches")
                resp.raise_for_status()
                catalog = [_simplify_breach(b) for b in resp.json()]
                catalog.sort(key=lambda b: b["added_date"], reverse=True)
                result["recent_breaches"] = catalog[:recent_limit]
                related = [b for b in catalog if b["domain"] and (b["domain"] == domain or domain.endswith("." + b["domain"]))]
                result["domain_related_breaches"] = related
                result["potential_data_classes"] = sorted({dc for b in related for dc in b["data_classes"]})
                result["status"] = "unknown"
                result["message"] = (
                    "Sin HIBP_API_KEY: no es posible verificar el correo individualmente. "
                    f"Se muestran las {len(result['recent_breaches'])} brechas más recientes del catálogo público"
                    + (f" y {len(related)} brecha(s) asociadas al dominio {domain}." if related else ".")
                )
    except httpx.TimeoutException as exc:
        raise BreachAuditorError("Timeout consultando Have I Been Pwned.") from exc
    except httpx.HTTPError as exc:
        raise BreachAuditorError(f"Error consultando Have I Been Pwned: {exc}") from exc
    except ValueError as exc:
        raise BreachAuditorError("Respuesta JSON inválida de Have I Been Pwned.") from exc

    return result


# --------------------------------------------------------------------------- #
# Motor de remediación
# --------------------------------------------------------------------------- #
SEVERITY_ORDER = ["CRÍTICA", "ALTA", "MEDIA", "BAJA"]
TRIGGER_ORDER = ["confirmado", "posible", "hallazgo DNS", "preventivo"]


@dataclass(frozen=True)
class RemediationRule:
    data_class: str
    category: str
    severity: str
    actions: tuple[str, ...]


@dataclass
class RemediationItem:
    data_class: str
    category: str
    severity: str
    trigger: str
    actions: list[str] = field(default_factory=list)


REMEDIATION_RULES: dict[str, RemediationRule] = {
    "passwords": RemediationRule(
        "Passwords", "Credenciales", "CRÍTICA",
        (
            "Rotar inmediatamente la contraseña en el servicio afectado y en TODOS los servicios donde se reutilizó.",
            "Generar contraseñas únicas (≥16 caracteres) con un gestor (Bitwarden, KeePassXC, 1Password).",
            "Activar MFA resistente a phishing: llaves FIDO2/passkeys o app TOTP (Aegis, Authy, Google Authenticator).",
            "Cerrar todas las sesiones activas y revocar tokens/contraseñas de aplicación y OAuth de terceros.",
            "Validar cada nueva contraseña contra Pwned Passwords (k-Anonymity) antes de usarla.",
        ),
    ),
    "phone numbers": RemediationRule(
        "Phone numbers", "Telefonía / identidad", "ALTA",
        (
            "Solicitar a la operadora un NIP/PIN de portabilidad y bloqueo de cambio de SIM para prevenir SIM Swapping.",
            "Migrar el 2FA basado en SMS a app TOTP o passkeys en banca, correo y redes sociales.",
            "Eliminar el número como método de recuperación donde exista una alternativa más segura.",
            "Activar la verificación en dos pasos (PIN) de WhatsApp y la contraseña en la nube de Telegram.",
            "Ocultar el número en perfiles públicos (Facebook, Instagram, LinkedIn, Truecaller) y apps de identificación.",
            "Alertar sobre smishing/vishing: no compartir códigos OTP ni NIP por llamada o mensaje.",
            "En México: registrar el número en el REPEP (Profeco) para reducir llamadas comerciales.",
        ),
    ),
    "email addresses": RemediationRule(
        "Email addresses", "Correo electrónico", "MEDIA",
        (
            "Usar alias de correo por servicio (SimpleLogin, Firefox Relay, Apple Hide My Email o sub-direcciones +tag).",
            "Activar MFA robusto en la cuenta de correo: es la llave maestra para recuperar el resto de cuentas.",
            "Revisar reglas de reenvío, filtros y aplicaciones conectadas en busca de persistencia de un atacante.",
            "Reforzar el filtrado anti-phishing y desconfiar de correos que citen la filtración.",
            "Suscribirse a notificaciones de HIBP para recibir alertas de nuevas brechas.",
        ),
    ),
    "credit cards": RemediationRule(
        "Credit cards", "Financiero", "CRÍTICA",
        (
            "Contactar al banco para bloquear y reemitir la tarjeta comprometida.",
            "Activar notificaciones en tiempo real de cada transacción.",
            "Usar tarjetas digitales/virtuales de un solo uso para compras en línea.",
            "Revisar estados de cuenta de los últimos 90 días y disputar cargos no reconocidos.",
            "Consultar el Buró de Crédito para detectar créditos abiertos a tu nombre.",
        ),
    ),
    "ip addresses": RemediationRule(
        "IP addresses", "Red", "MEDIA",
        (
            "Si la IP es fija, solicitar al ISP una nueva asignación o reiniciar el módem si es dinámica.",
            "Actualizar el firmware del router y cambiar la contraseña de administración por defecto.",
            "Verificar puertos expuestos de tu IP en Shodan/Censys y cerrar servicios innecesarios (UPnP, RDP, SSH).",
            "Usar una VPN de confianza en redes públicas y para actividades sensibles.",
        ),
    ),
    "security questions and answers": RemediationRule(
        "Security questions and answers", "Recuperación de cuentas", "ALTA",
        (
            "Cambiar las preguntas de seguridad y usar respuestas falsas aleatorias guardadas en el gestor de contraseñas.",
            "Sustituir la recuperación por preguntas por métodos MFA o códigos de recuperación offline.",
        ),
    ),
    "usernames": RemediationRule(
        "Usernames", "Identidad digital", "MEDIA",
        (
            "Evitar reutilizar el mismo nombre de usuario en servicios sensibles para dificultar el pivoteo OSINT.",
            "Auditar perfiles públicos asociados al alias y eliminar cuentas en desuso.",
        ),
    ),
    "physical addresses": RemediationRule(
        "Physical addresses", "Privacidad física", "MEDIA",
        (
            "Estar alerta a paquetería o correspondencia fraudulenta y suplantación en trámites.",
            "Solicitar la eliminación de datos en sitios de people-search y directorios públicos.",
        ),
    ),
    "dates of birth": RemediationRule(
        "Dates of birth", "Identidad", "MEDIA",
        (
            "No usar la fecha de nacimiento como contraseña, PIN o respuesta de seguridad.",
            "Vigilar intentos de suplantación de identidad en bancos y servicios gubernamentales.",
        ),
    ),
    "government issued ids": RemediationRule(
        "Government issued IDs", "Identidad oficial", "CRÍTICA",
        (
            "Reportar la exposición del documento a la autoridad emisora y solicitar reposición si procede.",
            "Activar alertas de crédito/Buró y monitorear aperturas de cuentas a tu nombre.",
        ),
    ),
    "names": RemediationRule(
        "Names", "Identidad", "BAJA",
        ("Esperar campañas de phishing personalizadas que usen tu nombre real; verificar remitentes.",),
    ),
}

GENERIC_RULE_ACTIONS: tuple[str, ...] = (
    "Identificar el servicio afectado y revisar qué información personal contiene la cuenta.",
    "Cambiar credenciales del servicio y activar MFA si está disponible.",
    "Monitorear actividad sospechosa relacionada con este tipo de dato.",
)


class RemediationEngine:
    """Motor de reglas que transforma tipos de datos expuestos en acciones concretas."""

    def __init__(self, rules: dict[str, RemediationRule] | None = None) -> None:
        self.rules = rules or REMEDIATION_RULES

    @staticmethod
    def _downgrade(severity: str) -> str:
        idx = SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else len(SEVERITY_ORDER) - 1
        return SEVERITY_ORDER[min(idx + 1, len(SEVERITY_ORDER) - 1)]

    def rule_for(self, data_class: str) -> RemediationRule:
        rule = self.rules.get(data_class.strip().lower())
        if rule:
            return rule
        return RemediationRule(data_class, "Otros datos", "MEDIA", GENERIC_RULE_ACTIONS)

    @staticmethod
    def _dns_actions(dns_results: Iterable[dict[str, Any]]) -> list[str]:
        actions: list[str] = []
        for dns_r in dns_results:
            domain = dns_r.get("domain", "?")
            spf = dns_r.get("spf", {}) or {}
            dmarc = dns_r.get("dmarc", {}) or {}
            if dns_r.get("domain_exists") is False:
                actions.append(f"[{domain}] El dominio no existe: verificar el correo o posible dominio expirado (riesgo de takeover).")
                continue
            if not spf.get("present"):
                actions.append(f"[{domain}] Publicar un registro SPF terminando en '-all' con los remitentes autorizados.")
            elif spf.get("all_qualifier") in {"+all", "?all", ""}:
                actions.append(f"[{domain}] Endurecer SPF: cambiar '{spf.get('all_qualifier') or 'sin all'}' por '~all' o '-all'.")
            if not dmarc.get("present"):
                actions.append(f"[{domain}] Publicar DMARC (_dmarc.{domain}) iniciando con p=none + rua y escalar a p=reject.")
            elif dmarc.get("policy") == "none":
                actions.append(f"[{domain}] Escalar la política DMARC de p=none a p=quarantine/p=reject tras revisar reportes.")
            if not dns_r.get("mail_active"):
                actions.append(f"[{domain}] El dominio no tiene servidores de correo activos: el correo no puede recibir mensajes.")
        return actions

    def build_plan(
        self,
        data_classes: Iterable[str] = (),
        potential_data_classes: Iterable[str] = (),
        audited_phone: bool = False,
        audited_email: bool = False,
        password_exposed: bool = False,
        dns_results: Iterable[dict[str, Any]] = (),
    ) -> dict[str, Any]:
        items: dict[str, RemediationItem] = {}

        def add(data_class: str, trigger: str) -> None:
            key = data_class.strip().lower()
            existing = items.get(key)
            if existing and TRIGGER_ORDER.index(existing.trigger) <= TRIGGER_ORDER.index(trigger):
                return
            rule = self.rule_for(data_class)
            severity = self._downgrade(rule.severity) if trigger == "preventivo" else rule.severity
            items[key] = RemediationItem(rule.data_class, rule.category, severity, trigger, list(rule.actions))

        for dc in data_classes:
            add(dc, "confirmado")
        if password_exposed:
            add("Passwords", "confirmado")
        for dc in potential_data_classes:
            add(dc, "posible")
        if audited_phone:
            add("Phone numbers", "preventivo")
        if audited_email:
            add("Email addresses", "preventivo")

        dns_actions = self._dns_actions(dns_results)
        if dns_actions:
            items["__dns__"] = RemediationItem("Email domain configuration", "Higiene DNS del dominio", "MEDIA", "hallazgo DNS", dns_actions)

        ordered = sorted(
            items.values(),
            key=lambda i: (SEVERITY_ORDER.index(i.severity), TRIGGER_ORDER.index(i.trigger), i.data_class),
        )
        summary = {sev: sum(1 for i in ordered if i.severity == sev) for sev in SEVERITY_ORDER}
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "items": [asdict(i) for i in ordered],
        }
