"""Reconocimiento OSINT de números telefónicos.

- Validación y normalización a E.164 con ``phonenumbers``.
- Extracción de país, región/LADA, operadora original y zonas horarias.
- Generación de Google Dorks con múltiples variaciones de formato.
- Enriquecimiento opcional con Numverify (si existe NUMVERIFY_API_KEY).
"""

from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import quote_plus

import httpx
import phonenumbers
from phonenumbers import (
    NumberParseException,
    PhoneNumberFormat,
    PhoneNumberType,
    carrier,
    geocoder,
    timezone,
)

from modules import USER_AGENT

NUMVERIFY_ENDPOINT = "http://apilayer.net/api/validate"
GOOGLE_SEARCH_URL = "https://www.google.com/search?q="

NUMBER_TYPE_LABELS: dict[int, str] = {
    PhoneNumberType.FIXED_LINE: "Fija",
    PhoneNumberType.MOBILE: "Móvil",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fija o móvil (no distinguible por numeración)",
    PhoneNumberType.TOLL_FREE: "Número gratuito",
    PhoneNumberType.PREMIUM_RATE: "Tarificación especial",
    PhoneNumberType.SHARED_COST: "Costo compartido",
    PhoneNumberType.VOIP: "VoIP",
    PhoneNumberType.PERSONAL_NUMBER: "Número personal",
    PhoneNumberType.PAGER: "Localizador",
    PhoneNumberType.UAN: "UAN (número corporativo)",
    PhoneNumberType.VOICEMAIL: "Buzón de voz",
    PhoneNumberType.UNKNOWN: "Desconocido",
}

DORK_SCOPES: dict[str, str] = {
    "Redes sociales": (
        "(site:facebook.com OR site:instagram.com OR site:x.com OR site:twitter.com "
        "OR site:linkedin.com OR site:tiktok.com)"
    ),
    "Mensajería": "(site:wa.me OR site:t.me OR site:chat.whatsapp.com OR intext:whatsapp)",
    "Documentos públicos": (
        "(filetype:pdf OR filetype:xls OR filetype:xlsx OR filetype:doc OR filetype:docx "
        "OR filetype:csv OR filetype:txt)"
    ),
    "Reportes de spam / fraude": (
        "(site:tellows.com.mx OR site:tellows.com OR site:quienhablo.mx OR site:spamcalls.net "
        "OR site:sync.me OR site:whocallsme.com OR intext:spam OR intext:fraude OR intext:extorsión)"
    ),
    "Anuncios / marketplaces": (
        "(site:mercadolibre.com.mx OR site:facebook.com/marketplace OR site:segundamano.mx "
        "OR site:vivanuncios.com.mx OR site:olx.com)"
    ),
    "Pastes / filtraciones": (
        "(site:pastebin.com OR site:justpaste.it OR site:rentry.co OR site:ghostbin.com "
        "OR site:trello.com)"
    ),
}


class PhoneReconError(Exception):
    """Error controlado durante el análisis de un número telefónico."""


@dataclass
class PhoneReconResult:
    input: str
    valid: bool
    possible: bool
    e164: str
    international: str
    national: str
    country_code: int
    national_number: str
    region_code: str
    country: str
    location: str
    area_code: str
    carrier: str
    line_type: str
    timezones: list[str] = field(default_factory=list)
    format_variants: list[str] = field(default_factory=list)
    dorks: list[dict[str, str]] = field(default_factory=list)
    numverify: dict[str, Any] | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result


def build_format_variants(number: phonenumbers.PhoneNumber) -> list[str]:
    """Genera variaciones de escritura del número útiles para búsquedas."""
    e164 = phonenumbers.format_number(number, PhoneNumberFormat.E164)
    international = phonenumbers.format_number(number, PhoneNumberFormat.INTERNATIONAL)
    national = phonenumbers.format_number(number, PhoneNumberFormat.NATIONAL)
    nsn = phonenumbers.national_significant_number(number)
    cc = str(number.country_code)

    national_dashed = re.sub(r"[^\d]+", "-", national).strip("-")
    international_dashed = "+" + re.sub(r"[^\d]+", "-", international.lstrip("+")).strip("-")
    national_dotted = national_dashed.replace("-", ".")

    return _dedupe(
        [
            e164,  # +525512345678
            international,  # +52 55 1234 5678
            nsn,  # 5512345678 (sin código de país)
            national,  # 55 1234 5678
            national_dashed,  # 55-1234-5678
            international_dashed,  # +52-55-1234-5678
            f"{cc}{nsn}",  # 525512345678
            national_dotted,  # 55.1234.5678
        ]
    )


def build_google_dorks(variants: list[str], max_variants: int = 5) -> list[dict[str, str]]:
    """Construye Google Dorks combinando variantes del número con distintos alcances."""
    dorks: list[dict[str, str]] = []
    selected = variants[:max_variants]
    or_block = " OR ".join(f'"{v}"' for v in selected)

    for category, scope in DORK_SCOPES.items():
        query = f"({or_block}) {scope}"
        dorks.append({"category": category, "query": query, "url": GOOGLE_SEARCH_URL + quote_plus(query)})

    for variant in variants:
        query = f'"{variant}"'
        dorks.append(
            {"category": f"Búsqueda exacta ({variant})", "query": query, "url": GOOGLE_SEARCH_URL + quote_plus(query)}
        )
    return dorks


def query_numverify(e164: str, api_key: str | None = None, timeout: float = 10.0) -> dict[str, Any] | None:
    """Consulta Numverify si hay API key. Devuelve ``None`` si no hay llave configurada."""
    key = api_key or os.getenv("NUMVERIFY_API_KEY", "").strip()
    if not key:
        return None

    params = {"access_key": key, "number": e164.lstrip("+"), "format": 1}
    try:
        with httpx.Client(timeout=timeout, headers={"User-Agent": USER_AGENT}) as client:
            response = client.get(NUMVERIFY_ENDPOINT, params=params)
            response.raise_for_status()
            data = response.json()
    except httpx.TimeoutException:
        return {"status": "error", "error": "Timeout al consultar Numverify"}
    except httpx.HTTPError as exc:
        return {"status": "error", "error": f"Error HTTP en Numverify: {exc}"}
    except ValueError:
        return {"status": "error", "error": "Respuesta no JSON de Numverify"}

    if isinstance(data, dict) and data.get("success") is False:
        err = data.get("error", {})
        return {"status": "error", "error": f"{err.get('type', 'api_error')}: {err.get('info', 'sin detalle')}"}

    return {
        "status": "ok",
        "valid": data.get("valid"),
        "line_type": data.get("line_type") or "desconocido",
        "carrier": data.get("carrier") or "",
        "location": data.get("location") or "",
        "country_name": data.get("country_name") or "",
    }


def analyze_phone(raw_number: str, default_region: str | None = None, timeout: float = 10.0) -> PhoneReconResult:
    """Analiza un número telefónico y devuelve un :class:`PhoneReconResult`."""
    if not raw_number or not raw_number.strip():
        raise PhoneReconError("El número telefónico está vacío.")

    cleaned = raw_number.strip()
    region = None if cleaned.startswith("+") else (default_region or os.getenv("DEFAULT_PHONE_REGION", "MX")).upper()

    try:
        number = phonenumbers.parse(cleaned, region)
    except NumberParseException as exc:
        raise PhoneReconError(f"No se pudo interpretar el número '{cleaned}': {exc}") from exc

    valid = phonenumbers.is_valid_number(number)
    possible = phonenumbers.is_possible_number(number)
    e164 = phonenumbers.format_number(number, PhoneNumberFormat.E164)
    nsn = phonenumbers.national_significant_number(number)

    area_len = phonenumbers.length_of_geographical_area_code(number)
    area_code = nsn[:area_len] if area_len > 0 else ""

    notes: list[str] = []
    if not valid:
        notes.append("El número no es válido según el plan de numeración; los datos pueden ser imprecisos.")
    line_type_code = phonenumbers.number_type(number)
    if line_type_code == PhoneNumberType.FIXED_LINE_OR_MOBILE:
        notes.append(
            "El plan de numeración no distingue fija/móvil (p. ej. México desde 2019). "
            "Usa Numverify para mayor precisión."
        )
    notes.append("La operadora reportada es la ORIGINAL del bloque numérico; no refleja portabilidad.")

    variants = build_format_variants(number)
    result = PhoneReconResult(
        input=raw_number,
        valid=valid,
        possible=possible,
        e164=e164,
        international=phonenumbers.format_number(number, PhoneNumberFormat.INTERNATIONAL),
        national=phonenumbers.format_number(number, PhoneNumberFormat.NATIONAL),
        country_code=number.country_code,
        national_number=nsn,
        region_code=phonenumbers.region_code_for_number(number) or "",
        country=geocoder.country_name_for_number(number, "es") or "",
        location=geocoder.description_for_number(number, "es") or "",
        area_code=area_code,
        carrier=carrier.name_for_number(number, "es") or "",
        line_type=NUMBER_TYPE_LABELS.get(line_type_code, "Desconocido"),
        timezones=list(timezone.time_zones_for_number(number)),
        format_variants=variants,
        dorks=build_google_dorks(variants),
        notes=notes,
    )

    numverify = query_numverify(e164, timeout=timeout)
    if numverify is not None:
        result.numverify = numverify
        if numverify.get("status") == "ok":
            result.line_type = f"{result.line_type} | Numverify: {numverify.get('line_type')}"
            if numverify.get("carrier") and not result.carrier:
                result.carrier = str(numverify["carrier"])
    return result
