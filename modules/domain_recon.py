"""Reconocimiento pasivo de dominios.

- Subdominios desde Certificate Transparency (crt.sh), sin duplicados.
- Datos WHOIS (creación, expiración, registrador) con ``python-whois``.

Ambas consultas se ejecutan en paralelo y cualquier fallo de red o timeout se
registra en el resultado sin detener el programa.
"""

from __future__ import annotations

import concurrent.futures
import re
import time
from datetime import datetime, timezone
from typing import Any

import httpx
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from modules import USER_AGENT

try:
    import whois  # python-whois
except ImportError:  # pragma: no cover - dependencia opcional en tiempo de ejecución
    whois = None  # type: ignore[assignment]

console = Console()

CRTSH_URL = "https://crt.sh/"
CRTSH_TIMEOUT = 30.0
CRTSH_RETRIES = 2
WHOIS_TIMEOUT = 20.0
MAX_TABLE_ROWS = 15
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$")


class DomainReconError(Exception):
    """Error controlado durante el reconocimiento de dominios."""


def normalizar_dominio(dominio: str) -> str:
    """Limpia esquema, rutas, puertos y 'www.' de la entrada y valida el formato."""
    value = (dominio or "").strip().lower()
    value = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", value)
    value = value.split("/", 1)[0].split("?", 1)[0].split(":", 1)[0].rstrip(".")
    if value.startswith("www."):
        value = value[4:]
    if not DOMAIN_RE.match(value):
        raise DomainReconError(f"Dominio inválido: '{dominio}'")
    return value


# --------------------------------------------------------------------------- #
# Certificate Transparency (crt.sh)
# --------------------------------------------------------------------------- #
def consultar_crtsh(dominio: str) -> dict[str, Any]:
    """Obtiene subdominios únicos registrados en certificados SSL/TLS."""
    result: dict[str, Any] = {"source": "crt.sh", "status": "error", "certificates": 0, "subdomains": [], "error": ""}
    params = {"q": f"%.{dominio}", "output": "json"}

    entries: list[dict[str, Any]] | None = None
    last_error = ""
    with httpx.Client(timeout=CRTSH_TIMEOUT, headers={"User-Agent": USER_AGENT}, follow_redirects=True) as client:
        for attempt in range(1, CRTSH_RETRIES + 1):
            try:
                response = client.get(CRTSH_URL, params=params)
                if response.status_code == 200:
                    entries = response.json() if response.text.strip() else []
                    break
                last_error = f"crt.sh respondió HTTP {response.status_code}"
                if response.status_code < 500:
                    break  # error del cliente: reintentar no ayuda
                last_error += " (servicio saturado)"
            except httpx.TimeoutException:
                last_error = f"Timeout de {CRTSH_TIMEOUT:.0f}s consultando crt.sh"
            except httpx.HTTPError as exc:
                last_error = f"Error de red con crt.sh: {exc.__class__.__name__}"
            except ValueError:
                last_error = "crt.sh devolvió una respuesta no JSON (posible saturación)"
            if attempt < CRTSH_RETRIES:
                time.sleep(2 * attempt)

    if entries is None:
        result["error"] = last_error or "Sin respuesta de crt.sh"
        return result

    subdomains: set[str] = set()
    for entry in entries:
        for field in ("name_value", "common_name"):
            raw = entry.get(field) or ""
            for name in str(raw).splitlines():
                name = name.strip().lower().lstrip("*.").rstrip(".")
                if name and "@" not in name and (name == dominio or name.endswith("." + dominio)):
                    subdomains.add(name)

    result.update(status="ok", certificates=len(entries), subdomains=sorted(subdomains), error="")
    return result


# --------------------------------------------------------------------------- #
# WHOIS
# --------------------------------------------------------------------------- #
def _primera_fecha(value: Any) -> datetime | None:
    if isinstance(value, (list, tuple)):
        fechas = [v for v in value if isinstance(v, datetime)]
        return min(fechas) if fechas else None
    return value if isinstance(value, datetime) else None


def _iso(value: datetime | None) -> str:
    return value.isoformat() if value else ""


def _primer_texto(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        value = next((v for v in value if v), "")
    return str(value).strip() if value else ""


def consultar_whois(dominio: str) -> dict[str, Any]:
    """Consulta WHOIS con timeout duro para no bloquear el programa."""
    result: dict[str, Any] = {
        "source": "whois",
        "status": "error",
        "registrar": "",
        "creation_date": "",
        "expiration_date": "",
        "updated_date": "",
        "days_to_expiration": None,
        "domain_age_days": None,
        "name_servers": [],
        "error": "",
    }
    if whois is None:
        result["error"] = "python-whois no está instalado (pip install python-whois)"
        return result

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        data = executor.submit(whois.whois, dominio).result(timeout=WHOIS_TIMEOUT)
    except concurrent.futures.TimeoutError:
        result["error"] = f"Timeout de {WHOIS_TIMEOUT:.0f}s consultando WHOIS"
        return result
    except Exception as exc:  # python-whois lanza excepciones heterogéneas (socket, parser...)
        result["error"] = f"Error WHOIS: {exc.__class__.__name__}: {str(exc).splitlines()[0][:200] if str(exc) else ''}"
        return result
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    if not data or not getattr(data, "domain_name", None):
        result["error"] = "WHOIS sin datos (dominio no registrado o TLD sin WHOIS público)"
        return result

    creation = _primera_fecha(data.get("creation_date"))
    expiration = _primera_fecha(data.get("expiration_date"))
    updated = _primera_fecha(data.get("updated_date"))
    now = datetime.now(timezone.utc)

    def _aware(d: datetime) -> datetime:
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)

    name_servers = data.get("name_servers") or []
    if isinstance(name_servers, str):
        name_servers = [name_servers]

    result.update(
        status="ok",
        registrar=_primer_texto(data.get("registrar")),
        creation_date=_iso(creation),
        expiration_date=_iso(expiration),
        updated_date=_iso(updated),
        days_to_expiration=(_aware(expiration) - now).days if expiration else None,
        domain_age_days=(now - _aware(creation)).days if creation else None,
        name_servers=sorted({str(ns).lower().rstrip(".") for ns in name_servers if ns}),
        error="",
    )
    return result


# --------------------------------------------------------------------------- #
# Presentación y orquestación
# --------------------------------------------------------------------------- #
def _render(data: dict[str, Any]) -> None:
    w = data["whois"]
    ct = data["certificate_transparency"]

    info = Table(title=f"🌐 Dominio: {data['domain']}", box=box.ROUNDED, show_header=False, title_style="bold cyan")
    info.add_column("Campo", style="bold white", no_wrap=True)
    info.add_column("Valor", style="green", overflow="fold")
    if w["status"] == "ok":
        exp_days = w["days_to_expiration"]
        exp_note = ""
        if exp_days is not None:
            style = "red" if exp_days < 30 else "yellow" if exp_days < 90 else "green"
            exp_note = f" [{style}]({exp_days} días restantes)[/]"
        info.add_row("Registrador", w["registrar"] or "[dim]—[/]")
        info.add_row("Fecha de creación", (w["creation_date"] or "[dim]—[/]")
                     + (f" [dim]({w['domain_age_days']} días de antigüedad)[/]" if w["domain_age_days"] is not None else ""))
        info.add_row("Fecha de expiración", (w["expiration_date"] or "[dim]—[/]") + exp_note)
        info.add_row("Última actualización", w["updated_date"] or "[dim]—[/]")
        info.add_row("Servidores DNS", ", ".join(w["name_servers"]) or "[dim]—[/]")
    else:
        info.add_row("WHOIS", f"[red]{w['error']}[/]")
    if ct["status"] == "ok":
        info.add_row("Certificados en CT", str(ct["certificates"]))
        info.add_row("Subdominios únicos", str(len(ct["subdomains"])))
    else:
        info.add_row("crt.sh", f"[red]{ct['error']}[/]")
    console.print(info)

    if ct["status"] == "ok":
        subs = ct["subdomains"]
        shown = subs[:MAX_TABLE_ROWS]
        table = Table(
            title=f"🔐 Subdominios en Certificate Transparency (mostrando {len(shown)} de {len(subs)})",
            box=box.SIMPLE_HEAVY,
            title_style="bold cyan",
        )
        table.add_column("#", style="dim", justify="right")
        table.add_column("Subdominio", style="magenta", overflow="fold")
        for idx, sub in enumerate(shown, 1):
            table.add_row(str(idx), sub)
        if not shown:
            table.add_row("—", "[dim]Sin subdominios en certificados[/]")
        console.print(table)
        if len(subs) > MAX_TABLE_ROWS:
            console.print(f"[dim]… {len(subs) - MAX_TABLE_ROWS} subdominios adicionales guardados en el resultado/reporte.[/]")

    if data["errors"]:
        console.print(Panel("\n".join(data["errors"]), title="⚠ Avisos", border_style="yellow"))


def analizar_dominio(dominio: str, mostrar: bool = True) -> dict[str, Any]:
    """Analiza un dominio (crt.sh + WHOIS) en paralelo y devuelve un diccionario de resultados."""
    try:
        domain = normalizar_dominio(dominio)
    except DomainReconError as exc:
        if mostrar:
            console.print(f"[red]✖ {exc}[/]")
        return {"domain": dominio, "status": "error", "errors": [str(exc)],
                "whois": {}, "certificate_transparency": {}, "subdomains": []}

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        future_ct = pool.submit(consultar_crtsh, domain)
        future_whois = pool.submit(consultar_whois, domain)
        if mostrar:
            with console.status(f"[cyan]Consultando crt.sh y WHOIS para {domain}..."):
                concurrent.futures.wait([future_ct, future_whois])
        ct_result = _safe_result(future_ct, "crt.sh")
        whois_result = _safe_result(future_whois, "whois")

    errors = [f"{r['source']}: {r['error']}" for r in (ct_result, whois_result) if r.get("error")]
    data: dict[str, Any] = {
        "domain": domain,
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "status": "ok" if not errors else ("partial" if len(errors) < 2 else "error"),
        "whois": whois_result,
        "certificate_transparency": ct_result,
        "subdomains": ct_result.get("subdomains", []),
        "subdomain_count": len(ct_result.get("subdomains", [])),
        "errors": errors,
    }
    if mostrar:
        _render(data)
    return data


def _safe_result(future: concurrent.futures.Future, source: str) -> dict[str, Any]:
    try:
        return future.result()
    except Exception as exc:  # salvaguarda final: nunca detener el programa
        return {"source": source, "status": "error", "error": f"Excepción no controlada: {exc}", "subdomains": []}
