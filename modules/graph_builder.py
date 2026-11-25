"""Visualizador interactivo de relaciones OSINT.

Construye un grafo con ``networkx`` a partir de los resultados de la sesión y lo
renderiza con ``pyvis`` en un HTML interactivo autocontenido dentro de ``reports/``.

Ramas (por color):
    - Telefonía / región (operadora, país, LADA, zona horaria)
    - Correo / dominio (alias de pivote, proveedor, SPF, DMARC, WHOIS)
    - Alias detectados en plataformas
    - Subdominios de Certificate Transparency (crt.sh)
    - Servidores MX
    - Estado de filtraciones (HIBP)
"""

from __future__ import annotations

import html
import re
from datetime import datetime
from pathlib import Path
from typing import Any

import networkx as nx
from pyvis.network import Network

REPORTS_DIR = Path("reports")
MAX_SUBDOMAINS = 60
MAX_BREACHES = 30

COLORS: dict[str, str] = {
    "target": "#e91e63",
    "telefonia": "#ff9800",
    "correo": "#2196f3",
    "alias": "#4caf50",
    "subdominio": "#9c27b0",
    "mx": "#00bcd4",
    "whois": "#a1887f",
    "breached": "#f44336",
    "clean": "#8bc34a",
    "unknown": "#ffc107",
    "info": "#78909c",
}

LEGEND: list[tuple[str, str]] = [
    ("Objetivo", COLORS["target"]),
    ("Operadora / región", COLORS["telefonia"]),
    ("Correo / dominio", COLORS["correo"]),
    ("Alias en plataformas", COLORS["alias"]),
    ("Subdominios (crt.sh)", COLORS["subdominio"]),
    ("Servidores MX", COLORS["mx"]),
    ("WHOIS", COLORS["whois"]),
    ("Filtración confirmada", COLORS["breached"]),
    ("Sin filtraciones", COLORS["clean"]),
    ("Filtraciones: indeterminado", COLORS["unknown"]),
]

WEB_PROFILE_SOURCES = {"Gravatar", "GitHub (alias)", "GitLab (alias)"}


class GraphBuilderError(Exception):
    """Error controlado al generar el grafo."""


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value or "")


def _results(datos_sesion: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(datos_sesion, dict):
        return {}
    results = datos_sesion.get("results", datos_sesion)
    return results if isinstance(results, dict) else {}


def _as_list(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return [value] if isinstance(value, dict) else []


class _Composer:
    """Pequeña capa sobre networkx para añadir nodos con estilo coherente."""

    def __init__(self, center_id: str) -> None:
        self.graph = nx.Graph()
        self.center = center_id

    def node(self, node_id: str, label: str, category: str, title: str = "", size: int = 14, shape: str = "dot") -> str:
        if node_id not in self.graph:
            self.graph.add_node(
                node_id,
                label=label if len(label) <= 40 else label[:37] + "...",
                title=title or label,
                color=COLORS.get(category, COLORS["info"]),
                size=size,
                shape=shape,
                group=category,
            )
        return node_id

    def hub(self, key: str, label: str, category: str, title: str = "") -> str:
        node_id = self.node(f"hub:{key}", label, category, title, size=24, shape="box")
        self.edge(self.center, node_id, width=3)
        return node_id

    def leaf(self, parent: str, node_id: str, label: str, category: str, title: str = "", size: int = 14) -> str:
        self.node(node_id, label, category, title, size=size)
        self.edge(parent, node_id)
        return node_id

    def edge(self, a: str, b: str, width: int = 1) -> None:
        if a != b and not self.graph.has_edge(a, b):
            self.graph.add_edge(a, b, width=width)


# --------------------------------------------------------------------------- #
# Selección de datos relacionados con el identificador
# --------------------------------------------------------------------------- #
def _match_phone(entry: dict[str, Any], ident: str) -> bool:
    ident_digits = _digits(ident)
    if not ident_digits:
        return False
    e164_digits = _digits(entry.get("e164", ""))
    nsn = entry.get("national_number", "")
    return ident_digits == e164_digits or ident_digits == _digits(entry.get("input", "")) or (
        bool(nsn) and ident_digits.endswith(nsn)
    )


def _collect(results: dict[str, Any], ident: str) -> dict[str, Any]:
    ident_l = ident.strip().lower()
    is_email = "@" in ident_l

    phones = [p for p in _as_list(results.get("phone")) if not is_email and _match_phone(p, ident_l)]
    emails = [e for e in _as_list(results.get("email")) if e.get("email") == ident_l]
    breaches = [b for b in _as_list(results.get("breaches")) if b.get("email") == ident_l]

    aliases: set[str] = set()
    domains: set[str] = set()
    if is_email:
        user, domain = ident_l.rsplit("@", 1)
        domains.add(domain)
        aliases.update({user.split("+", 1)[0]})
        for e in emails:
            aliases.update({e.get("pivot_alias", ""), e.get("base_alias", "")})
    elif not _digits(ident_l) or not phones:
        # Permite usar un alias o un dominio directamente como objetivo
        (domains if "." in ident_l else aliases).add(ident_l)

    usernames = [u for u in _as_list(results.get("username")) if u.get("username", "").lower() in aliases]
    domain_data = [d for d in _as_list(results.get("domain")) if d.get("domain", "").lower() in domains]
    return {
        "is_email": is_email,
        "phones": phones,
        "emails": emails,
        "breaches": breaches,
        "usernames": usernames,
        "domains": domain_data,
    }


# --------------------------------------------------------------------------- #
# Ramas del grafo
# --------------------------------------------------------------------------- #
def _branch_phone(c: _Composer, phones: list[dict[str, Any]]) -> None:
    for p in phones:
        hub = c.hub("telefonia", "Operadora / Región", "telefonia", f"Número {p.get('e164', '')}")
        fields = [
            ("País", p.get("country")),
            ("Región", p.get("location")),
            ("LADA", p.get("area_code")),
            ("Operadora", p.get("carrier") or "Desconocida (sin dato de portabilidad)"),
            ("Tipo de línea", p.get("line_type")),
        ]
        for label, value in fields:
            if value:
                c.leaf(hub, f"tel:{label}:{value}", f"{label}: {value}", "telefonia")
        for tz in p.get("timezones", []) or []:
            c.leaf(hub, f"tel:tz:{tz}", f"TZ: {tz}", "telefonia")
        nv = p.get("numverify") or {}
        if nv.get("status") == "ok":
            c.leaf(hub, "tel:numverify", f"Numverify: {nv.get('line_type')}", "telefonia", f"Operadora: {nv.get('carrier', '')}")


def _branch_email(c: _Composer, emails: list[dict[str, Any]], domains: list[dict[str, Any]]) -> None:
    for e in emails:
        hub = c.hub("correo", f"Dominio: {e.get('domain', '')}", "correo", f"Correo {e.get('email', '')}")
        c.leaf(hub, f"mail:alias:{e.get('pivot_alias')}", f"Alias pivote: {e.get('pivot_alias')}", "correo")
        dns_r = e.get("dns") or {}
        if dns_r.get("provider"):
            c.leaf(hub, "mail:provider", f"Proveedor: {dns_r['provider']}", "correo")
        spf = dns_r.get("spf") or {}
        dmarc = dns_r.get("dmarc") or {}
        c.leaf(hub, "mail:spf", f"SPF: {spf.get('all_qualifier') or ('ausente' if not spf.get('present') else 'sin all')}",
               "correo", spf.get("assessment", ""))
        c.leaf(hub, "mail:dmarc", f"DMARC: {dmarc.get('policy') or 'ausente'}", "correo", dmarc.get("assessment", ""))

        mx_list = dns_r.get("mx") or []
        if mx_list or dns_r.get("implicit_mx"):
            mx_hub = c.hub("mx", f"Servidores MX ({len(mx_list)})", "mx", "Correo activo" if dns_r.get("mail_active") else "Sin correo activo")
            for mx in mx_list:
                c.leaf(mx_hub, f"mx:{mx.get('exchange')}", f"{mx.get('exchange')} ({mx.get('preference')})", "mx")
            if dns_r.get("implicit_mx"):
                c.leaf(mx_hub, "mx:implicit", "MX implícito (registro A)", "mx")
        elif dns_r:
            c.hub("mx", "Sin servidores MX", "mx", "; ".join(dns_r.get("errors", [])) or "Null MX / sin correo")

    for d in domains:
        w = d.get("whois") or {}
        hub = c.hub("correo", f"Dominio: {d.get('domain', '')}", "correo")
        if w.get("status") == "ok":
            whois_node = c.leaf(hub, "whois", "WHOIS", "whois", size=18)
            for label, key in (("Registrador", "registrar"), ("Creación", "creation_date"), ("Expira", "expiration_date")):
                if w.get(key):
                    value = str(w[key])[:10] if "date" in key else str(w[key])
                    c.leaf(whois_node, f"whois:{key}", f"{label}: {value}", "whois", str(w[key]))
        elif w.get("error"):
            c.leaf(hub, "whois:error", "WHOIS no disponible", "whois", w["error"])


def _branch_aliases(c: _Composer, usernames: list[dict[str, Any]], emails: list[dict[str, Any]]) -> None:
    profiles: list[tuple[str, str, str]] = []  # (id, label, url)
    for u in usernames:
        for f in u.get("found", []):
            profiles.append((f"alias:{f['platform']}:{u['username']}", f"{f['platform']}: {u['username']}", f.get("url", "")))
    for e in emails:
        for check in e.get("checks", []) or []:
            if check.get("status") != "found":
                continue
            data = check.get("data") or {}
            source = check.get("source", "")
            if source in WEB_PROFILE_SOURCES:
                name = data.get("login") or data.get("username") or data.get("display_name") or data.get("preferred_username") or ""
                url = data.get("url") or data.get("profile_url") or ""
                profiles.append((f"alias:{source}:{name}", f"{source.split(' ')[0]}: {name}", url))
            elif source == "GitHub (correo)":
                for user in data.get("users", []):
                    profiles.append((f"alias:GitHub:{user['login']}", f"GitHub (correo): {user['login']}", user.get("url", "")))
                if data.get("commit_count"):
                    profiles.append(("alias:github-commits", f"Commits públicos: {data['commit_count']}", ""))

    if not profiles:
        return
    hub = c.hub("alias", f"Alias detectados ({len(profiles)})", "alias")
    for node_id, label, url in profiles:
        c.leaf(hub, node_id, label, "alias", url or label)


def _branch_subdomains(c: _Composer, domains: list[dict[str, Any]]) -> None:
    for d in domains:
        subs = d.get("subdomains") or []
        if not subs:
            continue
        hub = c.hub(f"sub:{d['domain']}", f"Subdominios crt.sh ({len(subs)})", "subdominio", f"Certificate Transparency de {d['domain']}")
        for sub in subs[:MAX_SUBDOMAINS]:
            c.leaf(hub, f"sub:{sub}", sub, "subdominio", size=10)
        if len(subs) > MAX_SUBDOMAINS:
            c.leaf(hub, f"sub:more:{d['domain']}", f"+{len(subs) - MAX_SUBDOMAINS} más (ver reporte)", "info", size=10)


def _branch_breaches(c: _Composer, breaches: list[dict[str, Any]]) -> None:
    for b in breaches:
        status = b.get("status", "unknown")
        category = {"breached": "breached", "clean": "clean"}.get(status, "unknown")
        label = {
            "breached": f"Filtraciones: {b.get('breach_count', 0)}",
            "clean": "Sin filtraciones conocidas",
            "error": "Filtraciones: error de consulta",
        }.get(status, "Filtraciones: no verificado")
        hub = c.hub("breaches", label, category, b.get("message", ""))
        for br in (b.get("breaches") or [])[:MAX_BREACHES]:
            title = f"{br.get('title')} ({br.get('breach_date')})\nDatos: {', '.join(br.get('data_classes', []))}"
            c.leaf(hub, f"breach:{br.get('name')}", f"{br.get('title')} {str(br.get('breach_date', ''))[:4]}", "breached", title)
        for dc in b.get("data_classes") or []:
            c.leaf(hub, f"dc:{dc}", dc, "breached", "Tipo de dato expuesto", size=10)
        for br in (b.get("domain_related_breaches") or [])[:MAX_BREACHES]:
            c.leaf(hub, f"breach-dom:{br.get('name')}", f"Brecha del dominio: {br.get('title')}", "unknown",
                   f"Datos: {', '.join(br.get('data_classes', []))}")
        if status == "unknown" and not b.get("domain_related_breaches"):
            c.leaf(hub, "breach:nokey", "Requiere HIBP_API_KEY", "unknown", "Sin API key no se verifica el correo individualmente")


# --------------------------------------------------------------------------- #
# Render
# --------------------------------------------------------------------------- #
def _legend_html(identificador: str, stats: str) -> str:
    items = "".join(
        f'<div style="margin:3px 0"><span style="display:inline-block;width:12px;height:12px;border-radius:50%;'
        f'background:{color};margin-right:8px"></span>{html.escape(name)}</div>'
        for name, color in LEGEND
    )
    return (
        '<div style="position:fixed;top:12px;left:12px;z-index:10;background:#1e1e1ecc;color:#fff;'
        'padding:12px 16px;border-radius:8px;font-family:Segoe UI,Arial,sans-serif;font-size:13px;'
        'border:1px solid #333;max-width:280px">'
        f'<div style="font-size:15px;font-weight:600;margin-bottom:4px">🕸️ Grafo OSINT</div>'
        f'<div style="color:#e91e63;margin-bottom:6px;word-break:break-all">{html.escape(identificador)}</div>'
        f'<div style="color:#aaa;margin-bottom:8px">{html.escape(stats)}</div>{items}</div>'
    )


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")[:60] or "objetivo"


def generar_grafo_osint(datos_sesion: dict[str, Any], identificador: str, directorio: str | Path = REPORTS_DIR) -> str:
    """Genera el grafo interactivo del identificador y devuelve la ruta del HTML creado."""
    if not identificador or not identificador.strip():
        raise GraphBuilderError("Se requiere un identificador (teléfono o correo) para el nodo central.")
    ident = identificador.strip()
    results = _results(datos_sesion)
    data = _collect(results, ident)

    center_label = ident if not data["phones"] else data["phones"][0].get("e164", ident)
    center_kind = "Correo" if data["is_email"] else ("Teléfono" if data["phones"] else "Objetivo")
    composer = _Composer("target")
    composer.node("target", center_label, "target", f"{center_kind} investigado: {center_label}", size=40, shape="star")

    _branch_phone(composer, data["phones"])
    _branch_email(composer, data["emails"], data["domains"])
    _branch_aliases(composer, data["usernames"], data["emails"])
    _branch_subdomains(composer, data["domains"])
    _branch_breaches(composer, data["breaches"])

    graph = composer.graph
    if graph.number_of_nodes() == 1:
        composer.leaf("target", "empty", "Sin hallazgos en la sesión para este objetivo", "info")

    stats = f"{graph.number_of_nodes()} nodos · {graph.number_of_edges()} relaciones"

    net = Network(
        height="100vh",
        width="100%",
        bgcolor="#111111",
        font_color="white",
        directed=False,
        cdn_resources="in_line",
    )
    net.from_nx(graph)
    net.barnes_hut(gravity=-9000, central_gravity=0.35, spring_length=150, spring_strength=0.03, damping=0.12)

    out_dir = Path(directorio)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"grafo_{_safe_name(center_label)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        page = net.generate_html(name=str(path), local=True, notebook=False)
        page = page.replace("<body>", "<body style=\"margin:0\">" + _legend_html(center_label, stats), 1)
        # Escritura explícita en UTF-8 (pyvis usa la codificación del sistema y falla en Windows con acentos/emoji)
        path.write_text(page, encoding="utf-8")
    except OSError as exc:
        raise GraphBuilderError(f"No se pudo escribir el grafo: {exc}") from exc
    except Exception as exc:  # errores internos de pyvis/jinja
        raise GraphBuilderError(f"Error al renderizar el grafo con pyvis: {exc}") from exc
    return str(path.resolve())
