#!/usr/bin/env python3
"""osint-recon-tool — CLI de reconocimiento OSINT y auditoría defensiva (Blue Team / CTI).

Uso rápido:
    python main.py                       # menú interactivo
    python main.py phone "+52 55 1234 5678"
    python main.py email usuario@dominio.com --export
    python main.py breaches usuario@dominio.com
    python main.py password              # verificación k-Anonymity (entrada oculta)
    python main.py genpass --length 24
    python main.py audit --email usuario@dominio.com --phone "+525512345678" --export
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys
import uuid
from datetime import datetime, timezone
from typing import Any

from dotenv import load_dotenv
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

from modules import __tool_name__, __version__
from modules.breach_auditor import (
    BreachAuditorError,
    RemediationEngine,
    check_email_breaches,
    check_password_pwned,
    generate_secure_password,
)
from modules.domain_recon import analizar_dominio
from modules.email_recon import EmailReconError, run_email_recon
from modules.graph_builder import GraphBuilderError, generar_grafo_osint
from modules.phone_recon import PhoneReconError, analyze_phone
from modules.report_exporter import ReportExporter
from modules.username_recon import UsernameReconError, ejecutar_busqueda_alias

console = Console()

# Dominios de correo públicos: analizar su crt.sh/WHOIS no aporta inteligencia sobre el objetivo.
WEBMAIL_DOMAINS: frozenset[str] = frozenset(
    {
        "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
        "yahoo.com", "yahoo.com.mx", "icloud.com", "me.com", "proton.me", "protonmail.com",
        "aol.com", "gmx.com", "zoho.com", "yandex.com", "prodigy.net.mx",
    }
)

SEVERITY_STYLES: dict[str, str] = {
    "CRÍTICA": "bold white on red",
    "ALTA": "bold red",
    "MEDIA": "bold yellow",
    "BAJA": "bold green",
}
STATUS_STYLES: dict[str, str] = {
    "found": "[bold green]ENCONTRADO[/]",
    "not_found": "[dim]No encontrado[/]",
    "rate_limited": "[yellow]Rate limit[/]",
    "error": "[red]Error[/]",
}


# --------------------------------------------------------------------------- #
# Sesión
# --------------------------------------------------------------------------- #
class Session:
    """Acumula todos los hallazgos de la ejecución para su exportación."""

    def __init__(self) -> None:
        self.session_id = uuid.uuid4().hex[:12]
        self.created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.results: dict[str, Any] = {}

    def add(self, section: str, data: dict[str, Any]) -> None:
        self.results.setdefault(section, []).append(data)

    def is_empty(self) -> bool:
        return not self.results

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": {
                "tool": __tool_name__,
                "version": __version__,
                "session_id": self.session_id,
                "created_at": self.created_at,
            },
            "results": self.results,
        }


# --------------------------------------------------------------------------- #
# Utilidades de presentación
# --------------------------------------------------------------------------- #
def banner() -> None:
    console.print(
        Panel.fit(
            f"[bold cyan]{__tool_name__}[/] v{__version__}\n"
            "[white]Reconocimiento OSINT y auditoría defensiva de teléfonos y correos[/]\n"
            "[dim]Uso exclusivo sobre activos propios o con autorización expresa (Blue Team / CTI).[/]",
            title="🛡️  OSINT Recon",
            border_style="cyan",
        )
    )


def kv_table(title: str, rows: list[tuple[str, Any]]) -> Table:
    table = Table(title=title, box=box.ROUNDED, show_header=False, title_style="bold cyan", expand=False)
    table.add_column("Campo", style="bold white", no_wrap=True)
    table.add_column("Valor", style="green", overflow="fold")
    for key, value in rows:
        if isinstance(value, bool):
            value = "[green]Sí[/]" if value else "[red]No[/]"
        elif isinstance(value, (list, tuple)):
            value = ", ".join(str(v) for v in value) if value else "—"
        elif value in (None, ""):
            value = "[dim]—[/]"
        table.add_row(key, str(value))
    return table


# --------------------------------------------------------------------------- #
# Renderizado de resultados
# --------------------------------------------------------------------------- #
def render_phone(data: dict[str, Any]) -> None:
    console.print(
        kv_table(
            f"📞 Análisis de {data['e164']}",
            [
                ("Entrada", data["input"]),
                ("Válido", data["valid"]),
                ("Posible", data["possible"]),
                ("E.164", data["e164"]),
                ("Internacional", data["international"]),
                ("Nacional", data["national"]),
                ("Código de país", f"+{data['country_code']} ({data['region_code']})"),
                ("País", data["country"]),
                ("Región / localidad", data["location"]),
                ("LADA / código de área", data["area_code"]),
                ("Operadora original", data["carrier"]),
                ("Tipo de línea", data["line_type"]),
                ("Zonas horarias", data["timezones"]),
            ],
        )
    )
    nv = data.get("numverify")
    if nv is None:
        console.print("[dim]Numverify: sin NUMVERIFY_API_KEY, enriquecimiento omitido.[/]")
    elif nv.get("status") == "ok":
        console.print(kv_table("Numverify", [(k, v) for k, v in nv.items() if k != "status"]))
    else:
        console.print(f"[yellow]Numverify: {nv.get('error')}[/]")

    variants = Table(title="Variantes de formato", box=box.SIMPLE, title_style="bold cyan")
    variants.add_column("#", style="dim")
    variants.add_column("Formato", style="magenta")
    for i, v in enumerate(data["format_variants"], 1):
        variants.add_row(str(i), v)
    console.print(variants)

    dorks = Table(title="🔎 Google Dorks", box=box.ROUNDED, title_style="bold cyan", show_lines=True)
    dorks.add_column("Categoría", style="bold yellow", no_wrap=True)
    dorks.add_column("URL", style="cyan", overflow="fold")
    for d in data["dorks"]:
        dorks.add_row(d["category"], f"[link={d['url']}]{d['url']}[/link]")
    console.print(dorks)
    for note in data.get("notes", []):
        console.print(f"[dim]ℹ {note}[/]")


def render_email(data: dict[str, Any]) -> None:
    console.print(
        kv_table(
            f"✉️  Análisis de {data['email']}",
            [
                ("Usuario", data["user"]),
                ("Alias base (pivote)", data["pivot_alias"]),
                ("Etiqueta +tag", data["plus_tag"]),
                ("Dominio", data["domain"]),
                ("MD5 (Gravatar)", data["md5"]),
            ],
        )
    )
    dns_r = data.get("dns", {})
    mx_list = [f"{m['preference']} {m['exchange']}" for m in dns_r.get("mx", [])]
    spf = dns_r.get("spf", {}) or {}
    dmarc = dns_r.get("dmarc", {}) or {}
    console.print(
        kv_table(
            f"🌐 DNS de {dns_r.get('domain', '')}",
            [
                ("Dominio existe", dns_r.get("domain_exists", False)),
                ("Correo activo", dns_r.get("mail_active", False)),
                ("MX", mx_list or ("MX implícito (registro A)" if dns_r.get("implicit_mx") else "—")),
                ("Null MX (RFC 7505)", dns_r.get("null_mx", False)),
                ("Proveedor", dns_r.get("provider", "")),
                ("SPF", spf.get("record", "")),
                ("Evaluación SPF", spf.get("assessment", "")),
                ("DMARC", dmarc.get("record", "")),
                ("Evaluación DMARC", dmarc.get("assessment", "")),
                ("Errores", dns_r.get("errors", [])),
            ],
        )
    )

    checks = Table(title="🌍 Presencia en servicios públicos", box=box.ROUNDED, title_style="bold cyan", show_lines=True)
    checks.add_column("Fuente", style="bold white", no_wrap=True)
    checks.add_column("Estado", no_wrap=True)
    checks.add_column("Detalle", overflow="fold")
    for c in data.get("checks", []):
        detail = c.get("error", "") or ""
        d = c.get("data") or {}
        if c["status"] == "found":
            if c["source"] == "Gravatar":
                accounts = ", ".join(a["service"] for a in d.get("accounts", []))
                detail = f"{d.get('display_name', '')} · {d.get('profile_url', '')}" + (f" · Cuentas: {accounts}" if accounts else "")
            elif c["source"] == "GitHub (correo)":
                users = ", ".join(u["login"] for u in d.get("users", []))
                detail = f"Usuarios: {users or '—'} · Commits: {d.get('commit_count', 0)} · Autores: {', '.join(d.get('commit_authors', [])) or '—'}"
            else:
                detail = " · ".join(str(v) for v in d.values() if v not in (None, ""))
        checks.add_row(c["source"], STATUS_STYLES.get(c["status"], c["status"]), detail)
    console.print(checks)


def render_breaches(data: dict[str, Any]) -> None:
    style = {"breached": "red", "clean": "green", "unknown": "yellow", "error": "red"}.get(data["status"], "white")
    mode = "HIBP v3 autenticado" if data["mode"] == "authenticated" else "Catálogo público (sin API key)"
    console.print(Panel(f"[bold]{data['message']}[/]\nModo: {mode}", title=f"🔓 Brechas — {data['email']}", border_style=style))

    def breach_table(title: str, breaches: list[dict[str, Any]]) -> Table:
        t = Table(title=title, box=box.ROUNDED, title_style="bold cyan", show_lines=True)
        t.add_column("Brecha", style="bold white")
        t.add_column("Dominio", style="cyan")
        t.add_column("Fecha", no_wrap=True)
        t.add_column("Cuentas", justify="right")
        t.add_column("Datos expuestos", overflow="fold", style="yellow")
        for b in breaches:
            t.add_row(b["title"], b["domain"] or "—", b["breach_date"], f"{b['pwn_count']:,}", ", ".join(b["data_classes"]))
        return t

    if data["breaches"]:
        console.print(breach_table("Brechas que incluyen el correo", data["breaches"]))
    if data["pastes"]:
        p = Table(title="Pastes", box=box.SIMPLE, title_style="bold cyan")
        for col in ("Fuente", "ID", "Fecha", "Correos"):
            p.add_column(col)
        for paste in data["pastes"]:
            p.add_row(paste["source"], paste["id"], paste["date"], str(paste["email_count"]))
        console.print(p)
    if data["domain_related_breaches"]:
        console.print(breach_table("⚠ Brechas asociadas al dominio del correo", data["domain_related_breaches"]))
    if data["recent_breaches"]:
        console.print(breach_table("Brechas añadidas recientemente (contexto)", data["recent_breaches"]))
    if data["data_classes"]:
        console.print(f"[bold red]Tipos de datos expuestos:[/] {', '.join(data['data_classes'])}")


def render_password_check(data: dict[str, Any]) -> None:
    if data["exposed"]:
        msg = f"[bold red]⚠ CONTRASEÑA COMPROMETIDA[/]: aparece [bold]{data['count']:,}[/] veces en filtraciones.\nNo la utilices en ningún servicio."
        style = "red"
    else:
        msg = "[bold green]✔ No aparece en Pwned Passwords.[/]\nAun así, úsala solo si es única y larga."
        style = "green"
    console.print(
        Panel(
            f"{msg}\n[dim]Prefijo SHA-1 enviado (k-Anonymity): {data['sha1_prefix']} · "
            f"{data['candidates_in_range']} sufijos en el rango[/]",
            title="🔑 Pwned Passwords",
            border_style=style,
        )
    )


def render_generated(data: dict[str, Any]) -> None:
    if data["verified"]:
        console.print(
            Panel(
                f"[bold green]{data['password']}[/]\n\n"
                f"Longitud: {data['length']} · Entropía: {data['entropy_bits']} bits · "
                f"Apariciones en filtraciones: {data['pwned_count']} · Intentos: {data['attempts']}",
                title="🔐 Contraseña segura verificada",
                border_style="green",
            )
        )
        console.print("[dim]Guárdala en tu gestor de contraseñas. No se almacena en los reportes.[/]")
    else:
        console.print(
            Panel(
                f"[bold red]No se pudo verificar la contraseña contra Pwned Passwords.[/]\n{data.get('error', '')}\n"
                "Por seguridad no se recomienda ninguna contraseña sin verificación.",
                title="🔐 Generador",
                border_style="red",
            )
        )


def render_remediation(plan: dict[str, Any]) -> None:
    summary = " · ".join(f"[{SEVERITY_STYLES[s]}] {s}: {c} [/]" for s, c in plan["summary"].items())
    console.print(Panel(summary or "Sin acciones", title="🧭 Plan de remediación", border_style="magenta"))
    if not plan["items"]:
        console.print("[green]No se identificaron acciones de remediación.[/]")
        return
    table = Table(box=box.ROUNDED, show_lines=True)
    table.add_column("Severidad", no_wrap=True)
    table.add_column("Dato / origen", style="bold white")
    table.add_column("Acciones concretas", overflow="fold")
    for item in plan["items"]:
        actions = "\n".join(f"• {a}" for a in item["actions"])
        table.add_row(
            f"[{SEVERITY_STYLES.get(item['severity'], 'white')}] {item['severity']} [/]",
            f"{item['data_class']}\n[dim]{item['category']}\n({item['trigger']})[/]",
            actions,
        )
    console.print(table)


# --------------------------------------------------------------------------- #
# Acciones
# --------------------------------------------------------------------------- #
def action_phone(session: Session, number: str, region: str | None = None) -> dict[str, Any] | None:
    try:
        with console.status("[cyan]Analizando número telefónico..."):
            result = analyze_phone(number, default_region=region).to_dict()
    except PhoneReconError as exc:
        console.print(f"[red]✖ {exc}[/]")
        return None
    session.add("phone", result)
    render_phone(result)
    return result


def _already_done(session: Session, section: str, key: str, value: str) -> bool:
    return any(str(item.get(key, "")).lower() == value.lower() for item in session.results.get(section, []))


def action_alias(session: Session, username: str) -> dict[str, Any] | None:
    console.print(f"[cyan]Rastreando el alias '{username}' en plataformas públicas...[/]")
    try:
        result = ejecutar_busqueda_alias(username)
    except UsernameReconError as exc:
        console.print(f"[red]✖ {exc}[/]")
        return None
    session.add("username", result)
    return result


def action_domain(session: Session, domain: str) -> dict[str, Any] | None:
    result = analizar_dominio(domain)
    if result.get("status") == "error" and not result.get("whois") and not result.get("certificate_transparency"):
        return None  # dominio inválido: el módulo ya informó el error
    session.add("domain", result)
    return result


def run_email_chain(session: Session, alias: str, domain: str, mode: bool | None) -> None:
    """Pivota desde un correo hacia su alias y su dominio.

    ``mode``: ``True`` ejecuta automáticamente, ``False`` omite, ``None`` pregunta al usuario.
    """
    if mode is False:
        return
    is_webmail = domain in WEBMAIL_DOMAINS
    console.print(
        Panel(
            f"Alias de pivote: [bold green]{alias}[/]\nDominio: [bold blue]{domain}[/]"
            + ("\n[dim]El dominio es un proveedor de correo público; su análisis no aporta datos del objetivo.[/]" if is_webmail else ""),
            title="🔗 Pivote automático desde el correo",
            border_style="blue",
        )
    )
    if mode is None:
        if not sys.stdin.isatty():
            console.print("[dim]Entrada no interactiva: usa --chain para ejecutar los módulos en cadena.[/]")
            return
        do_alias = Confirm.ask(f"¿Rastrear el alias '{alias}' en plataformas públicas?", default=True)
        do_domain = Confirm.ask(f"¿Analizar el dominio '{domain}' (crt.sh / WHOIS)?", default=not is_webmail)
    else:
        do_alias, do_domain = True, not is_webmail
        if is_webmail:
            console.print(f"[dim]Se omite crt.sh/WHOIS de '{domain}' (proveedor público).[/]")

    if do_alias:
        if _already_done(session, "username", "username", alias):
            console.print(f"[dim]El alias '{alias}' ya fue rastreado en esta sesión.[/]")
        else:
            action_alias(session, alias)
    if do_domain:
        if _already_done(session, "domain", "domain", domain):
            console.print(f"[dim]El dominio '{domain}' ya fue analizado en esta sesión.[/]")
        else:
            action_domain(session, domain)


def action_email(session: Session, email: str, chain: bool | None = None) -> dict[str, Any] | None:
    try:
        with console.status("[cyan]Consultando DNS, Gravatar, GitHub y GitLab..."):
            result = asyncio.run(run_email_recon(email))
    except EmailReconError as exc:
        console.print(f"[red]✖ {exc}[/]")
        return None
    session.add("email", result)
    render_email(result)
    run_email_chain(session, result["pivot_alias"], result["domain"], chain)
    return result


def _session_targets(session: Session) -> list[str]:
    targets: list[str] = []
    for section, key in (("email", "email"), ("breaches", "email"), ("phone", "e164"), ("username", "username"), ("domain", "domain")):
        for item in session.results.get(section, []):
            value = item.get(key)
            if value and value not in targets:
                targets.append(value)
    return targets


def action_graph(session: Session, identificador: str | None = None, output_dir: str = "reports") -> str | None:
    if identificador is None:
        targets = _session_targets(session)
        if not targets:
            console.print("[yellow]No hay objetivos en la sesión. Analiza primero un teléfono o correo.[/]")
            return None
        if len(targets) == 1:
            identificador = targets[0]
        else:
            for idx, t in enumerate(targets, 1):
                console.print(f"  [bold yellow]{idx}[/]. {t}")
            choice = IntPrompt.ask("Objetivo para el nodo central", choices=[str(i) for i in range(1, len(targets) + 1)], default=1)
            identificador = targets[choice - 1]
    try:
        with console.status(f"[cyan]Construyendo grafo de relaciones para {identificador}..."):
            path = generar_grafo_osint(session.to_dict(), identificador, output_dir)
    except GraphBuilderError as exc:
        console.print(f"[red]✖ {exc}[/]")
        return None
    session.add("graphs", {"target": identificador, "path": path, "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds")})
    console.print(Panel(f"[cyan]{path}[/]\n[dim]Ábrelo en tu navegador para explorar el grafo interactivo.[/]",
                        title="🕸️  Grafo interactivo generado", border_style="magenta"))
    return path


def action_full_audit(
    session: Session,
    email: str | None,
    phone: str | None,
    region: str | None = None,
    check_password: bool = False,
    chain: bool = True,
    graph: bool = True,
    output_dir: str = "reports",
) -> None:
    targets: list[str] = []
    if phone:
        console.rule("[bold cyan]Teléfono")
        result = action_phone(session, phone, region)
        if result:
            targets.append(result["e164"])
    if email:
        console.rule("[bold cyan]Correo y pivotes")
        if action_email(session, email, chain=chain):
            targets.append(email.strip().lower())
        console.rule("[bold cyan]Filtraciones")
        action_breaches(session, email)
    if check_password:
        console.rule("[bold cyan]Contraseña")
        action_password(session)
    console.rule("[bold cyan]Remediación")
    action_remediation(session)
    if graph:
        console.rule("[bold cyan]Grafo de relaciones")
        for target in targets:
            action_graph(session, target, output_dir)


def action_breaches(session: Session, email: str) -> None:
    try:
        with console.status("[cyan]Consultando Have I Been Pwned..."):
            result = check_email_breaches(email)
    except BreachAuditorError as exc:
        console.print(f"[red]✖ {exc}[/]")
        return
    session.add("breaches", result)
    render_breaches(result)


def action_password(session: Session, password: str | None = None) -> None:
    pwd = password if password is not None else getpass.getpass("Contraseña a verificar (entrada oculta): ")
    try:
        with console.status("[cyan]Consultando Pwned Passwords (k-Anonymity)..."):
            result = check_password_pwned(pwd)
    except BreachAuditorError as exc:
        console.print(f"[red]✖ {exc}[/]")
        return
    finally:
        pwd = ""  # minimiza la vida de la contraseña en memoria
    session.add("password_check", result)
    render_password_check(result)


def action_genpass(session: Session, length: int = 20, symbols: bool = True) -> None:
    try:
        with console.status("[cyan]Generando y validando contraseña..."):
            result = generate_secure_password(length=length, use_symbols=symbols)
    except BreachAuditorError as exc:
        console.print(f"[red]✖ {exc}[/]")
        return
    render_generated(result)
    session.add("generated_passwords", {k: v for k, v in result.items() if k != "password"})


def action_remediation(session: Session) -> dict[str, Any]:
    breaches = session.results.get("breaches", [])
    emails = session.results.get("email", [])
    data_classes = sorted({dc for b in breaches for dc in b.get("data_classes", [])})
    potential = sorted({dc for b in breaches for dc in b.get("potential_data_classes", [])})
    plan = RemediationEngine().build_plan(
        data_classes=data_classes,
        potential_data_classes=potential,
        audited_phone=bool(session.results.get("phone")),
        audited_email=bool(emails or breaches),
        password_exposed=any(p.get("exposed") for p in session.results.get("password_check", [])),
        dns_results=[e["dns"] for e in emails if e.get("dns")],
    )
    session.results["remediation"] = plan
    render_remediation(plan)
    return plan


def action_export(session: Session, output_dir: str = "reports") -> None:
    if session.is_empty():
        console.print("[yellow]La sesión no tiene resultados para exportar.[/]")
        return
    if "remediation" not in session.results:
        action_remediation(session)
    try:
        paths = ReportExporter(output_dir).export(session.to_dict())
    except RuntimeError as exc:
        console.print(f"[red]✖ {exc}[/]")
        return
    console.print(
        Panel(
            f"JSON: [cyan]{paths['json'].resolve()}[/]\nHTML: [cyan]{paths['html'].resolve()}[/]",
            title="📄 Reportes exportados",
            border_style="green",
        )
    )


# --------------------------------------------------------------------------- #
# Menú interactivo
# --------------------------------------------------------------------------- #
MENU_OPTIONS: list[tuple[str, str]] = [
    ("1", "Reconocimiento de teléfono"),
    ("2", "Reconocimiento de correo (+ pivote a alias y dominio)"),
    ("3", "Auditoría de brechas de un correo (HIBP)"),
    ("4", "Rastreo de alias en plataformas"),
    ("5", "Inteligencia de dominio (crt.sh / WHOIS)"),
    ("6", "Verificar contraseña (Pwned Passwords)"),
    ("7", "Generar contraseña segura verificada"),
    ("8", "Auditoría completa + Grafo interactivo"),
    ("9", "Generar grafo interactivo de la sesión"),
    ("10", "Generar plan de remediación"),
    ("11", "Exportar reporte (JSON + HTML)"),
    ("0", "Salir"),
]


def interactive(session: Session) -> None:
    while True:
        table = Table(title="Menú principal", box=box.ROUNDED, show_header=False, title_style="bold cyan")
        table.add_column("Opción", style="bold yellow", justify="center")
        table.add_column("Acción")
        for key, label in MENU_OPTIONS:
            table.add_row(key, label)
        console.print(table)
        choice = Prompt.ask("Selecciona una opción", choices=[k for k, _ in MENU_OPTIONS], default="0")
        try:
            if choice == "1":
                action_phone(session, Prompt.ask("Número telefónico"), Prompt.ask("Región por defecto (ISO)", default="MX"))
            elif choice == "2":
                action_email(session, Prompt.ask("Correo electrónico"), chain=None)
            elif choice == "3":
                action_breaches(session, Prompt.ask("Correo electrónico"))
            elif choice == "4":
                action_alias(session, Prompt.ask("Alias / username"))
            elif choice == "5":
                action_domain(session, Prompt.ask("Dominio (ej. empresa.com)"))
            elif choice == "6":
                action_password(session)
            elif choice == "7":
                length = IntPrompt.ask("Longitud", default=20)
                action_genpass(session, length=length, symbols=Confirm.ask("¿Incluir símbolos?", default=True))
            elif choice == "8":
                email = Prompt.ask("Correo a auditar [dim](Enter para omitir)[/]", default="").strip() or None
                phone = Prompt.ask("Teléfono a auditar [dim](Enter para omitir)[/]", default="").strip() or None
                if not (email or phone):
                    console.print("[yellow]Indica al menos un correo o un teléfono.[/]")
                else:
                    region = Prompt.ask("Región por defecto (ISO)", default="MX") if phone and not phone.startswith("+") else None
                    action_full_audit(
                        session, email, phone, region,
                        check_password=Confirm.ask("¿Verificar también una contraseña?", default=False),
                        chain=True, graph=True,
                    )
            elif choice == "9":
                action_graph(session)
            elif choice == "10":
                action_remediation(session)
            elif choice == "11":
                action_export(session)
            else:
                if not session.is_empty() and Confirm.ask("¿Exportar la sesión antes de salir?", default=True):
                    action_export(session)
                console.print("[cyan]Hasta luego.[/]")
                return
        except KeyboardInterrupt:
            console.print("\n[yellow]Operación cancelada.[/]")
        console.rule(style="dim")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="osint-recon-tool",
        description="Reconocimiento OSINT y auditoría defensiva de teléfonos y correos.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    p_phone = sub.add_parser("phone", help="Analiza un número telefónico")
    p_phone.add_argument("number", help="Número (ej. '+52 55 1234 5678')")
    p_phone.add_argument("--region", default=None, help="Región ISO por defecto si no tiene '+' (ej. MX)")
    p_phone.add_argument("--graph", action="store_true", help="Genera el grafo interactivo")

    p_email = sub.add_parser("email", help="Reconocimiento OSINT de un correo")
    p_email.add_argument("address")
    chain_group = p_email.add_mutually_exclusive_group()
    chain_group.add_argument("--chain", dest="chain", action="store_true", default=None,
                             help="Ejecuta automáticamente el rastreo de alias y el análisis de dominio")
    chain_group.add_argument("--no-chain", dest="chain", action="store_false", help="No pivota a alias/dominio")
    p_email.add_argument("--graph", action="store_true", help="Genera el grafo interactivo")

    p_breach = sub.add_parser("breaches", help="Auditoría de brechas de un correo (HIBP)")
    p_breach.add_argument("address")

    p_alias = sub.add_parser("alias", help="Rastrea un alias en plataformas públicas")
    p_alias.add_argument("username")

    p_domain = sub.add_parser("domain", help="Inteligencia de dominio (crt.sh + WHOIS)")
    p_domain.add_argument("dominio")

    sub.add_parser("password", help="Verifica una contraseña con k-Anonymity (entrada oculta)")

    p_gen = sub.add_parser("genpass", help="Genera una contraseña segura validada")
    p_gen.add_argument("--length", type=int, default=20)
    p_gen.add_argument("--no-symbols", action="store_true")

    p_audit = sub.add_parser("audit", help="Auditoría completa + remediación + grafo interactivo")
    p_audit.add_argument("--email", help="Correo a auditar")
    p_audit.add_argument("--phone", help="Teléfono a auditar")
    p_audit.add_argument("--region", default=None)
    p_audit.add_argument("--check-password", action="store_true", help="Pide una contraseña para verificarla")
    p_audit.add_argument("--no-chain", action="store_true", help="No pivota del correo a alias/dominio")
    p_audit.add_argument("--no-graph", action="store_true", help="No genera el grafo interactivo")

    for p in (p_phone, p_email, p_breach, p_alias, p_domain, p_gen, p_audit):
        p.add_argument("--export", action="store_true", help="Exporta JSON + HTML a reports/")
        p.add_argument("--output-dir", default="reports", help="Directorio de reportes")
    return parser


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except (ValueError, OSError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    session = Session()
    banner()

    try:
        if args.command is None:
            interactive(session)
            return 0
        if args.command == "phone":
            result = action_phone(session, args.number, args.region)
            if result and args.graph:
                action_graph(session, result["e164"], args.output_dir)
        elif args.command == "email":
            result = action_email(session, args.address, chain=args.chain)
            action_remediation(session)
            if result and args.graph:
                action_graph(session, result["email"], args.output_dir)
        elif args.command == "breaches":
            action_breaches(session, args.address)
            action_remediation(session)
        elif args.command == "alias":
            action_alias(session, args.username)
        elif args.command == "domain":
            action_domain(session, args.dominio)
        elif args.command == "password":
            action_password(session)
        elif args.command == "genpass":
            action_genpass(session, length=args.length, symbols=not args.no_symbols)
        elif args.command == "audit":
            if not (args.email or args.phone or args.check_password):
                parser.error("audit requiere al menos --email, --phone o --check-password")
            action_full_audit(
                session,
                email=args.email,
                phone=args.phone,
                region=args.region,
                check_password=args.check_password,
                chain=not args.no_chain,
                graph=not args.no_graph,
                output_dir=args.output_dir,
            )

        if getattr(args, "export", False):
            action_export(session, args.output_dir)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrumpido por el usuario.[/]")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
