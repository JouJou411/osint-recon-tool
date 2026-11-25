"""Exportación de resultados de sesión a JSON estructurado y HTML visual."""

from __future__ import annotations

import html
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

SECTION_TITLES: dict[str, str] = {
    "phone": "Reconocimiento de teléfonos",
    "email": "Reconocimiento de correos",
    "username": "Rastreo de alias en plataformas",
    "domain": "Inteligencia de dominio (crt.sh / WHOIS)",
    "breaches": "Estado de brechas (HIBP)",
    "password_check": "Verificación de contraseñas (k-Anonymity)",
    "generated_passwords": "Contraseñas generadas (metadatos)",
    "graphs": "Grafos interactivos de relaciones",
    "remediation": "Plan de remediación",
}

SEVERITY_COLORS: dict[str, str] = {
    "CRÍTICA": "#b71c1c",
    "ALTA": "#e65100",
    "MEDIA": "#f9a825",
    "BAJA": "#2e7d32",
}

CSS = """
*{box-sizing:border-box}body{font-family:'Segoe UI',Roboto,Arial,sans-serif;margin:0;background:#0f172a;color:#e2e8f0}
header{background:linear-gradient(135deg,#1e3a8a,#0f766e);padding:28px 40px}header h1{margin:0;font-size:26px}
header p{margin:4px 0 0;opacity:.85}main{padding:24px 40px;max-width:1300px;margin:auto}
section{background:#1e293b;border-radius:10px;padding:20px 24px;margin-bottom:24px;box-shadow:0 2px 8px #0006}
h2{margin-top:0;color:#38bdf8;border-bottom:1px solid #334155;padding-bottom:8px}
.card{background:#0f172a;border:1px solid #334155;border-radius:8px;padding:14px;margin:12px 0}
table{border-collapse:collapse;width:100%;margin:6px 0;font-size:14px}
td,th{border:1px solid #334155;padding:6px 10px;text-align:left;vertical-align:top;word-break:break-word}
th{background:#334155;color:#f8fafc;width:22%}a{color:#5eead4}ul{margin:4px 0;padding-left:20px}
.badge{display:inline-block;padding:3px 10px;border-radius:12px;color:#fff;font-weight:600;font-size:12px}
.trigger{display:inline-block;padding:2px 8px;border-radius:10px;background:#475569;font-size:12px;margin-left:6px}
.summary span{margin-right:10px}.muted{color:#94a3b8}footer{text-align:center;color:#64748b;padding:20px;font-size:12px}
.disclaimer{background:#422006;border-left:4px solid #f59e0b;padding:10px 14px;border-radius:6px;font-size:13px}
"""

URL_RE = re.compile(r"^https?://", re.IGNORECASE)


class ReportExporter:
    """Genera reportes JSON y HTML de una sesión dentro de ``reports/``."""

    def __init__(self, base_dir: str | Path = "reports") -> None:
        self.base_dir = Path(base_dir)

    def _ensure_dir(self) -> None:
        self.base_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _basename(session: dict[str, Any]) -> str:
        return f"osint_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    def export(self, session: dict[str, Any], basename: str | None = None) -> dict[str, Path]:
        """Exporta la sesión en ambos formatos y devuelve las rutas generadas."""
        self._ensure_dir()
        name = basename or self._basename(session)
        return {"json": self.export_json(session, name), "html": self.export_html(session, name)}

    def export_json(self, session: dict[str, Any], basename: str) -> Path:
        self._ensure_dir()
        path = self.base_dir / f"{basename}.json"
        try:
            path.write_text(json.dumps(session, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        except OSError as exc:
            raise RuntimeError(f"No se pudo escribir el JSON en {path}: {exc}") from exc
        return path

    # ------------------------------------------------------------------ #
    # HTML
    # ------------------------------------------------------------------ #
    def _render_scalar(self, value: Any) -> str:
        if value is None or value == "":
            return '<span class="muted">—</span>'
        if isinstance(value, bool):
            return "✅ Sí" if value else "❌ No"
        text = str(value)
        if URL_RE.match(text):
            esc = html.escape(text)
            label = esc if len(esc) <= 90 else esc[:87] + "..."
            return f'<a href="{esc}" target="_blank" rel="noopener noreferrer">{label}</a>'
        return html.escape(text)

    def _render_value(self, value: Any, depth: int = 0) -> str:
        if isinstance(value, dict):
            if not value:
                return '<span class="muted">—</span>'
            rows = "".join(
                f"<tr><th>{html.escape(str(k))}</th><td>{self._render_value(v, depth + 1)}</td></tr>" for k, v in value.items()
            )
            return f"<table>{rows}</table>"
        if isinstance(value, (list, tuple)):
            if not value:
                return '<span class="muted">(vacío)</span>'
            if all(isinstance(v, dict) for v in value):
                return "".join(f'<div class="card">{self._render_value(v, depth + 1)}</div>' for v in value)
            return "<ul>" + "".join(f"<li>{self._render_value(v, depth + 1)}</li>" for v in value) + "</ul>"
        return self._render_scalar(value)

    def _render_remediation(self, plan: dict[str, Any]) -> str:
        summary = plan.get("summary", {})
        badges = "".join(
            f'<span class="badge" style="background:{SEVERITY_COLORS.get(sev, "#475569")}">{html.escape(sev)}: {count}</span>'
            for sev, count in summary.items()
        )
        parts = [f'<p class="summary">{badges}</p>']
        for item in plan.get("items", []):
            sev = item.get("severity", "")
            color = SEVERITY_COLORS.get(sev, "#475569")
            actions = "".join(f"<li>{html.escape(a)}</li>" for a in item.get("actions", []))
            parts.append(
                '<div class="card">'
                f'<span class="badge" style="background:{color}">{html.escape(sev)}</span> '
                f'<strong>{html.escape(item.get("data_class", ""))}</strong> '
                f'<span class="muted">({html.escape(item.get("category", ""))})</span>'
                f'<span class="trigger">{html.escape(item.get("trigger", ""))}</span>'
                f"<ul>{actions}</ul></div>"
            )
        return "".join(parts)

    def _render_graphs(self, graphs: list[dict[str, Any]]) -> str:
        if not graphs:
            return '<span class="muted">(vacío)</span>'
        cards: list[str] = []
        for g in graphs:
            target = html.escape(str(g.get("target", "")))
            raw_path = str(g.get("path", ""))
            generated_at = html.escape(str(g.get("generated_at", "")))
            file_name = Path(raw_path).name if raw_path else ""
            link_html = (
                f'<a href="{html.escape(file_name)}" target="_blank" rel="noopener noreferrer">{html.escape(file_name)}</a>'
                if file_name
                else '<span class="muted">—</span>'
            )
            cards.append(
                '<div class="card">'
                f"<strong>Objetivo:</strong> {target}<br>"
                f"<strong>Grafo interactivo:</strong> {link_html}<br>"
                f'<span class="muted">Ruta: {html.escape(raw_path)} · Generado: {generated_at}</span>'
                "</div>"
            )
        return "".join(cards)

    def build_html(self, session: dict[str, Any]) -> str:
        meta = session.get("metadata", {})
        results = session.get("results", {})
        sections: list[str] = []
        for key, value in results.items():
            title = SECTION_TITLES.get(key, key.replace("_", " ").title())
            if key == "remediation" and isinstance(value, dict):
                body = self._render_remediation(value)
            elif key == "graphs" and isinstance(value, list):
                body = self._render_graphs(value)
            else:
                body = self._render_value(value)
            sections.append(f"<section><h2>{html.escape(title)}</h2>{body}</section>")
        if not sections:
            sections.append('<section><p class="muted">La sesión no contiene resultados.</p></section>')

        return f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Reporte OSINT - {html.escape(str(meta.get('session_id', '')))}</title><style>{CSS}</style></head>
<body><header><h1>🛡️ {html.escape(str(meta.get('tool', 'osint-recon-tool')))} — Reporte de auditoría</h1>
<p>Sesión: {html.escape(str(meta.get('session_id', '')))} · Inicio: {html.escape(str(meta.get('created_at', '')))} ·
Exportado: {html.escape(datetime.now().isoformat(timespec='seconds'))} · Versión {html.escape(str(meta.get('version', '')))}</p></header>
<main><section><h2>Metadatos</h2>{self._render_value(meta)}
<p class="disclaimer">Reporte generado con fines defensivos (Blue Team / CTI). Úsese únicamente sobre activos propios o con autorización expresa.
No contiene contraseñas en texto plano.</p></section>
{''.join(sections)}</main><footer>osint-recon-tool · Reporte confidencial</footer></body></html>"""

    def export_html(self, session: dict[str, Any], basename: str) -> Path:
        self._ensure_dir()
        path = self.base_dir / f"{basename}.html"
        try:
            path.write_text(self.build_html(session), encoding="utf-8")
        except OSError as exc:
            raise RuntimeError(f"No se pudo escribir el HTML en {path}: {exc}") from exc
        return path
