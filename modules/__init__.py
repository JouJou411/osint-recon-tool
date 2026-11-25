"""osint-recon-tool: módulos de reconocimiento OSINT y auditoría defensiva."""

from __future__ import annotations

__version__ = "1.0.0"
__tool_name__ = "osint-recon-tool"
USER_AGENT = f"{__tool_name__}/{__version__} (defensive-audit; +https://github.com/)"

__all__ = [
    "__version__",
    "__tool_name__",
    "USER_AGENT",
    "phone_recon",
    "email_recon",
    "breach_auditor",
    "report_exporter",
    "username_recon",
    "domain_recon",
    "graph_builder",
]
