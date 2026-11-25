"""Reconocimiento OSINT de direcciones de correo electrónico.

- Separación de usuario (alias de pivote) y dominio.
- Consultas DNS (MX, SPF, DMARC) con ``dnspython``.
- Perfil público de Gravatar por hash MD5.
- Comprobaciones asíncronas contra endpoints públicos sin autenticación
  (GitHub y GitLab) con timeouts y manejo de errores.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
from typing import Any

import dns.exception
import dns.resolver
import httpx

from modules import USER_AGENT

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

MX_PROVIDERS: dict[str, str] = {
    "google.com": "Google Workspace / Gmail",
    "googlemail.com": "Google Workspace / Gmail",
    "outlook.com": "Microsoft 365 / Outlook",
    "protection.outlook.com": "Microsoft 365 / Exchange Online",
    "yahoodns.net": "Yahoo Mail",
    "zoho.com": "Zoho Mail",
    "zoho.eu": "Zoho Mail",
    "protonmail.ch": "Proton Mail",
    "icloud.com": "Apple iCloud Mail",
    "mimecast.com": "Mimecast (gateway)",
    "pphosted.com": "Proofpoint (gateway)",
    "messagelabs.com": "Broadcom/Symantec (gateway)",
    "secureserver.net": "GoDaddy",
    "mailgun.org": "Mailgun",
    "amazonaws.com": "Amazon SES / AWS",
}


class EmailReconError(Exception):
    """Error controlado durante el reconocimiento de correo."""


def parse_email(email: str) -> dict[str, str]:
    """Normaliza y separa el correo en usuario, alias base y dominio."""
    if not email:
        raise EmailReconError("El correo está vacío.")
    normalized = email.strip().lower()
    if not EMAIL_RE.match(normalized):
        raise EmailReconError(f"Formato de correo inválido: '{email}'")
    user, domain = normalized.rsplit("@", 1)
    base_alias = user.split("+", 1)[0]
    pivot_alias = base_alias.replace(".", "") if domain in {"gmail.com", "googlemail.com"} else base_alias
    return {
        "email": normalized,
        "user": user,
        "base_alias": base_alias,
        "pivot_alias": pivot_alias,
        "domain": domain,
        "plus_tag": user.split("+", 1)[1] if "+" in user else "",
    }


def _detect_provider(mx_hosts: list[str]) -> str:
    for host in mx_hosts:
        host_l = host.lower().rstrip(".")
        for suffix, provider in MX_PROVIDERS.items():
            if host_l == suffix or host_l.endswith("." + suffix):
                return provider
    return "Propio / desconocido" if mx_hosts else "N/A"


def _txt_records(resolver: dns.resolver.Resolver, qname: str) -> list[str]:
    answer = resolver.resolve(qname, "TXT")
    records: list[str] = []
    for rdata in answer:
        records.append(b"".join(rdata.strings).decode("utf-8", errors="replace"))
    return records


def _assess_spf(record: str | None) -> dict[str, Any]:
    if not record:
        return {
            "present": False,
            "record": "",
            "all_qualifier": "",
            "assessment": "Sin SPF: el dominio es susceptible a suplantación (spoofing).",
        }
    match = re.search(r"([~\-+?]?)all\b", record)
    qualifier = (match.group(1) or "+") if match else ""
    assessments = {
        "-": "Estricto (-all): rechaza remitentes no autorizados.",
        "~": "SoftFail (~all): marca como sospechoso, protección moderada.",
        "?": "Neutral (?all): no ofrece protección real.",
        "+": "Permisivo (+all): cualquiera puede enviar en nombre del dominio. CRÍTICO.",
        "": "Sin mecanismo 'all' explícito: política incompleta.",
    }
    return {"present": True, "record": record, "all_qualifier": f"{qualifier}all" if match else "", "assessment": assessments[qualifier]}


def _assess_dmarc(record: str | None) -> dict[str, Any]:
    if not record:
        return {
            "present": False,
            "record": "",
            "policy": "",
            "assessment": "Sin DMARC: no hay política contra suplantación ni reportes.",
        }
    match = re.search(r"\bp\s*=\s*(\w+)", record, re.IGNORECASE)
    policy = match.group(1).lower() if match else ""
    assessments = {
        "reject": "p=reject: máxima protección contra suplantación.",
        "quarantine": "p=quarantine: los correos no alineados van a spam.",
        "none": "p=none: solo monitoreo, NO bloquea suplantaciones.",
    }
    return {
        "present": True,
        "record": record,
        "policy": policy,
        "assessment": assessments.get(policy, "Política DMARC no reconocida o mal formada."),
    }


def query_dns(domain: str, timeout: float = 5.0) -> dict[str, Any]:
    """Consulta MX, SPF (TXT) y DMARC (_dmarc TXT) del dominio."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2

    result: dict[str, Any] = {
        "domain": domain,
        "domain_exists": True,
        "mx": [],
        "mail_active": False,
        "implicit_mx": False,
        "null_mx": False,
        "provider": "N/A",
        "spf": _assess_spf(None),
        "dmarc": _assess_dmarc(None),
        "errors": [],
    }

    # --- MX ---
    try:
        answer = resolver.resolve(domain, "MX")
        mx = sorted(
            ({"preference": int(r.preference), "exchange": r.exchange.to_text().rstrip(".")} for r in answer),
            key=lambda x: x["preference"],
        )
        result["mx"] = mx
        if len(mx) == 1 and mx[0]["exchange"] in {"", "."}:
            result["null_mx"] = True  # RFC 7505: el dominio no acepta correo
        else:
            result["mail_active"] = True
    except dns.resolver.NXDOMAIN:
        result["domain_exists"] = False
        result["errors"].append("NXDOMAIN: el dominio no existe.")
        return result
    except dns.resolver.NoAnswer:
        # RFC 5321: sin MX se usa el registro A como MX implícito
        try:
            resolver.resolve(domain, "A")
            result["implicit_mx"] = True
            result["mail_active"] = True
        except dns.exception.DNSException:
            result["errors"].append("Sin registros MX ni A: el dominio no recibe correo.")
    except dns.resolver.NoNameservers:
        result["errors"].append("Ningún servidor DNS respondió para MX.")
    except dns.exception.Timeout:
        result["errors"].append("Timeout consultando MX.")
    except dns.exception.DNSException as exc:
        result["errors"].append(f"Error DNS (MX): {exc}")

    result["provider"] = _detect_provider([m["exchange"] for m in result["mx"]])

    # --- SPF ---
    try:
        spf_records = [r for r in _txt_records(resolver, domain) if r.lower().startswith("v=spf1")]
        if len(spf_records) > 1:
            result["errors"].append("Múltiples registros SPF: inválido según RFC 7208.")
        result["spf"] = _assess_spf(spf_records[0] if spf_records else None)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    except dns.exception.DNSException as exc:
        result["errors"].append(f"Error DNS (SPF): {exc}")

    # --- DMARC ---
    try:
        dmarc_records = [r for r in _txt_records(resolver, f"_dmarc.{domain}") if r.lower().startswith("v=dmarc1")]
        result["dmarc"] = _assess_dmarc(dmarc_records[0] if dmarc_records else None)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    except dns.exception.DNSException as exc:
        result["errors"].append(f"Error DNS (DMARC): {exc}")

    return result


def _error(source: str, message: str) -> dict[str, Any]:
    return {"source": source, "status": "error", "error": message, "data": None}


def _rate_limited(response: httpx.Response) -> bool:
    return response.status_code == 429 or (
        response.status_code == 403 and response.headers.get("x-ratelimit-remaining") == "0"
    )


async def check_gravatar(client: httpx.AsyncClient, md5_hash: str) -> dict[str, Any]:
    source = "Gravatar"
    try:
        response = await client.get(f"https://www.gravatar.com/{md5_hash}.json")
    except httpx.TimeoutException:
        return _error(source, "Timeout")
    except httpx.HTTPError as exc:
        return _error(source, str(exc))

    if response.status_code == 404:
        return {"source": source, "status": "not_found", "data": {"md5": md5_hash}}
    if response.status_code != 200:
        return _error(source, f"HTTP {response.status_code}")
    try:
        entry = response.json().get("entry", [{}])[0]
    except (ValueError, IndexError, AttributeError):
        return _error(source, "Respuesta JSON inesperada")

    return {
        "source": source,
        "status": "found",
        "data": {
            "md5": md5_hash,
            "profile_url": entry.get("profileUrl", ""),
            "avatar_url": f"https://www.gravatar.com/avatar/{md5_hash}?s=200",
            "display_name": entry.get("displayName", ""),
            "preferred_username": entry.get("preferredUsername", ""),
            "about": entry.get("aboutMe", ""),
            "location": entry.get("currentLocation", ""),
            "accounts": [
                {"service": a.get("shortname", ""), "url": a.get("url", "")} for a in entry.get("accounts", []) or []
            ],
            "urls": [u.get("value", "") for u in entry.get("urls", []) or []],
        },
    }


async def check_github_email(client: httpx.AsyncClient, email: str) -> dict[str, Any]:
    """Busca usuarios con el correo público y commits firmados con ese correo."""
    source = "GitHub (correo)"
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    try:
        users_resp, commits_resp = await asyncio.gather(
            client.get("https://api.github.com/search/users", params={"q": f"{email} in:email"}, headers=headers),
            client.get("https://api.github.com/search/commits", params={"q": f"author-email:{email}", "per_page": 10}, headers=headers),
        )
    except httpx.TimeoutException:
        return _error(source, "Timeout")
    except httpx.HTTPError as exc:
        return _error(source, str(exc))

    if _rate_limited(users_resp) or _rate_limited(commits_resp):
        return {"source": source, "status": "rate_limited", "error": "Límite de peticiones anónimas de GitHub alcanzado", "data": None}

    data: dict[str, Any] = {"users": [], "commit_count": 0, "commits": [], "commit_authors": []}
    if users_resp.status_code == 200:
        payload = users_resp.json()
        data["users"] = [{"login": u.get("login"), "url": u.get("html_url")} for u in payload.get("items", [])]
    if commits_resp.status_code == 200:
        payload = commits_resp.json()
        data["commit_count"] = payload.get("total_count", 0)
        authors: set[str] = set()
        for item in payload.get("items", []):
            commit = item.get("commit", {})
            author = commit.get("author", {}) or {}
            login = (item.get("author") or {}).get("login")
            if login:
                authors.add(login)
            data["commits"].append(
                {
                    "repo": (item.get("repository") or {}).get("full_name", ""),
                    "author_name": author.get("name", ""),
                    "date": author.get("date", ""),
                    "url": item.get("html_url", ""),
                }
            )
        data["commit_authors"] = sorted(authors)

    found = bool(data["users"] or data["commit_count"])
    return {"source": source, "status": "found" if found else "not_found", "data": data}


async def check_github_username(client: httpx.AsyncClient, alias: str) -> dict[str, Any]:
    source = "GitHub (alias)"
    try:
        response = await client.get(f"https://api.github.com/users/{alias}", headers={"Accept": "application/vnd.github+json"})
    except httpx.TimeoutException:
        return _error(source, "Timeout")
    except httpx.HTTPError as exc:
        return _error(source, str(exc))
    if _rate_limited(response):
        return {"source": source, "status": "rate_limited", "error": "Límite de GitHub alcanzado", "data": None}
    if response.status_code == 404:
        return {"source": source, "status": "not_found", "data": {"alias": alias}}
    if response.status_code != 200:
        return _error(source, f"HTTP {response.status_code}")
    u = response.json()
    return {
        "source": source,
        "status": "found",
        "data": {
            "login": u.get("login"),
            "name": u.get("name"),
            "url": u.get("html_url"),
            "company": u.get("company"),
            "location": u.get("location"),
            "blog": u.get("blog"),
            "public_repos": u.get("public_repos"),
            "created_at": u.get("created_at"),
        },
    }


async def check_gitlab_username(client: httpx.AsyncClient, alias: str) -> dict[str, Any]:
    source = "GitLab (alias)"
    try:
        response = await client.get("https://gitlab.com/api/v4/users", params={"username": alias})
    except httpx.TimeoutException:
        return _error(source, "Timeout")
    except httpx.HTTPError as exc:
        return _error(source, str(exc))
    if response.status_code == 429:
        return {"source": source, "status": "rate_limited", "error": "Límite de GitLab alcanzado", "data": None}
    if response.status_code != 200:
        return _error(source, f"HTTP {response.status_code}")
    users = response.json()
    if not users:
        return {"source": source, "status": "not_found", "data": {"alias": alias}}
    u = users[0]
    return {
        "source": source,
        "status": "found",
        "data": {"username": u.get("username"), "name": u.get("name"), "url": u.get("web_url"), "state": u.get("state")},
    }


async def run_email_recon(email: str, timeout: float | None = None) -> dict[str, Any]:
    """Ejecuta todo el reconocimiento de un correo y devuelve un diccionario de resultados."""
    parsed = parse_email(email)
    http_timeout = timeout if timeout is not None else float(os.getenv("HTTP_TIMEOUT", "10"))
    md5_hash = hashlib.md5(parsed["email"].encode("utf-8")).hexdigest()

    dns_task = asyncio.to_thread(query_dns, parsed["domain"])

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(http_timeout),
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
    ) as client:
        gathered = await asyncio.gather(
            dns_task,
            check_gravatar(client, md5_hash),
            check_github_email(client, parsed["email"]),
            check_github_username(client, parsed["pivot_alias"]),
            check_gitlab_username(client, parsed["pivot_alias"]),
            return_exceptions=True,
        )

    dns_result, *checks = gathered
    if isinstance(dns_result, BaseException):
        dns_result = {"domain": parsed["domain"], "errors": [f"Fallo DNS: {dns_result}"], "mail_active": False}

    sources = ["Gravatar", "GitHub (correo)", "GitHub (alias)", "GitLab (alias)"]
    normalized_checks: list[dict[str, Any]] = []
    for name, check in zip(sources, checks):
        if isinstance(check, BaseException):
            normalized_checks.append(_error(name, f"Excepción no controlada: {check}"))
        else:
            normalized_checks.append(check)

    return {
        **parsed,
        "md5": md5_hash,
        "dns": dns_result,
        "checks": normalized_checks,
    }
