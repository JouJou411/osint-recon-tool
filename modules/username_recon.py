"""Reconocimiento pasivo de alias (usernames) en plataformas públicas.

Comprueba de forma asíncrona si existe un perfil público con el alias dado,
evaluando el código de estado HTTP (200 = encontrado). Algunas plataformas
incluyen un validador adicional para evitar falsos positivos (p. ej. APIs que
responden 200 con cuerpo ``null`` o redirecciones a páginas de login).
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

import httpx
from rich import box
from rich.console import Console
from rich.table import Table

from modules import USER_AGENT

console = Console()

REQUEST_TIMEOUT = 8.0
USERNAME_RE = re.compile(r"^[A-Za-z0-9._\-]{1,39}$")
LOGIN_MARKERS = ("login", "signin", "sign_in", "sign-in", "/auth")


def _json_not_null(response: httpx.Response) -> bool:
    try:
        return response.json() is not None
    except ValueError:
        return False


def _keybase_found(response: httpx.Response) -> bool:
    try:
        them = response.json().get("them") or []
    except (ValueError, AttributeError):
        return False
    return any(item is not None for item in them)


@dataclass(frozen=True)
class Platform:
    name: str
    profile_url: str  # URL pública que se muestra al usuario
    check_url: str  # URL que se consulta (puede ser una API)
    validator: Callable[[httpx.Response], bool] | None = None


PLATFORMS: tuple[Platform, ...] = (
    Platform("GitHub", "https://github.com/{u}", "https://github.com/{u}"),
    Platform("GitLab", "https://gitlab.com/{u}", "https://gitlab.com/{u}"),
    Platform("Reddit", "https://www.reddit.com/user/{u}", "https://www.reddit.com/user/{u}/about.json"),
    Platform("Dev.to", "https://dev.to/{u}", "https://dev.to/api/users/by_username?url={u}"),
    Platform("Medium", "https://medium.com/@{u}", "https://medium.com/@{u}"),
    Platform("Pinterest", "https://www.pinterest.com/{u}/", "https://www.pinterest.com/{u}/"),
    Platform("Vimeo", "https://vimeo.com/{u}", "https://vimeo.com/{u}"),
    Platform("About.me", "https://about.me/{u}", "https://about.me/{u}"),
    Platform("Docker Hub", "https://hub.docker.com/u/{u}", "https://hub.docker.com/v2/users/{u}/"),
    Platform("PyPI", "https://pypi.org/user/{u}/", "https://pypi.org/user/{u}/"),
    Platform(
        "Hacker News",
        "https://news.ycombinator.com/user?id={u}",
        "https://hacker-news.firebaseio.com/v0/user/{u}.json",
        _json_not_null,
    ),
    Platform(
        "Keybase",
        "https://keybase.io/{u}",
        "https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}",
        _keybase_found,
    ),
)


class UsernameReconError(Exception):
    """Error controlado durante la búsqueda de alias."""


def _validate_username(username: str) -> str:
    alias = (username or "").strip().lstrip("@")
    if not USERNAME_RE.match(alias):
        raise UsernameReconError(
            f"Alias inválido: '{username}'. Usa 1-39 caracteres: letras, números, '.', '_' o '-'."
        )
    return alias


async def _check_platform(client: httpx.AsyncClient, platform: Platform, alias: str) -> dict[str, Any]:
    profile_url = platform.profile_url.format(u=alias)
    result: dict[str, Any] = {
        "platform": platform.name,
        "url": profile_url,
        "status": "error",
        "http_status": None,
        "detail": "",
    }
    try:
        response = await client.get(platform.check_url.format(u=alias))
    except httpx.TimeoutException:
        result["detail"] = f"Timeout ({REQUEST_TIMEOUT:.0f}s)"
        return result
    except httpx.HTTPError as exc:
        result["detail"] = f"Error de red: {exc.__class__.__name__}"
        return result

    code = response.status_code
    result["http_status"] = code
    final_path = response.url.path.lower()

    if code == 200:
        if any(marker in final_path for marker in LOGIN_MARKERS):
            result.update(status="not_found", detail="Redirigido a página de login")
        elif platform.validator is not None and not platform.validator(response):
            result.update(status="not_found", detail="Respuesta 200 sin perfil asociado")
        else:
            result.update(status="found", detail="Perfil público detectado")
    elif code in (404, 410):
        result.update(status="not_found", detail="No existe")
    elif code in (403, 429, 999):
        result.update(status="blocked", detail="Bloqueado / rate limit (indeterminado)")
    else:
        result.update(status="unknown", detail=f"Código HTTP inesperado {code}")
    return result


def _render(data: dict[str, Any]) -> None:
    found = [r for r in data["results"] if r["status"] == "found"]
    table = Table(
        title=f"👤 Perfiles detectados para '{data['username']}' ({len(found)}/{data['total_platforms']})",
        box=box.ROUNDED,
        title_style="bold cyan",
        show_lines=False,
    )
    table.add_column("#", style="dim", justify="right")
    table.add_column("Plataforma", style="bold white", no_wrap=True)
    table.add_column("URL directa", style="cyan", overflow="fold")
    table.add_column("HTTP", justify="center")
    for idx, r in enumerate(found, 1):
        table.add_row(str(idx), r["platform"], f"[link={r['url']}]{r['url']}[/link]", str(r["http_status"]))
    if not found:
        table.add_row("—", "[dim]Sin coincidencias[/]", "", "")
    console.print(table)

    others = [r for r in data["results"] if r["status"] in ("blocked", "unknown", "error")]
    if others:
        listing = ", ".join(f"{r['platform']} ({r['detail']})" for r in others)
        console.print(f"[yellow]⚠ Resultado indeterminado en:[/] {listing}")
    console.print("[dim]ℹ Una coincidencia de alias no garantiza que el perfil pertenezca a la misma persona.[/]")


async def buscar_alias(username: str, mostrar: bool = True) -> dict[str, Any]:
    """Busca el alias de forma concurrente en todas las plataformas y devuelve los resultados."""
    alias = _validate_username(username)
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
        "Accept-Language": "es-MX,es;q=0.9,en;q=0.8",
    }
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(REQUEST_TIMEOUT),
        headers=headers,
        follow_redirects=True,
    ) as client:
        gathered = await asyncio.gather(
            *(_check_platform(client, p, alias) for p in PLATFORMS),
            return_exceptions=True,
        )

    results: list[dict[str, Any]] = []
    for platform, item in zip(PLATFORMS, gathered):
        if isinstance(item, BaseException):
            results.append(
                {
                    "platform": platform.name,
                    "url": platform.profile_url.format(u=alias),
                    "status": "error",
                    "http_status": None,
                    "detail": f"Excepción no controlada: {item}",
                }
            )
        else:
            results.append(item)

    found = [r for r in results if r["status"] == "found"]
    data: dict[str, Any] = {
        "username": alias,
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total_platforms": len(PLATFORMS),
        "found_count": len(found),
        "found": [{"platform": r["platform"], "url": r["url"]} for r in found],
        "results": results,
    }
    if mostrar:
        _render(data)
    return data


def ejecutar_busqueda_alias(username: str, mostrar: bool = True) -> dict[str, Any]:
    """Envoltorio síncrono de :func:`buscar_alias`.

    Si ya existe un event loop en ejecución (p. ej. Jupyter), la corrutina se ejecuta
    en un hilo independiente para evitar ``RuntimeError``.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(buscar_alias(username, mostrar))

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        return executor.submit(asyncio.run, buscar_alias(username, mostrar)).result()
