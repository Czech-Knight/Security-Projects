from __future__ import annotations

import ipaddress
import socket
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from app.config import settings


class TargetPolicyError(ValueError):
    pass


_LOCAL_NAMES = {"localhost", "127.0.0.1", "::1", "host.docker.internal"}
_REDIRECT_CODES = {301, 302, 303, 307, 308}


def _resolved_addresses(host: str, port: int) -> set[str]:
    try:
        return {
            item[4][0].split("%", 1)[0]
            for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        }
    except socket.gaierror as exc:
        raise TargetPolicyError(f"Target hostname could not be resolved: {host}") from exc


def is_local_target(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    host = parsed.hostname.lower()
    if host in _LOCAL_NAMES:
        return True
    try:
        addresses = _resolved_addresses(host, parsed.port or (443 if parsed.scheme == "https" else 80))
        return bool(addresses) and all(ipaddress.ip_address(address).is_loopback for address in addresses)
    except (TargetPolicyError, ValueError):
        return False


def validate_dynamic_target(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise TargetPolicyError("Target URL must use http:// or https:// and include a hostname.")
    if parsed.username or parsed.password:
        raise TargetPolicyError("Credentials must not be embedded in a target URL. Use an authentication profile.")
    host = parsed.hostname.lower()
    if host in _LOCAL_NAMES:
        return url

    addresses = _resolved_addresses(host, parsed.port or (443 if parsed.scheme == "https" else 80))
    try:
        all_loopback = bool(addresses) and all(ipaddress.ip_address(address).is_loopback for address in addresses)
    except ValueError as exc:
        raise TargetPolicyError(f"Target resolved to an invalid IP address: {host}") from exc
    if all_loopback:
        return url
    if not settings.allow_remote_dynamic_scan:
        raise TargetPolicyError(
            "Remote dynamic testing is disabled. Use localhost/127.0.0.1 or explicitly enable authorised remote scanning."
        )
    return url


def safe_request(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    max_redirects: int = 3,
    **kwargs: Any,
) -> httpx.Response:
    """Request a target while re-validating every redirect destination.

    This prevents a permitted loopback URL from redirecting scanners to an unauthorised
    remote host. Callers receive the final response, or the last redirect response when
    no Location header is present.
    """

    current = validate_dynamic_target(url)
    for redirect_count in range(max_redirects + 1):
        response = client.request(method, current, follow_redirects=False, **kwargs)
        if response.status_code not in _REDIRECT_CODES:
            return response
        location = response.headers.get("location")
        if not location:
            return response
        if redirect_count >= max_redirects:
            raise TargetPolicyError("Target exceeded the maximum safe redirect count.")
        current = validate_dynamic_target(urljoin(current, location))
    raise TargetPolicyError("Target redirect validation failed.")
