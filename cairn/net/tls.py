from __future__ import annotations

import asyncio
import hashlib
import ssl
from datetime import UTC, datetime
from typing import Any


async def probe_tls(
    host: str,
    ip: str,
    port: int,
    *,
    timeout: float = 6.0,
    server_hostname: str | None = None,
) -> dict[str, Any]:
    """Capture certificate and negotiated protocol without trusting it.

    A separate verified handshake determines whether a normal client would
    accept the certificate. The first handshake is intentionally unverified so
    expired/self-signed/mismatched certificates can still be documented.
    """

    sni = server_hostname or host
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    result: dict[str, Any] = {
        "connected": False,
        "verified": False,
        "verification_error": None,
        "protocol": None,
        "cipher": None,
        "certificate": None,
        "fingerprint_sha256": None,
    }
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=context, server_hostname=sni), timeout=timeout
        )
        del reader
        ssl_obj = writer.get_extra_info("ssl_object")
        result["connected"] = True
        if ssl_obj is not None:
            result["protocol"] = ssl_obj.version()
            cipher = ssl_obj.cipher()
            result["cipher"] = cipher[0] if cipher else None
            cert = ssl_obj.getpeercert()
            if cert:
                result["certificate"] = _cert_summary(cert)
            der = ssl_obj.getpeercert(binary_form=True)
            if der:
                result["fingerprint_sha256"] = hashlib.sha256(der).hexdigest()
    except (TimeoutError, OSError, ssl.SSLError) as exc:
        result["error"] = str(exc)
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ssl.SSLError):
                pass

    verify_context = ssl.create_default_context()
    writer = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=verify_context, server_hostname=sni), timeout=timeout
        )
        result["verified"] = True
    except (TimeoutError, OSError, ssl.SSLError) as exc:
        result["verification_error"] = str(exc)
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ssl.SSLError):
                pass
    return result


def _cert_summary(cert: dict[str, Any]) -> dict[str, Any]:
    subject = _flatten_name(cert.get("subject", ()))
    issuer = _flatten_name(cert.get("issuer", ()))
    not_after = cert.get("notAfter")
    not_before = cert.get("notBefore")
    days_remaining = None
    if not_after:
        try:
            expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=UTC)
            days_remaining = (expiry - datetime.now(UTC)).days
        except (ValueError, OverflowError):
            pass
    return {
        "subject": subject,
        "issuer": issuer,
        "not_before": not_before,
        "not_after": not_after,
        "days_remaining": days_remaining,
        "sans": [value for key, value in cert.get("subjectAltName", ()) if key == "DNS"],
        "serial": cert.get("serialNumber"),
    }


def _flatten_name(parts: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    for rdn in parts or ():
        for key, value in rdn:
            out[key] = value
    return out
