"""
domain-data-mcp — Combined Domain Intelligence MCP Server

Aggregates DNS records, WHOIS data, and SSL status for any domain.
Uses dns.google for DNS, python-whois for WHOIS, and ssl+socket for SSL.
Tool annotations: @mcp.tool() with docstrings
Service-prefixed naming: domain_info_*
Error-as-result pattern: returns {"error": ...} dict on failure, never throws
"""

import datetime
import socket
import ssl
import sys
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("domain-data-mcp", instructions="Combined domain intelligence MCP server")

RECORD_TYPES = {"A", "AAAA", "MX", "NS", "CNAME", "TXT"}
DNS_API = "https://dns.google/resolve"
SSL_TIMEOUT = 10.0
DEFAULT_PORT = 443


def _make_error(message: str) -> dict[str, Any]:
    return {"error": message}


# ── DNS helpers ──────────────────────────────────────────────────────────

def _lookup_dns(domain: str, record_type: str) -> list[dict[str, Any]]:
    """Return list of DNS answer dicts, or empty list on error."""
    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(DNS_API, params={"name": domain, "type": record_type})
            resp.raise_for_status()
            data = resp.json()
    except Exception:
        return []

    if data.get("Status") != 0:
        return []

    answers = data.get("Answer", [])
    results = []
    for ans in answers:
        results.append({
            "type": record_type,
            "ttl": ans.get("TTL", 0),
            "data": ans.get("data", ""),
        })
    return results


def _get_all_dns_records(domain: str) -> dict[str, Any]:
    """Get all DNS records for a domain."""
    records: dict[str, Any] = {}
    for rtype in sorted(RECORD_TYPES):
        recs = _lookup_dns(domain, rtype)
        if recs:
            records[rtype] = recs
    return records


# ── WHOIS helpers ────────────────────────────────────────────────────────

def _get_whois(domain: str) -> dict[str, Any]:
    """Get WHOIS data for a domain. Uses python-whois if available."""
    try:
        import whois as whois_module
    except ImportError:
        return _make_error("python-whois module not available")

    try:
        w = whois_module.whois(domain)
    except Exception as e:
        return _make_error(f"WHOIS lookup failed: {str(e)}")

    result: dict[str, Any] = {}

    # Registrar
    registrar = w.get("registrar")
    if registrar:
        result["registrar"] = str(registrar)

    # Creation date
    creation = w.get("creation_date")
    if creation:
        if isinstance(creation, list):
            creation = creation[0]
        result["creation_date"] = str(creation)
        if isinstance(creation, datetime.datetime):
            result["creation_date_iso"] = creation.isoformat()

    # Expiration date
    expiration = w.get("expiration_date")
    if expiration:
        if isinstance(expiration, list):
            expiration = expiration[0]
        result["expiration_date"] = str(expiration)
        if isinstance(expiration, datetime.datetime):
            result["expiration_date_iso"] = expiration.isoformat()
            result["days_until_expiry"] = (expiration - datetime.datetime.now(expiration.tzinfo)).days

    # Updated date
    updated = w.get("updated_date")
    if updated:
        if isinstance(updated, list):
            updated = updated[0]
        result["updated_date"] = str(updated)

    # Name servers
    ns = w.get("name_servers")
    if ns:
        if isinstance(ns, list):
            result["name_servers"] = [str(n) for n in ns]
        else:
            result["name_servers"] = [str(ns)]

    # Status
    status = w.get("status")
    if status:
        if isinstance(status, list):
            result["status"] = [str(s) for s in status]
        else:
            result["status"] = [str(status)]

    # Domain name
    domain_name = w.get("domain_name")
    if domain_name:
        if isinstance(domain_name, list):
            result["domain_name"] = domain_name[0]
        else:
            result["domain_name"] = domain_name

    # Other fields
    for field in ("dnssec", "org", "country", "city", "state", "emails"):
        val = w.get(field)
        if val:
            result[field] = str(val)

    return result


# ── SSL helpers ──────────────────────────────────────────────────────────

def _get_ssl_status(domain: str, port: int = DEFAULT_PORT) -> dict[str, Any]:
    """Check SSL for a domain, returning summary status."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=SSL_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls_sock:
                cert = tls_sock.getpeercert()
    except Exception as e:
        return {"valid": False, "error": str(e)}

    if not cert:
        return {"valid": False, "error": "No certificate presented"}

    not_after_str = cert.get("notAfter", "")
    days_remaining = None
    valid = False
    if not_after_str:
        try:
            expiry_dt = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            days_remaining = (expiry_dt - datetime.datetime.now()).days
            valid = days_remaining > 0
        except (ValueError, TypeError):
            pass

    issuer_parts = []
    for part in cert.get("issuer", []):
        for key, val in part:
            issuer_parts.append(f"{key}={val}")

    return {
        "valid": valid,
        "issuer": ", ".join(issuer_parts),
        "expires": not_after_str,
        "days_remaining": days_remaining,
    }


# ── Main tool ────────────────────────────────────────────────────────────

@mcp.tool(description="Get comprehensive domain intelligence: WHOIS, DNS, and SSL status")
def get_domain_info(domain: str, port: int = DEFAULT_PORT) -> dict[str, Any]:
    """
    Retrieve combined domain intelligence including WHOIS registration,
    DNS records, and SSL certificate status.
    
    Args:
        domain: The domain name to investigate (e.g. example.com)
        port: TCP port for SSL check (default 443)
    
    Returns:
        Dict with whois, dns, and ssl keys containing detailed information
    """
    if not domain or not isinstance(domain, str):
        return _make_error("domain must be a non-empty string")

    result: dict[str, Any] = {"domain": domain}

    # DNS
    dns_data = _get_all_dns_records(domain)
    if dns_data:
        result["dns"] = dns_data

    # WHOIS
    whois_data = _get_whois(domain)
    if whois_data:
        result["whois"] = whois_data

    # SSL
    ssl_data = _get_ssl_status(domain, port)
    result["ssl"] = ssl_data

    # Summary
    summary = {
        "domain": domain,
        "dns_record_count": sum(len(v) for v in dns_data.values()) if dns_data else 0,
        "ssl_valid": ssl_data.get("valid", False),
        "whois_available": "error" not in whois_data if whois_data else False,
    }
    result["summary"] = summary

    return result


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
