# Domain Intelligence MCP

Domain intelligence for AI agents — WHOIS registration, DNS records, and SSL certificate data combined into a single lookup. Zero API keys required.

## What your agent can do

- Look up who owns any domain (WHOIS registrant, registrar, creation/expiry dates)
- Check DNS records (A, AAAA, MX, NS, CNAME, TXT)
- Inspect SSL certificates (issuer, expiry date, days remaining)
- Get a summary overview in the same response (record count, SSL validity, WHOIS availability)

## Tools

| Tool | Description |
|------|-------------|
| `get_domain_info` | WHOIS registration, all DNS record types, SSL certificate status, and a summary — all in one call |

## Installation

### Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "domain-data": {
      "command": "python",
      "args": ["/path/to/server.py"]
    }
  }
}
```

### Dependencies

```bash
pip install -r requirements.txt
python server.py
```

### Cursor / VS Code

Same config structure in your MCP settings JSON, pointing to `server.py`.

## Example

```
get_domain_info("example.com")
```

Returns an object with:
- `whois` — registrar, creation/expiry dates, name servers, status
- `dns` — all record types (A, AAAA, MX, NS, CNAME, TXT)
- `ssl` — issuer, expiry, days remaining, validity
- `summary` — quick overview with record count and SSL status

## Pricing

| Plan | Price | Features |
|------|-------|----------|
| **Free** | $0 | Basic domain lookups |
| **Pro** | $19/mo | Unlimited lookups, batch queries, historical data, priority support |

[Subscribe to Pro](https://buy.stripe.com/dRm6oJ4Hd2Jugek0wz1oI0m)

## Data Sources

- **DNS**: Google DNS-over-HTTPS API (dns.google)
- **WHOIS**: python-whois library
- **SSL**: Python's built-in ssl + socket modules

## Deployment with Smithery

The `smithery.yaml` file is included for deployment on [Smithery](https://smithery.ai).

## License

MIT © AgentPay Labs
