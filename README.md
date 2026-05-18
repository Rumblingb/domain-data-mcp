# Domain Data MCP Server

An MCP (Model Context Protocol) server for combined domain intelligence. Aggregates DNS records, WHOIS registration data, and SSL certificate status into a single query.

## Data Sources

- **DNS**: Google DNS-over-HTTPS API (dns.google)
- **WHOIS**: python-whois library
- **SSL**: Python's built-in ssl + socket modules

## Tools

### `get_domain_info(domain, port?)`
Retrieve comprehensive domain intelligence in one call.

- **domain** (string): The domain name to investigate (e.g., `example.com`)
- **port** (integer, optional): TCP port for SSL check (default: 443)

Returns an object with:
- **whois**: Registrar, creation/expiry dates, name servers, domain status
- **dns**: All DNS record types (A, AAAA, MX, NS, CNAME, TXT)
- **ssl**: Certificate validity, issuer, expiry, days remaining
- **summary**: Quick overview with record count, SSL validity, WHOIS availability

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python server.py
```

## Deployment with Smithery

The `smithery.yaml` file is included for deployment on [Smithery](https://smithery.ai). Configure the start command to point to this directory.

## Pricing

| Plan | Price | Features |
|------|-------|----------|
| **Free** | $0 | Basic domain lookups |
| **Pro** | $19/mo | Unlimited lookups, batch queries, historical data, priority support |

[Subscribe to Pro](https://buy.stripe.com/dRm6oJ4Hd2Jugek0wz1oI0m)

## License

MIT
