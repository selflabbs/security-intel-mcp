# Security Intel MCP — by SelfLabbs

Security intelligence for AI agents. Give your agent the ability to check CVEs, package vulnerabilities, malicious URLs, and IP reputation **before** it trusts a dependency, fetches a link, or approves a host.

Agents make security-relevant decisions constantly — installing packages, following URLs, evaluating logs. This server puts threat intel in the loop.

## Tools

| Tool | What it does | Source |
|---|---|---|
| `cve_lookup` | CVE summary: CVSS score, severity, CISA KEV (actively-exploited) status, fixes, references | NVD |
| `package_vulnerabilities` | Known vulns for any package/version across npm, PyPI, Go, Maven, crates.io, RubyGems + more | OSV.dev |
| `url_check` | Is this URL a known malware/phishing distribution site? | URLhaus (abuse.ch) |
| `ip_reputation` | Abuse confidence score, report history, ISP, Tor status for any IP | AbuseIPDB |

## Quick start (hosted — recommended)

No install. Add the remote server to your client:

**Claude Code**
```bash
claude mcp add --transport http security-intel https://mcp.selflabbs.com/mcp
```

**Claude Desktop / other clients (via mcp-remote)**
```json
{
  "mcpServers": {
    "security-intel": {
      "command": "npx",
      "args": ["mcp-remote", "https://mcp.selflabbs.com/mcp"]
    }
  }
}
```

**Cursor** — Settings → MCP → Add server → URL: `https://mcp.selflabbs.com/mcp`

## Self-host (Cloudflare Workers, free tier)

1. Create a Worker in the Cloudflare dashboard, paste `worker.js`
2. Settings → Variables, add:
   - `ABUSEIPDB_KEY` — free at [abuseipdb.com](https://www.abuseipdb.com/) (enables `ip_reputation`)
   - `URLHAUS_AUTH_KEY` — free at [auth.abuse.ch](https://auth.abuse.ch/) (enables `url_check`)
   - `SERVER_API_KEY` — optional; set to require `Authorization: Bearer <key>` from clients
3. Deploy. Your endpoint is `https://<worker>.<account>.workers.dev/mcp`

`cve_lookup` and `package_vulnerabilities` work with zero keys.

## Example agent workflows

- *"Before adding this npm package, check it for known vulnerabilities"* → `package_vulnerabilities`
- *"Is CVE-2024-3094 actively exploited? Do I need to act today?"* → `cve_lookup` (KEV status)
- *"Vet the IPs in this auth log"* → `ip_reputation`
- *"Check this download link before I fetch it"* → `url_check`

## Pricing

Hosted free tier: fair-use. Higher-volume plans: see [selflabbs.com](https://selflabbs.com).

## License

MIT (this repo). Data provided by NVD, OSV.dev, abuse.ch, and AbuseIPDB under their respective terms — check their policies for commercial/high-volume use.
