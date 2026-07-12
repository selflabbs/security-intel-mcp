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
| `audit_dependencies` | Paste a whole package.json / requirements.txt / go.mod and get one consolidated vulnerability report across every dependency | OSV.dev (batch) |

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

The hosted endpoint is **freemium**:

- **Free** — every tool works, results capped at 10 items per call. No key required.
- **Builder — $19/mo** — uncapped results, 5,000 tool calls/mo, priority endpoint.
- **Team — $49/mo** — uncapped results, 25,000 tool calls/mo, usage dashboard.

**[Subscribe →](https://buy.polar.sh/polar_cl_Q9y3qLrNbtsssN3w5m8SK56oNcruwrmxLEPnd34oAZf)** — one subscription unlocks Pro on every SelfLabbs server.

### Using your Pro key

After subscribing you receive a license key beginning with `SELFLABBS-`. Pass it as a Bearer token and the free-tier caps are removed:

```bash
claude mcp add --transport http --header "Authorization: Bearer SELFLABBS-XXXX-XXXX" security-intel https://security-intel-mcp.greenfield1775.workers.dev/mcp
```

The key is validated against Polar on each request (cached briefly). Cancel anytime — access reverts to the free tier automatically.

## License

MIT (this repo). Data provided by NVD, OSV.dev, abuse.ch, and AbuseIPDB under their respective terms — check their policies for commercial/high-volume use.
