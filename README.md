# Security Intel MCP — by SelfLabbs

Vulnerability intelligence for AI agents — as MCP tools your agent can call mid-task. No API keys.

## Tools

| Tool | What it does | Source |
|---|---|---|
| `cve_lookup` | CVE summary: description, CVSS score & severity, CWE, references | NVD (NIST) |
| `package_vulnerabilities` | Known vulnerabilities for a package/version | OSV.dev |
| `audit_dependencies` | Audit a whole package.json (or dependency list) in one call | OSV.dev |

No API keys required for any tool.

## Quick start

```
claude mcp add --transport http security-intel https://security.selflabbs.com/mcp
```

Or point any MCP client at `https://security.selflabbs.com/mcp`.

## Data & attribution

Vulnerability data comes from the [National Vulnerability Database](https://nvd.nist.gov) (NIST — US public domain) and [OSV.dev](https://osv.dev) (CC-BY 4.0), the same open source used by scanners like Trivy and Grype.

Part of [SelfLabbs](https://selflabbs.com) — keyless intelligence APIs for AI agents.
