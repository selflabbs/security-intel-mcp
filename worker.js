/**
 * SelfLabbs Security Intel MCP Server
 * Remote MCP server (Streamable HTTP, stateless) for Cloudflare Workers.
 * Zero dependencies — paste directly into the Cloudflare dashboard editor.
 *
 * Tools:
 *   cve_lookup             — CVE details from NVD (severity, CVSS, KEV status, fixes)
 *   package_vulnerabilities — known vulns for a package/version via OSV.dev
 *   url_check              — malicious URL check via URLhaus (needs URLHAUS_AUTH_KEY)
 *   ip_reputation          — IP abuse score via AbuseIPDB (needs ABUSEIPDB_KEY)
 *
 * Env vars (Worker Settings → Variables):
 *   ABUSEIPDB_KEY      — required for ip_reputation
 *   URLHAUS_AUTH_KEY   — required for url_check (free at auth.abuse.ch)
 *   SERVER_API_KEY     — optional; if set, requests must send
 *                        Authorization: Bearer <key>  (paid-tier gate)
 */

const SERVER_INFO = { name: "selflabbs-security-intel", version: "1.0.0" };
const PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"];

// ---------------------------------------------------------------- tools spec

const TOOLS = [
  {
    name: "cve_lookup",
    description:
      "Look up a CVE by ID. Returns a compact summary: description, CVSS score/severity, CISA KEV (known-exploited) status, affected products, dates, and top references. Use before approving dependencies, evaluating alerts, or assessing exposure.",
    inputSchema: {
      type: "object",
      properties: {
        cve_id: {
          type: "string",
          description: "CVE identifier, e.g. CVE-2021-44228",
          pattern: "^CVE-\\d{4}-\\d{4,}$",
        },
      },
      required: ["cve_id"],
    },
  },
  {
    name: "package_vulnerabilities",
    description:
      "List known vulnerabilities for a software package (optionally a specific version) using OSV.dev. Covers npm, PyPI, Go, Maven, crates.io, RubyGems, Packagist, NuGet and more. Returns vuln IDs, severity, summary, and fixed versions.",
    inputSchema: {
      type: "object",
      properties: {
        ecosystem: {
          type: "string",
          description:
            "Package ecosystem: npm, PyPI, Go, Maven, crates.io, RubyGems, Packagist, NuGet, Hex, Pub, SwiftURL, Debian, Alpine",
        },
        name: { type: "string", description: "Package name, e.g. lodash or org.apache.logging.log4j:log4j-core" },
        version: { type: "string", description: "Exact version to check (optional; omit to list all known vulns)" },
      },
      required: ["ecosystem", "name"],
    },
  },
  {
    name: "url_check",
    description:
      "Check whether a URL is a known malware/phishing distribution site via abuse.ch URLhaus. Returns threat status, malware family tags, and takedown state. Use before fetching or recommending unfamiliar URLs.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "Full URL to check, including scheme" },
      },
      required: ["url"],
    },
  },
  {
    name: "ip_reputation",
    description:
      "Get abuse reputation for an IPv4/IPv6 address via AbuseIPDB: abuse confidence score (0-100), report count, ISP, usage type, country. Use to vet inbound connections, log entries, or suspicious hosts.",
    inputSchema: {
      type: "object",
      properties: {
        ip: { type: "string", description: "IPv4 or IPv6 address" },
      },
      required: ["ip"],
    },
  },
];

// ---------------------------------------------------------------- tool impls

async function cveLookup(args) {
  const id = String(args.cve_id || "").trim().toUpperCase();
  if (!/^CVE-\d{4}-\d{4,}$/.test(id)) throw new UserError("Invalid CVE ID format. Expected e.g. CVE-2021-44228");

  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(id)}`;
  const res = await cachedFetch(url, { headers: { "User-Agent": "selflabbs-security-intel-mcp" } }, 3600);
  if (!res.ok) throw new UserError(`NVD API error (HTTP ${res.status}). NVD rate-limits aggressively; retry in ~30s.`);
  const data = await res.json();
  const v = data.vulnerabilities?.[0]?.cve;
  if (!v) return { found: false, cve_id: id, note: "Not found in NVD. It may be reserved, rejected, or too new." };

  const metrics =
    v.metrics?.cvssMetricV31?.[0]?.cvssData ||
    v.metrics?.cvssMetricV40?.[0]?.cvssData ||
    v.metrics?.cvssMetricV30?.[0]?.cvssData ||
    v.metrics?.cvssMetricV2?.[0]?.cvssData;

  return {
    found: true,
    cve_id: v.id,
    status: v.vulnStatus,
    description: v.descriptions?.find((d) => d.lang === "en")?.value,
    severity:
      v.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity ||
      v.metrics?.cvssMetricV40?.[0]?.cvssData?.baseSeverity ||
      v.metrics?.cvssMetricV30?.[0]?.cvssData?.baseSeverity ||
      null,
    cvss_score: metrics?.baseScore ?? null,
    cvss_vector: metrics?.vectorString ?? null,
    known_exploited: Boolean(v.cisaExploitAdd),
    cisa_kev: v.cisaExploitAdd
      ? { added: v.cisaExploitAdd, action_due: v.cisaActionDue, required_action: v.cisaRequiredAction }
      : null,
    weaknesses: (v.weaknesses || [])
      .flatMap((w) => w.description || [])
      .filter((d) => d.lang === "en")
      .map((d) => d.value)
      .slice(0, 5),
    published: v.published,
    last_modified: v.lastModified,
    references: (v.references || []).slice(0, 5).map((r) => r.url),
  };
}

async function packageVulnerabilities(args) {
  const ecosystem = String(args.ecosystem || "").trim();
  const name = String(args.name || "").trim();
  if (!ecosystem || !name) throw new UserError("ecosystem and name are required");

  const query = { package: { name, ecosystem } };
  if (args.version) query.version = String(args.version).trim();

  const res = await fetch("https://api.osv.dev/v1/query", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(query),
  });
  if (!res.ok) throw new UserError(`OSV API error (HTTP ${res.status}). Check the ecosystem name (case-sensitive, e.g. "PyPI", "npm").`);
  const data = await res.json();
  const vulns = data.vulns || [];

  return {
    package: name,
    ecosystem,
    version: args.version || "(all versions)",
    vulnerability_count: vulns.length,
    vulnerabilities: vulns.slice(0, 25).map((v) => ({
      id: v.id,
      aliases: (v.aliases || []).slice(0, 4),
      severity: v.database_specific?.severity || cvssFromOsv(v) || "UNKNOWN",
      summary: v.summary || (v.details ? v.details.slice(0, 200) : null),
      fixed_versions: extractFixedVersions(v, name),
      published: v.published,
    })),
    truncated: vulns.length > 25,
  };
}

function cvssFromOsv(v) {
  const s = (v.severity || []).find((x) => x.type?.startsWith("CVSS"));
  return s ? s.score : null;
}

function extractFixedVersions(v, name) {
  const fixed = new Set();
  for (const a of v.affected || []) {
    if (a.package?.name !== name) continue;
    for (const r of a.ranges || [])
      for (const e of r.events || []) if (e.fixed) fixed.add(e.fixed);
  }
  return [...fixed].slice(0, 10);
}

async function urlCheck(args, env) {
  const target = String(args.url || "").trim();
  if (!/^https?:\/\//i.test(target)) throw new UserError("Provide a full URL including http:// or https://");
  if (!env.URLHAUS_AUTH_KEY)
    throw new UserError("url_check is not configured on this server (missing URLhaus auth key). Other tools remain available.");

  const body = new URLSearchParams({ url: target });
  const res = await fetch("https://urlhaus-api.abuse.ch/v1/url/", {
    method: "POST",
    headers: { "Auth-Key": env.URLHAUS_AUTH_KEY },
    body,
  });
  if (!res.ok) throw new UserError(`URLhaus API error (HTTP ${res.status})`);
  const data = await res.json();

  if (data.query_status === "no_results")
    return {
      url: target,
      listed: false,
      verdict: "not_listed",
      note: "Not in URLhaus. Absence of listing is NOT proof of safety — treat unfamiliar URLs with caution.",
    };
  if (data.query_status !== "ok") return { url: target, verdict: "error", detail: data.query_status };

  return {
    url: target,
    listed: true,
    verdict: "listed_malicious",
    threat: data.threat,
    status: data.url_status,
    tags: data.tags || [],
    first_seen: data.date_added,
    payload_count: Array.isArray(data.payloads) ? data.payloads.length : 0,
    reference: data.urlhaus_reference,
  };
}

async function ipReputation(args, env) {
  const ip = String(args.ip || "").trim();
  if (!ip) throw new UserError("ip is required");
  if (!env.ABUSEIPDB_KEY)
    throw new UserError("ip_reputation is not configured on this server (missing AbuseIPDB key). Other tools remain available.");

  const res = await fetch(
    `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
    { headers: { Key: env.ABUSEIPDB_KEY, Accept: "application/json" } }
  );
  if (res.status === 429) throw new UserError("AbuseIPDB daily quota reached. Try again tomorrow or upgrade the key.");
  if (!res.ok) throw new UserError(`AbuseIPDB API error (HTTP ${res.status})`);
  const { data } = await res.json();

  return {
    ip: data.ipAddress,
    abuse_confidence_score: data.abuseConfidenceScore,
    verdict:
      data.abuseConfidenceScore >= 75 ? "high_risk" : data.abuseConfidenceScore >= 25 ? "suspicious" : "low_risk",
    total_reports_90d: data.totalReports,
    last_reported: data.lastReportedAt,
    isp: data.isp,
    usage_type: data.usageType,
    country: data.countryCode,
    domain: data.domain,
    is_tor: data.isTor,
    is_whitelisted: data.isWhitelisted,
  };
}

const TOOL_IMPLS = {
  cve_lookup: cveLookup,
  package_vulnerabilities: packageVulnerabilities,
  url_check: urlCheck,
  ip_reputation: ipReputation,
};

// ---------------------------------------------------------------- MCP plumbing

class UserError extends Error {}

async function cachedFetch(url, init, ttlSeconds) {
  const cache = caches.default;
  const key = new Request(url, { method: "GET" });
  let res = await cache.match(key);
  if (res) return res;
  res = await fetch(url, init);
  if (res.ok) {
    const toCache = new Response(res.clone().body, res);
    toCache.headers.set("Cache-Control", `s-maxage=${ttlSeconds}`);
    await cache.put(key, toCache);
  }
  return res;
}

function rpcResult(id, result) {
  return { jsonrpc: "2.0", id, result };
}
function rpcError(id, code, message) {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

async function handleRpc(msg, env) {
  const { id, method, params } = msg;

  // Notifications: no response
  if (id === undefined || id === null) return null;

  switch (method) {
    case "initialize": {
      const requested = params?.protocolVersion;
      return rpcResult(id, {
        protocolVersion: PROTOCOL_VERSIONS.includes(requested) ? requested : PROTOCOL_VERSIONS[0],
        capabilities: { tools: {} },
        serverInfo: SERVER_INFO,
        instructions:
          "Security intelligence tools for AI agents: CVE lookups (NVD), package vulnerability checks (OSV.dev), malicious URL checks (URLhaus), and IP reputation (AbuseIPDB). Call these before trusting dependencies, URLs, or hosts.",
      });
    }
    case "ping":
      return rpcResult(id, {});
    case "tools/list":
      return rpcResult(id, { tools: TOOLS });
    case "tools/call": {
      const name = params?.name;
      const impl = TOOL_IMPLS[name];
      if (!impl) return rpcError(id, -32602, `Unknown tool: ${name}`);
      try {
        const out = await impl(params?.arguments || {}, env);
        return rpcResult(id, { content: [{ type: "text", text: JSON.stringify(out, null, 2) }] });
      } catch (e) {
        const message = e instanceof UserError ? e.message : `Internal error: ${e.message}`;
        return rpcResult(id, { content: [{ type: "text", text: message }], isError: true });
      }
    }
    case "resources/list":
      return rpcResult(id, { resources: [] });
    case "prompts/list":
      return rpcResult(id, { prompts: [] });
    default:
      return rpcError(id, -32601, `Method not found: ${method}`);
  }
}

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, Mcp-Session-Id, MCP-Protocol-Version",
  "Access-Control-Expose-Headers": "Mcp-Session-Id",
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });

    // Health + human-facing root
    if (url.pathname === "/" && request.method === "GET") {
      return new Response(
        JSON.stringify({
          service: SERVER_INFO.name,
          version: SERVER_INFO.version,
          mcp_endpoint: "/mcp",
          docs: "https://selflabbs.com",
          tools: TOOLS.map((t) => t.name),
        }, null, 2),
        { headers: { "Content-Type": "application/json", ...CORS } }
      );
    }

    if (url.pathname !== "/mcp") return new Response("Not found", { status: 404, headers: CORS });

    // Optional paid-tier gate
    if (env.SERVER_API_KEY) {
      const auth = request.headers.get("Authorization") || "";
      if (auth !== `Bearer ${env.SERVER_API_KEY}`)
        return new Response(JSON.stringify(rpcError(null, -32000, "Unauthorized: missing or invalid API key")), {
          status: 401,
          headers: { "Content-Type": "application/json", ...CORS },
        });
    }

    if (request.method === "GET")
      // Stateless server: no server-initiated stream
      return new Response(null, { status: 405, headers: { Allow: "POST", ...CORS } });

    if (request.method === "DELETE") return new Response(null, { status: 200, headers: CORS });

    if (request.method !== "POST")
      return new Response(null, { status: 405, headers: { Allow: "POST", ...CORS } });

    let body;
    try {
      body = await request.json();
    } catch {
      return new Response(JSON.stringify(rpcError(null, -32700, "Parse error")), {
        status: 400,
        headers: { "Content-Type": "application/json", ...CORS },
      });
    }

    const messages = Array.isArray(body) ? body : [body];
    const responses = (await Promise.all(messages.map((m) => handleRpc(m, env)))).filter(Boolean);

    if (responses.length === 0) return new Response(null, { status: 202, headers: CORS });

    const payload = Array.isArray(body) ? responses : responses[0];
    return new Response(JSON.stringify(payload), {
      headers: { "Content-Type": "application/json", ...CORS },
    });
  },
};
