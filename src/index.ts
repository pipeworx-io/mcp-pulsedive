interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, unknown>;
    required?: string[];
  };
}

interface McpToolExport {
  tools: McpToolDefinition[];
  callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>;
  meter?: { credits: number };
  cost?: Record<string, unknown>;
  provider?: string;
}

/**
 * Pulsedive MCP — threat-intelligence IOC enrichment (pulsedive.com)
 *
 * Tools:
 * - pulsedive_indicator: risk score + threats/feeds for an IP, domain, URL, or hash
 * - pulsedive_explore: search Pulsedive's threat DB with its query language
 *
 * Requires a Pulsedive API key via _apiKey (sent as the `key` query param).
 * Free tier: 50 lookups/day — https://pulsedive.com.
 */


const BASE_URL = 'https://pulsedive.com/api';

const tools: McpToolExport['tools'] = [
  {
    name: 'pulsedive_indicator',
    description:
      'Is this IP/domain/URL/hash malicious — risk score + threats. Looks up an indicator of compromise (IOC) in Pulsedive and returns its risk level, contributing risk factors, associated threats, and intel feeds. Example: pulsedive_indicator({ indicator: "8.8.8.8", _apiKey: "your-key" })',
    inputSchema: {
      type: 'object',
      properties: {
        indicator: {
          type: 'string',
          description: 'The IOC to look up — an IP, domain, URL, or file hash. e.g. "1.2.3.4", "example.com", "http://bad.tld/x"',
        },
        _apiKey: {
          type: 'string',
          description: 'Pulsedive API key (free tier 50/day at pulsedive.com)',
        },
      },
      required: ['indicator', '_apiKey'],
    },
  },
  {
    name: 'pulsedive_explore',
    description:
      'Search Pulsedive threat DB with a query. Uses the Pulsedive Explore query language (boolean field filters) to find indicators matching criteria like type, risk, feed, or threat. Example: pulsedive_explore({ q: "type=domain and risk=high", limit: 20, _apiKey: "your-key" })',
    inputSchema: {
      type: 'object',
      properties: {
        q: {
          type: 'string',
          description: 'Explore query, e.g. "type=domain and risk=high", "ioc=*.ru and threat=emotet"',
        },
        limit: {
          type: 'number',
          description: 'Max results to return (default 20, max 50)',
        },
        _apiKey: {
          type: 'string',
          description: 'Pulsedive API key',
        },
      },
      required: ['q', '_apiKey'],
    },
  },
];

async function callTool(name: string, args: Record<string, unknown>): Promise<unknown> {
  const apiKey = args._apiKey as string | undefined;
  delete args._apiKey;

  if (!apiKey) {
    throw new Error(
      'Pulsedive requires an API key. Pass your own via _apiKey — get one free (50 lookups/day) at https://pulsedive.com (Account → API).',
    );
  }

  switch (name) {
    case 'pulsedive_indicator':
      return indicatorLookup(args.indicator as string, apiKey);
    case 'pulsedive_explore':
      return explore(args.q as string, args.limit as number | undefined, apiKey);
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// Shared GET helper. Attaches the key, maps auth/rate-limit/HTTP failures to
// actionable errors, and surfaces Pulsedive's 200-body { error } responses
// (returned on malformed input) as thrown errors.
async function pdGet(
  path: string,
  params: Record<string, string>,
  apiKey: string,
  tool: string,
): Promise<Record<string, unknown>> {
  const qs = new URLSearchParams({ ...params, key: apiKey });
  const res = await fetch(`${BASE_URL}${path}?${qs}`);

  if (res.status === 401 || res.status === 403) {
    throw new Error(
      `Pulsedive ${tool}: authentication failed (HTTP ${res.status}). Check your Pulsedive _apiKey — get one free at https://pulsedive.com.`,
    );
  }
  if (res.status === 429) {
    throw new Error(
      `Pulsedive ${tool}: rate limited (HTTP 429). The free tier allows 50 lookups/day — wait or upgrade your Pulsedive plan.`,
    );
  }
  if (!res.ok) {
    throw new Error(`Pulsedive ${tool} error: HTTP ${res.status}`);
  }

  const data = (await res.json()) as Record<string, unknown>;

  // Pulsedive returns 200 with an { error } body on bad input (e.g. an
  // unknown indicator or an invalid Explore query). Surface it as an error.
  if (data && typeof data.error === 'string') {
    throw new Error(`Pulsedive ${tool}: ${data.error}`);
  }

  return data;
}

async function indicatorLookup(indicator: string, apiKey: string) {
  if (!indicator) {
    throw new Error(
      'Pulsedive pulsedive_indicator requires an `indicator` — an IP, domain, URL, or hash (e.g. "8.8.8.8").',
    );
  }

  const data = await pdGet('/info.php', { indicator }, apiKey, 'pulsedive_indicator');

  const riskFactors = Array.isArray(data.riskfactors)
    ? (data.riskfactors as Array<Record<string, unknown>>).map((r) => r.description)
    : [];

  const threats = Array.isArray(data.threats)
    ? (data.threats as Array<Record<string, unknown>>).map((t) => ({
        name: t.name,
        category: t.category,
      }))
    : [];

  const feeds = Array.isArray(data.feeds)
    ? (data.feeds as Array<Record<string, unknown>>).slice(0, 10).map((f) => ({
        name: f.name,
        category: f.category,
        organization: f.organization,
      }))
    : [];

  return {
    indicator: data.indicator,
    type: data.type,
    risk: data.risk,
    risk_factors: riskFactors,
    threats,
    feeds,
    properties: data.properties,
    stamp_seen: data.stamp_seen,
    stamp_updated: data.stamp_updated,
  };
}

async function explore(query: string, limit: number | undefined, apiKey: string) {
  if (!query) {
    throw new Error(
      'Pulsedive pulsedive_explore requires a `q` query, e.g. "type=domain and risk=high".',
    );
  }

  const capped = Math.min(limit ?? 20, 50);
  const data = await pdGet(
    '/explore.php',
    { q: query, limit: String(capped) },
    apiKey,
    'pulsedive_explore',
  );

  const results = Array.isArray(data.results)
    ? (data.results as Array<Record<string, unknown>>).map((r) => ({
        iid: r.iid,
        indicator: r.indicator,
        type: r.type,
        risk: r.risk,
        stamp_seen: r.stamp_seen,
      }))
    : [];

  return {
    query,
    count: results.length,
    results,
  };
}

export default { tools, callTool, meter: { credits: 1 } } satisfies McpToolExport;
