import crypto from "node:crypto";
import http from "node:http";
import { URL } from "node:url";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

const PORT = Number(process.env.PORT ?? 3000);
const BASE_URL = process.env.PUBLIC_BASE_URL ?? `http://localhost:${PORT}`;

const SEEDED = {
  businessUnits: {
    PI: {
      name: "Personal Investing",
      aumUsdBn: 128.4,
      netFlowsUsdMnQtd: 965,
      activeClients: 51420,
      nps: 56
    },
    WI: {
      name: "Workplace Investing",
      aumUsdBn: 292.7,
      netFlowsUsdMnQtd: 1835,
      activeClients: 20750,
      nps: 61
    }
  },
  accounts: [
    {
      accountId: "PI-1001",
      business: "PI",
      client: "Aarav Singh",
      riskProfile: "Moderate",
      modelPortfolio: "Balanced Growth",
      marketValueUsd: 842000,
      driftPct: 2.4,
      cashPct: 7.2
    },
    {
      accountId: "PI-1002",
      business: "PI",
      client: "Noah Williams",
      riskProfile: "Aggressive",
      modelPortfolio: "US Equity Focus",
      marketValueUsd: 1255000,
      driftPct: 4.8,
      cashPct: 3.1
    },
    {
      accountId: "WI-2001",
      business: "WI",
      client: "Acme Corp 401(k) - Segment A",
      riskProfile: "Moderate",
      modelPortfolio: "Global Multi-Asset",
      marketValueUsd: 24300000,
      driftPct: 1.1,
      cashPct: 2.6
    },
    {
      accountId: "WI-2002",
      business: "WI",
      client: "Orion Tech Pension Sleeve",
      riskProfile: "Conservative",
      modelPortfolio: "Income Stabilizer",
      marketValueUsd: 12100000,
      driftPct: 3.3,
      cashPct: 6.7
    }
  ],
  policyNotes: [
    {
      id: "POL-AL-01",
      title: "Model Portfolio Drift Tolerance",
      tags: ["rebalance", "drift", "investment-policy"],
      summary:
        "Accounts with drift > 3.0% require advisory review; >5.0% requires same-day remediation plan."
    },
    {
      id: "POL-RSK-11",
      title: "Suitability Refresh - Annual",
      tags: ["risk", "suitability", "compliance"],
      summary:
        "Risk profile and suitability must be revalidated at least annually or after major life events."
    },
    {
      id: "POL-CASH-04",
      title: "Strategic Cash Bands",
      tags: ["cash", "allocation", "portfolio"],
      summary:
        "Target cash range is 2%-5%; above 8% should trigger allocation recommendation."
    }
  ]
};

const DEMO_USERS = {
  analyst: {
    sub: "user-analyst",
    name: "Analyst User",
    scopes: ["accounts:read", "rebalance:read"]
  },
  advisor: {
    sub: "user-advisor",
    name: "Advisor User",
    scopes: ["accounts:read", "rebalance:read", "trades:write"]
  }
};

const AUTH_CODES = new Map();
const ACCESS_TOKENS = new Map();

function randomString(size = 32) {
  return crypto.randomBytes(size).toString("base64url");
}

function sha256base64url(input) {
  return crypto.createHash("sha256").update(input).digest("base64url");
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      try {
        const raw = Buffer.concat(chunks).toString("utf8");
        const contentType = (req.headers["content-type"] ?? "").split(";")[0].trim();
        if (!raw) {
          resolve({});
          return;
        }
        if (contentType === "application/json") {
          resolve(JSON.parse(raw));
          return;
        }
        if (contentType === "application/x-www-form-urlencoded") {
          resolve(Object.fromEntries(new URLSearchParams(raw)));
          return;
        }
        resolve({ raw });
      } catch (err) {
        reject(err);
      }
    });
    req.on("error", reject);
  });
}

function sendJson(res, status, payload, extraHeaders = {}) {
  res.writeHead(status, {
    "content-type": "application/json",
    ...extraHeaders
  });
  res.end(JSON.stringify(payload));
}

function htmlPage(title, body) {
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${title}</title>
  <style>
    body { font-family: ui-sans-serif, -apple-system, Segoe UI, Roboto, Arial, sans-serif; background:#f4f7fb; margin:0; }
    .shell { max-width: 680px; margin: 40px auto; background: white; border: 1px solid #dbe3ee; border-radius: 12px; padding: 24px; }
    h1 { margin-top: 0; font-size: 20px; }
    p { color: #334155; }
    .users { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin: 14px 0; }
    label { border: 1px solid #dbe3ee; border-radius: 8px; padding: 10px; cursor: pointer; }
    button { border: 0; border-radius: 8px; background: #0f766e; color: white; padding: 10px 14px; font-weight: 600; }
    .muted { font-size: 13px; color: #64748b; }
    code { background: #f1f5f9; padding: 2px 6px; border-radius: 6px; }
  </style>
</head>
<body>
  <div class="shell">${body}</div>
</body>
</html>`;
}

function getTokenFromAuthHeader(authHeader) {
  if (!authHeader?.startsWith("Bearer ")) return null;
  return authHeader.slice("Bearer ".length).trim();
}

function getAuthContext(req) {
  const token = getTokenFromAuthHeader(req.headers.authorization);
  if (!token) return { authenticated: false, scopes: [], user: null };
  const session = ACCESS_TOKENS.get(token);
  if (!session || session.expiresAt < Date.now()) {
    return { authenticated: false, scopes: [], user: null };
  }
  return {
    authenticated: true,
    scopes: session.scopes,
    user: session.user
  };
}

function unauthorizedMcp(requiredScopes = ["accounts:read"]) {
  const scopeText = requiredScopes.join(" ");
  const resourceMetadataUrl = `${BASE_URL}/.well-known/oauth-protected-resource`;
  return {
    content: [{ type: "text", text: "Authentication required." }],
    _meta: {
      "mcp/www_authenticate": `Bearer resource_metadata=\"${resourceMetadataUrl}\", scope=\"${scopeText}\"`
    }
  };
}

function hasScopes(auth, requiredScopes) {
  return requiredScopes.every((scope) => auth.scopes.includes(scope));
}

function createFinanceServer(auth) {
  const server = new McpServer({
    name: "Fidelity-Style Finance Ops App",
    version: "1.0.0"
  });

  server.registerResource(
    "finance-dashboard",
    "ui://widgets/finance-dashboard.html",
    {
      title: "Finance Dashboard",
      description: "Seeded PI/WI dashboard widget",
      mimeType: "text/html+skybridge",
      _meta: {
        "openai/widgetDescription": "Displays a finance operations snapshot for PI and WI.",
        "openai/widgetPrefersBorder": true,
        "openai/widgetCSP": {
          connect_domains: [],
          resource_domains: []
        }
      }
    },
    async () => ({
      contents: [
        {
          uri: "ui://widgets/finance-dashboard.html",
          mimeType: "text/html+skybridge",
          text: `
<div style="font-family: ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif; padding: 16px; color:#0f172a;">
  <h2 style="margin:0 0 12px; font-size:18px;">Finance Ops Snapshot</h2>
  <p style="margin:0 0 12px; color:#334155;">PI and WI seeded overview with account health and rebalance pressure.</p>
  <div id="metrics" style="display:grid; grid-template-columns: repeat(2, minmax(120px, 1fr)); gap:10px;"></div>
</div>
<script>
(function () {
  const payload = window.openai?.toolOutput ?? {};
  const metrics = document.getElementById('metrics');
  const pairs = [
    ['PI AUM (bn)', payload.piAumBn],
    ['WI AUM (bn)', payload.wiAumBn],
    ['Accounts >3% drift', payload.driftAccounts],
    ['Net flows QTD (mn)', payload.netFlowsQtdMn]
  ];
  metrics.innerHTML = pairs.map(([k,v]) => '<div style="border:1px solid #dbe3ee;border-radius:10px;padding:10px;background:#f8fafc"><div style="font-size:12px;color:#64748b">'+k+'</div><div style="font-size:18px;font-weight:700">'+(v ?? 'n/a')+'</div></div>').join('');
})();
</script>`
        }
      ]
    })
  );

  server.registerTool(
    "get_business_snapshot",
    {
      title: "Business Snapshot",
      description: "Returns PI and WI business KPIs and rebalance pressure summary.",
      inputSchema: {},
      _meta: {
        "openai/outputTemplate": "ui://widgets/finance-dashboard.html"
      }
    },
    async () => {
      const pi = SEEDED.businessUnits.PI;
      const wi = SEEDED.businessUnits.WI;
      const driftAccounts = SEEDED.accounts.filter((a) => a.driftPct > 3).length;
      const netFlowsQtdMn = pi.netFlowsUsdMnQtd + wi.netFlowsUsdMnQtd;
      const structured = {
        piAumBn: pi.aumUsdBn,
        wiAumBn: wi.aumUsdBn,
        driftAccounts,
        netFlowsQtdMn
      };
      return {
        content: [
          {
            type: "text",
            text: `PI AUM: $${pi.aumUsdBn}bn, WI AUM: $${wi.aumUsdBn}bn, accounts with drift >3%: ${driftAccounts}.`
          }
        ],
        structuredContent: structured,
        _meta: {
          "openai/outputTemplate": "ui://widgets/finance-dashboard.html"
        }
      };
    }
  );

  server.registerTool(
    "search_internal_policies",
    {
      title: "Search Internal Policies",
      description: "Searches seeded policy guidance for compliance and portfolio operations.",
      inputSchema: {
        query: z.string().min(2).describe("keyword or phrase")
      }
    },
    async ({ query }) => {
      const q = query.toLowerCase();
      const matches = SEEDED.policyNotes.filter(
        (p) =>
          p.title.toLowerCase().includes(q) ||
          p.summary.toLowerCase().includes(q) ||
          p.tags.some((t) => t.includes(q))
      );
      return {
        content: [
          {
            type: "text",
            text: matches.length
              ? `Found ${matches.length} matching policy item(s).`
              : "No policy notes matched the query."
          }
        ],
        structuredContent: { query, results: matches }
      };
    }
  );

  server.registerTool(
    "list_client_accounts",
    {
      title: "List Client Accounts",
      description: "Returns seeded PI/WI accounts. Requires authenticated access.",
      inputSchema: {
        business: z.enum(["PI", "WI"]).optional(),
        minDriftPct: z.number().min(0).max(100).optional()
      },
      securitySchemes: [{ type: "oauth2", scopes: ["accounts:read"] }],
      _meta: {
        securitySchemes: [{ type: "oauth2", scopes: ["accounts:read"] }]
      }
    },
    async ({ business, minDriftPct = 0 }) => {
      if (!auth.authenticated || !hasScopes(auth, ["accounts:read"])) {
        return unauthorizedMcp(["accounts:read"]);
      }

      const rows = SEEDED.accounts.filter((a) => {
        const businessOk = business ? a.business === business : true;
        return businessOk && a.driftPct >= minDriftPct;
      });

      return {
        content: [{ type: "text", text: `Returned ${rows.length} account(s).` }],
        structuredContent: {
          requestedBy: auth.user?.name,
          accounts: rows
        }
      };
    }
  );

  server.registerTool(
    "get_rebalance_plan",
    {
      title: "Get Rebalance Plan",
      description: "Creates a simple recommended action plan for an account based on drift and cash.",
      inputSchema: {
        accountId: z.string().min(3)
      },
      securitySchemes: [{ type: "oauth2", scopes: ["rebalance:read"] }],
      _meta: {
        securitySchemes: [{ type: "oauth2", scopes: ["rebalance:read"] }]
      }
    },
    async ({ accountId }) => {
      if (!auth.authenticated || !hasScopes(auth, ["rebalance:read"])) {
        return unauthorizedMcp(["rebalance:read"]);
      }

      const account = SEEDED.accounts.find((a) => a.accountId === accountId);
      if (!account) {
        return {
          content: [{ type: "text", text: `Account ${accountId} not found.` }],
          structuredContent: { found: false }
        };
      }

      const actions = [];
      if (account.driftPct > 5) {
        actions.push("Escalate to same-day remediation per drift policy.");
      } else if (account.driftPct > 3) {
        actions.push("Queue advisor review within 24 hours.");
      } else {
        actions.push("Within tolerance; monitor at next rebalance cycle.");
      }

      if (account.cashPct > 8) {
        actions.push("Propose redeployment from excess cash into model underweights.");
      } else if (account.cashPct < 2) {
        actions.push("Increase liquidity sleeve to maintain operational flexibility.");
      }

      return {
        content: [{ type: "text", text: `Rebalance plan generated for ${account.accountId}.` }],
        structuredContent: {
          account,
          recommendedActions: actions,
          generatedAt: new Date().toISOString()
        }
      };
    }
  );

  server.registerTool(
    "create_trade_ticket",
    {
      title: "Create Trade Ticket",
      description: "Creates a mock trade ticket for operational workflow demos.",
      inputSchema: {
        accountId: z.string(),
        instruction: z.string().min(8)
      },
      securitySchemes: [{ type: "oauth2", scopes: ["trades:write"] }],
      _meta: {
        securitySchemes: [{ type: "oauth2", scopes: ["trades:write"] }]
      }
    },
    async ({ accountId, instruction }) => {
      if (!auth.authenticated || !hasScopes(auth, ["trades:write"])) {
        return unauthorizedMcp(["trades:write"]);
      }

      const account = SEEDED.accounts.find((a) => a.accountId === accountId);
      if (!account) {
        return {
          content: [{ type: "text", text: `Account ${accountId} not found.` }],
          structuredContent: { created: false }
        };
      }

      const ticketId = `TKT-${Math.floor(Math.random() * 900000 + 100000)}`;
      return {
        content: [{ type: "text", text: `Trade ticket ${ticketId} created.` }],
        structuredContent: {
          created: true,
          ticketId,
          accountId,
          instruction,
          createdBy: auth.user?.name,
          status: "Pending Compliance Review",
          createdAt: new Date().toISOString()
        }
      };
    }
  );

  return server;
}

function handleAuthorizeGet(req, res, url) {
  const clientId = url.searchParams.get("client_id") ?? "unknown-client";
  const redirectUri = url.searchParams.get("redirect_uri") ?? "";
  const state = url.searchParams.get("state") ?? "";
  const scope = url.searchParams.get("scope") ?? "accounts:read";
  const codeChallenge = url.searchParams.get("code_challenge") ?? "";
  const codeChallengeMethod = url.searchParams.get("code_challenge_method") ?? "S256";

  if (!redirectUri || !codeChallenge) {
    sendJson(res, 400, {
      error: "invalid_request",
      error_description: "redirect_uri and code_challenge are required"
    });
    return;
  }

  const html = htmlPage(
    "Demo Finance Auth",
    `
<h1>Sign in to Finance Ops Demo</h1>
<p>Client: <code>${clientId}</code></p>
<p>Requested scope: <code>${scope}</code></p>
<form method="post" action="/oauth/authorize">
  <input type="hidden" name="client_id" value="${clientId}" />
  <input type="hidden" name="redirect_uri" value="${redirectUri}" />
  <input type="hidden" name="state" value="${state}" />
  <input type="hidden" name="scope" value="${scope}" />
  <input type="hidden" name="code_challenge" value="${codeChallenge}" />
  <input type="hidden" name="code_challenge_method" value="${codeChallengeMethod}" />
  <div class="users">
    <label><input type="radio" name="user" value="analyst" checked /> Analyst (read accounts + rebalance)</label>
    <label><input type="radio" name="user" value="advisor" /> Advisor (includes trade write)</label>
  </div>
  <button type="submit">Authorize</button>
</form>
<p class="muted">This is a demo auth screen for local/testing use.</p>`
  );

  res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
  res.end(html);
}

async function handleAuthorizePost(req, res) {
  const body = await parseBody(req);
  const {
    client_id: clientId,
    redirect_uri: redirectUri,
    state,
    scope = "accounts:read",
    code_challenge: codeChallenge,
    code_challenge_method: codeChallengeMethod = "S256",
    user = "analyst"
  } = body;

  if (!clientId || !redirectUri || !codeChallenge) {
    sendJson(res, 400, { error: "invalid_request" });
    return;
  }

  const demoUser = DEMO_USERS[user] ?? DEMO_USERS.analyst;
  const allowedScopes = scope
    .split(/\s+/)
    .filter(Boolean)
    .filter((s) => demoUser.scopes.includes(s));

  const code = randomString(24);
  AUTH_CODES.set(code, {
    clientId,
    redirectUri,
    codeChallenge,
    codeChallengeMethod,
    scopes: allowedScopes,
    user: demoUser,
    expiresAt: Date.now() + 5 * 60 * 1000
  });

  const redirect = new URL(redirectUri);
  redirect.searchParams.set("code", code);
  if (state) redirect.searchParams.set("state", state);

  res.writeHead(302, { location: redirect.toString() });
  res.end();
}

async function handleToken(req, res) {
  const body = await parseBody(req);
  const {
    grant_type: grantType,
    code,
    client_id: clientId,
    redirect_uri: redirectUri,
    code_verifier: codeVerifier
  } = body;

  if (grantType !== "authorization_code") {
    sendJson(res, 400, { error: "unsupported_grant_type" });
    return;
  }

  const authCode = AUTH_CODES.get(code);
  if (!authCode || authCode.expiresAt < Date.now()) {
    sendJson(res, 400, { error: "invalid_grant" });
    return;
  }

  if (authCode.clientId !== clientId || authCode.redirectUri !== redirectUri) {
    sendJson(res, 400, { error: "invalid_grant" });
    return;
  }

  if (authCode.codeChallengeMethod === "S256") {
    const hash = sha256base64url(codeVerifier ?? "");
    if (hash !== authCode.codeChallenge) {
      sendJson(res, 400, { error: "invalid_grant" });
      return;
    }
  }

  AUTH_CODES.delete(code);

  const token = randomString(32);
  ACCESS_TOKENS.set(token, {
    user: authCode.user,
    scopes: authCode.scopes,
    expiresAt: Date.now() + 60 * 60 * 1000
  });

  sendJson(res, 200, {
    access_token: token,
    token_type: "Bearer",
    expires_in: 3600,
    scope: authCode.scopes.join(" ")
  });
}

function handleProtectedResourceMetadata(res) {
  sendJson(res, 200, {
    resource: `${BASE_URL}/mcp`,
    authorization_servers: [`${BASE_URL}`],
    bearer_methods_supported: ["header"],
    scopes_supported: ["accounts:read", "rebalance:read", "trades:write"]
  });
}

function handleAuthorizationServerMetadata(res) {
  sendJson(res, 200, {
    issuer: BASE_URL,
    authorization_endpoint: `${BASE_URL}/oauth/authorize`,
    token_endpoint: `${BASE_URL}/oauth/token`,
    registration_endpoint: `${BASE_URL}/oauth/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_post"],
    scopes_supported: ["accounts:read", "rebalance:read", "trades:write"]
  });
}

async function handleRegister(req, res) {
  const body = await parseBody(req);
  const clientName = body.client_name ?? "chatgpt-app";
  const redirectUris = body.redirect_uris ?? [];
  sendJson(res, 201, {
    client_id: `client-${randomString(8)}`,
    client_name: clientName,
    redirect_uris: redirectUris,
    token_endpoint_auth_method: "none"
  });
}

const transports = new Map();

const app = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? "/", BASE_URL);

    if (req.method === "GET" && url.pathname === "/health") {
      sendJson(res, 200, { ok: true, service: "finance-mcp", now: new Date().toISOString() });
      return;
    }

    if (req.method === "GET" && url.pathname === "/.well-known/oauth-protected-resource") {
      handleProtectedResourceMetadata(res);
      return;
    }

    if (req.method === "GET" && url.pathname === "/.well-known/oauth-authorization-server") {
      handleAuthorizationServerMetadata(res);
      return;
    }

    if (req.method === "POST" && url.pathname === "/oauth/register") {
      await handleRegister(req, res);
      return;
    }

    if (req.method === "GET" && url.pathname === "/oauth/authorize") {
      handleAuthorizeGet(req, res, url);
      return;
    }

    if (req.method === "POST" && url.pathname === "/oauth/authorize") {
      await handleAuthorizePost(req, res);
      return;
    }

    if (req.method === "POST" && url.pathname === "/oauth/token") {
      await handleToken(req, res);
      return;
    }

    if (url.pathname === "/mcp") {
      const sessionId = req.headers["mcp-session-id"];
      let transport;

      if (sessionId && transports.has(sessionId)) {
        transport = transports.get(sessionId);
      } else if (!sessionId && req.method === "POST") {
        const auth = getAuthContext(req);
        const server = createFinanceServer(auth);
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomString(12),
          onsessioninitialized: (id) => {
            transports.set(id, transport);
          }
        });

        transport.onclose = () => {
          if (transport.sessionId) transports.delete(transport.sessionId);
          server.close().catch(() => {});
        };

        await server.connect(transport);
      } else {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "Bad Request: invalid session handling." }));
        return;
      }

      await transport.handleRequest(req, res, await parseBody(req));
      return;
    }

    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "Not Found" }));
  } catch (err) {
    console.error(err);
    res.writeHead(500, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "Internal Server Error", message: err?.message }));
  }
});

app.listen(PORT, () => {
  console.log(`Finance MCP server running on http://localhost:${PORT}`);
  console.log(`Configured public base URL: ${BASE_URL}`);
});
