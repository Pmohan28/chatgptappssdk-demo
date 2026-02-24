import base64
import hashlib
import json
import os
import secrets
import time
from typing import Any, Literal
from urllib.parse import urlencode

from mcp.server.fastmcp import Context, FastMCP
from mcp.types import CallToolResult, TextContent
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse

PORT = int(os.getenv("PORT", "3000"))
BASE_URL = os.getenv("PUBLIC_BASE_URL", f"http://localhost:{PORT}")

SEEDED: dict[str, Any] = {
    "businessUnits": {
        "PI": {
            "name": "Personal Investing",
            "aumUsdBn": 128.4,
            "netFlowsUsdMnQtd": 965,
            "activeClients": 51420,
            "nps": 56,
        },
        "WI": {
            "name": "Workplace Investing",
            "aumUsdBn": 292.7,
            "netFlowsUsdMnQtd": 1835,
            "activeClients": 20750,
            "nps": 61,
        },
    },
    "accounts": [
        {
            "accountId": "PI-1001",
            "business": "PI",
            "client": "Aarav Singh",
            "riskProfile": "Moderate",
            "modelPortfolio": "Balanced Growth",
            "marketValueUsd": 842000,
            "driftPct": 2.4,
            "cashPct": 7.2,
        },
        {
            "accountId": "PI-1002",
            "business": "PI",
            "client": "Noah Williams",
            "riskProfile": "Aggressive",
            "modelPortfolio": "US Equity Focus",
            "marketValueUsd": 1255000,
            "driftPct": 4.8,
            "cashPct": 3.1,
        },
        {
            "accountId": "WI-2001",
            "business": "WI",
            "client": "Acme Corp 401(k) - Segment A",
            "riskProfile": "Moderate",
            "modelPortfolio": "Global Multi-Asset",
            "marketValueUsd": 24300000,
            "driftPct": 1.1,
            "cashPct": 2.6,
        },
        {
            "accountId": "WI-2002",
            "business": "WI",
            "client": "Orion Tech Pension Sleeve",
            "riskProfile": "Conservative",
            "modelPortfolio": "Income Stabilizer",
            "marketValueUsd": 12100000,
            "driftPct": 3.3,
            "cashPct": 6.7,
        },
    ],
    "policyNotes": [
        {
            "id": "POL-AL-01",
            "title": "Model Portfolio Drift Tolerance",
            "tags": ["rebalance", "drift", "investment-policy"],
            "summary": "Accounts with drift > 3.0% require advisory review; >5.0% requires same-day remediation plan.",
        },
        {
            "id": "POL-RSK-11",
            "title": "Suitability Refresh - Annual",
            "tags": ["risk", "suitability", "compliance"],
            "summary": "Risk profile and suitability must be revalidated at least annually or after major life events.",
        },
        {
            "id": "POL-CASH-04",
            "title": "Strategic Cash Bands",
            "tags": ["cash", "allocation", "portfolio"],
            "summary": "Target cash range is 2%-5%; above 8% should trigger allocation recommendation.",
        },
    ],
}

DEMO_USERS = {
    "analyst": {
        "sub": "user-analyst",
        "name": "Analyst User",
        "scopes": ["accounts:read", "rebalance:read"],
    },
    "advisor": {
        "sub": "user-advisor",
        "name": "Advisor User",
        "scopes": ["accounts:read", "rebalance:read", "trades:write"],
    },
}

AUTH_CODES: dict[str, dict[str, Any]] = {}
ACCESS_TOKENS: dict[str, dict[str, Any]] = {}


def random_string(size: int = 32) -> str:
    return secrets.token_urlsafe(size)


def sha256base64url(input_value: str) -> str:
    digest = hashlib.sha256(input_value.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")


def html_page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html>
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>{title}</title>
  <style>
    body {{ font-family: ui-sans-serif, -apple-system, Segoe UI, Roboto, Arial, sans-serif; background:#f4f7fb; margin:0; }}
    .shell {{ max-width: 680px; margin: 40px auto; background: white; border: 1px solid #dbe3ee; border-radius: 12px; padding: 24px; }}
    h1 {{ margin-top: 0; font-size: 20px; }}
    p {{ color: #334155; }}
    .users {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin: 14px 0; }}
    label {{ border: 1px solid #dbe3ee; border-radius: 8px; padding: 10px; cursor: pointer; }}
    button {{ border: 0; border-radius: 8px; background: #0f766e; color: white; padding: 10px 14px; font-weight: 600; }}
    .muted {{ font-size: 13px; color: #64748b; }}
    code {{ background: #f1f5f9; padding: 2px 6px; border-radius: 6px; }}
  </style>
</head>
<body>
  <div class=\"shell\">{body}</div>
</body>
</html>"""


def get_auth_context(ctx: Context) -> dict[str, Any]:
    request = ctx.request_context.request
    if request is None:
        return {"authenticated": False, "scopes": [], "user": None}

    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        return {"authenticated": False, "scopes": [], "user": None}

    token = auth_header[len("Bearer ") :].strip()
    session = ACCESS_TOKENS.get(token)
    if not session or session["expiresAt"] < int(time.time() * 1000):
        return {"authenticated": False, "scopes": [], "user": None}

    return {
        "authenticated": True,
        "scopes": session["scopes"],
        "user": session["user"],
    }


def has_scopes(auth: dict[str, Any], required_scopes: list[str]) -> bool:
    scopes = set(auth.get("scopes", []))
    return all(scope in scopes for scope in required_scopes)


def unauthorized_mcp(required_scopes: list[str]) -> CallToolResult:
    scope_text = " ".join(required_scopes)
    resource_metadata_url = f"{BASE_URL}/.well-known/oauth-protected-resource"
    return CallToolResult(
        content=[TextContent(type="text", text="Authentication required.")],
        _meta={
            "mcp/www_authenticate": f'Bearer resource_metadata="{resource_metadata_url}", scope="{scope_text}"'
        },
        isError=True,
    )


mcp = FastMCP(
    name="Fidelity-Style Finance Ops App",
    host="0.0.0.0",
    port=PORT,
    streamable_http_path="/mcp",
)


@mcp.resource(
    "ui://widgets/finance-dashboard.html",
    name="finance-dashboard",
    title="Finance Dashboard",
    description="Seeded PI/WI dashboard widget",
    mime_type="text/html+skybridge",
    meta={
        "openai/widgetDescription": "Displays a finance operations snapshot for PI and WI.",
        "openai/widgetPrefersBorder": True,
        "openai/widgetCSP": {"connect_domains": [], "resource_domains": []},
    },
)
def finance_dashboard_resource() -> str:
    return """
<div style=\"font-family: ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif; padding: 16px; color:#0f172a;\">
  <h2 style=\"margin:0 0 12px; font-size:18px;\">Finance Ops Snapshot</h2>
  <p style=\"margin:0 0 12px; color:#334155;\">PI and WI seeded overview with account health and rebalance pressure.</p>
  <div id=\"metrics\" style=\"display:grid; grid-template-columns: repeat(2, minmax(120px, 1fr)); gap:10px;\"></div>
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
  metrics.innerHTML = pairs.map(([k,v]) => '<div style=\"border:1px solid #dbe3ee;border-radius:10px;padding:10px;background:#f8fafc\"><div style=\"font-size:12px;color:#64748b\">'+k+'</div><div style=\"font-size:18px;font-weight:700\">'+(v ?? 'n/a')+'</div></div>').join('');
})();
</script>
"""


@mcp.tool(
    name="get_business_snapshot",
    title="Business Snapshot",
    description="Returns PI and WI business KPIs and rebalance pressure summary.",
    meta={"openai/outputTemplate": "ui://widgets/finance-dashboard.html"},
)
def get_business_snapshot() -> CallToolResult:
    pi = SEEDED["businessUnits"]["PI"]
    wi = SEEDED["businessUnits"]["WI"]
    drift_accounts = len([a for a in SEEDED["accounts"] if a["driftPct"] > 3])
    net_flows_qtd_mn = pi["netFlowsUsdMnQtd"] + wi["netFlowsUsdMnQtd"]

    structured = {
        "piAumBn": pi["aumUsdBn"],
        "wiAumBn": wi["aumUsdBn"],
        "driftAccounts": drift_accounts,
        "netFlowsQtdMn": net_flows_qtd_mn,
    }

    return CallToolResult(
        content=[
            TextContent(
                type="text",
                text=(
                    f"PI AUM: ${pi['aumUsdBn']}bn, WI AUM: ${wi['aumUsdBn']}bn, "
                    f"accounts with drift >3%: {drift_accounts}."
                ),
            )
        ],
        structuredContent=structured,
        _meta={"openai/outputTemplate": "ui://widgets/finance-dashboard.html"},
    )


@mcp.tool(
    name="search_internal_policies",
    title="Search Internal Policies",
    description="Searches seeded policy guidance for compliance and portfolio operations.",
)
def search_internal_policies(query: str) -> dict[str, Any]:
    q = query.lower()
    matches = [
        p
        for p in SEEDED["policyNotes"]
        if q in p["title"].lower()
        or q in p["summary"].lower()
        or any(q in tag for tag in p["tags"])
    ]
    return {
        "query": query,
        "results": matches,
        "message": (
            f"Found {len(matches)} matching policy item(s)."
            if matches
            else "No policy notes matched the query."
        ),
    }


@mcp.tool(
    name="list_client_accounts",
    title="List Client Accounts",
    description="Returns seeded PI/WI accounts. Requires authenticated access.",
    meta={"securitySchemes": [{"type": "oauth2", "scopes": ["accounts:read"]}]},
)
def list_client_accounts(
    ctx: Context,
    business: Literal["PI", "WI"] | None = None,
    minDriftPct: float = 0.0,
) -> CallToolResult:
    auth = get_auth_context(ctx)
    if not auth["authenticated"] or not has_scopes(auth, ["accounts:read"]):
        return unauthorized_mcp(["accounts:read"])

    rows = [
        a
        for a in SEEDED["accounts"]
        if (business is None or a["business"] == business) and a["driftPct"] >= minDriftPct
    ]
    return CallToolResult(
        content=[TextContent(type="text", text=f"Returned {len(rows)} account(s).")],
        structuredContent={"requestedBy": auth["user"]["name"], "accounts": rows},
    )


@mcp.tool(
    name="get_rebalance_plan",
    title="Get Rebalance Plan",
    description="Creates a simple recommended action plan for an account based on drift and cash.",
    meta={"securitySchemes": [{"type": "oauth2", "scopes": ["rebalance:read"]}]},
)
def get_rebalance_plan(ctx: Context, accountId: str) -> CallToolResult:
    auth = get_auth_context(ctx)
    if not auth["authenticated"] or not has_scopes(auth, ["rebalance:read"]):
        return unauthorized_mcp(["rebalance:read"])

    account = next((a for a in SEEDED["accounts"] if a["accountId"] == accountId), None)
    if account is None:
        return CallToolResult(
            content=[TextContent(type="text", text=f"Account {accountId} not found.")],
            structuredContent={"found": False},
            isError=True,
        )

    actions: list[str] = []
    if account["driftPct"] > 5:
        actions.append("Escalate to same-day remediation per drift policy.")
    elif account["driftPct"] > 3:
        actions.append("Queue advisor review within 24 hours.")
    else:
        actions.append("Within tolerance; monitor at next rebalance cycle.")

    if account["cashPct"] > 8:
        actions.append("Propose redeployment from excess cash into model underweights.")
    elif account["cashPct"] < 2:
        actions.append("Increase liquidity sleeve to maintain operational flexibility.")

    return CallToolResult(
        content=[TextContent(type="text", text=f"Rebalance plan generated for {accountId}.")],
        structuredContent={
            "account": account,
            "recommendedActions": actions,
            "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    )


@mcp.tool(
    name="create_trade_ticket",
    title="Create Trade Ticket",
    description="Creates a mock trade ticket for operational workflow demos.",
    meta={"securitySchemes": [{"type": "oauth2", "scopes": ["trades:write"]}]},
)
def create_trade_ticket(ctx: Context, accountId: str, instruction: str) -> CallToolResult:
    auth = get_auth_context(ctx)
    if not auth["authenticated"] or not has_scopes(auth, ["trades:write"]):
        return unauthorized_mcp(["trades:write"])

    account = next((a for a in SEEDED["accounts"] if a["accountId"] == accountId), None)
    if account is None:
        return CallToolResult(
            content=[TextContent(type="text", text=f"Account {accountId} not found.")],
            structuredContent={"created": False},
            isError=True,
        )

    ticket_id = f"TKT-{secrets.randbelow(900000) + 100000}"
    return CallToolResult(
        content=[TextContent(type="text", text=f"Trade ticket {ticket_id} created.")],
        structuredContent={
            "created": True,
            "ticketId": ticket_id,
            "accountId": accountId,
            "instruction": instruction,
            "createdBy": auth["user"]["name"],
            "status": "Pending Compliance Review",
            "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    )


@mcp.custom_route("/health", methods=["GET"])
async def health(_: Request):
    return JSONResponse({"ok": True, "service": "finance-mcp-python", "now": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})


@mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
async def protected_resource(_: Request):
    return JSONResponse(
        {
            "resource": f"{BASE_URL}/mcp",
            "authorization_servers": [BASE_URL],
            "bearer_methods_supported": ["header"],
            "scopes_supported": ["accounts:read", "rebalance:read", "trades:write"],
        }
    )


@mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
async def authorization_server(_: Request):
    return JSONResponse(
        {
            "issuer": BASE_URL,
            "authorization_endpoint": f"{BASE_URL}/oauth/authorize",
            "token_endpoint": f"{BASE_URL}/oauth/token",
            "registration_endpoint": f"{BASE_URL}/oauth/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
            "scopes_supported": ["accounts:read", "rebalance:read", "trades:write"],
        }
    )


@mcp.custom_route("/oauth/register", methods=["POST"])
async def oauth_register(request: Request):
    payload: dict[str, Any] = {}
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        payload = await request.json()

    client_name = payload.get("client_name", "chatgpt-app")
    redirect_uris = payload.get("redirect_uris", [])
    return JSONResponse(
        {
            "client_id": f"client-{random_string(8)}",
            "client_name": client_name,
            "redirect_uris": redirect_uris,
            "token_endpoint_auth_method": "none",
        },
        status_code=201,
    )


@mcp.custom_route("/oauth/authorize", methods=["GET"])
async def oauth_authorize_get(request: Request):
    params = request.query_params
    client_id = params.get("client_id", "unknown-client")
    redirect_uri = params.get("redirect_uri", "")
    state = params.get("state", "")
    scope = params.get("scope", "accounts:read")
    code_challenge = params.get("code_challenge", "")
    code_challenge_method = params.get("code_challenge_method", "S256")

    if not redirect_uri or not code_challenge:
        return JSONResponse(
            {
                "error": "invalid_request",
                "error_description": "redirect_uri and code_challenge are required",
            },
            status_code=400,
        )

    body = f"""
<h1>Sign in to Finance Ops Demo</h1>
<p>Client: <code>{client_id}</code></p>
<p>Requested scope: <code>{scope}</code></p>
<form method=\"post\" action=\"/oauth/authorize\">
  <input type=\"hidden\" name=\"client_id\" value=\"{client_id}\" />
  <input type=\"hidden\" name=\"redirect_uri\" value=\"{redirect_uri}\" />
  <input type=\"hidden\" name=\"state\" value=\"{state}\" />
  <input type=\"hidden\" name=\"scope\" value=\"{scope}\" />
  <input type=\"hidden\" name=\"code_challenge\" value=\"{code_challenge}\" />
  <input type=\"hidden\" name=\"code_challenge_method\" value=\"{code_challenge_method}\" />
  <div class=\"users\">
    <label><input type=\"radio\" name=\"user\" value=\"analyst\" checked /> Analyst (read accounts + rebalance)</label>
    <label><input type=\"radio\" name=\"user\" value=\"advisor\" /> Advisor (includes trade write)</label>
  </div>
  <button type=\"submit\">Authorize</button>
</form>
<p class=\"muted\">This is a demo auth screen for local/testing use.</p>
"""
    return HTMLResponse(html_page("Demo Finance Auth", body))


@mcp.custom_route("/oauth/authorize", methods=["POST"])
async def oauth_authorize_post(request: Request):
    form = await request.form()
    client_id = str(form.get("client_id", ""))
    redirect_uri = str(form.get("redirect_uri", ""))
    state = str(form.get("state", ""))
    scope = str(form.get("scope", "accounts:read"))
    code_challenge = str(form.get("code_challenge", ""))
    code_challenge_method = str(form.get("code_challenge_method", "S256"))
    user = str(form.get("user", "analyst"))

    if not client_id or not redirect_uri or not code_challenge:
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    demo_user = DEMO_USERS.get(user, DEMO_USERS["analyst"])
    requested_scopes = [s for s in scope.split() if s.strip()]
    allowed_scopes = [s for s in requested_scopes if s in demo_user["scopes"]]

    code = random_string(18)
    AUTH_CODES[code] = {
        "clientId": client_id,
        "redirectUri": redirect_uri,
        "codeChallenge": code_challenge,
        "codeChallengeMethod": code_challenge_method,
        "scopes": allowed_scopes,
        "user": demo_user,
        "expiresAt": int(time.time() * 1000) + (5 * 60 * 1000),
    }

    query = {"code": code}
    if state:
        query["state"] = state
    location = f"{redirect_uri}{'&' if '?' in redirect_uri else '?'}{urlencode(query)}"
    return RedirectResponse(location, status_code=302)


@mcp.custom_route("/oauth/token", methods=["POST"])
async def oauth_token(request: Request):
    content_type = request.headers.get("content-type", "")
    if "application/x-www-form-urlencoded" in content_type:
        form = await request.form()
        payload = {k: str(v) for k, v in form.items()}
    elif "application/json" in content_type:
        payload = await request.json()
    else:
        payload = json.loads((await request.body()).decode("utf-8") or "{}")

    grant_type = payload.get("grant_type")
    code = payload.get("code")
    client_id = payload.get("client_id")
    redirect_uri = payload.get("redirect_uri")
    code_verifier = payload.get("code_verifier", "")

    if grant_type != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

    auth_code = AUTH_CODES.get(str(code))
    if not auth_code or auth_code["expiresAt"] < int(time.time() * 1000):
        return JSONResponse({"error": "invalid_grant"}, status_code=400)

    if auth_code["clientId"] != client_id or auth_code["redirectUri"] != redirect_uri:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)

    if auth_code["codeChallengeMethod"] == "S256":
        hashed = sha256base64url(str(code_verifier))
        if hashed != auth_code["codeChallenge"]:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

    AUTH_CODES.pop(str(code), None)

    token = random_string(24)
    ACCESS_TOKENS[token] = {
        "user": auth_code["user"],
        "scopes": auth_code["scopes"],
        "expiresAt": int(time.time() * 1000) + (60 * 60 * 1000),
    }

    return JSONResponse(
        {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": " ".join(auth_code["scopes"]),
        }
    )


if __name__ == "__main__":
    print(f"Finance MCP Python server running on http://localhost:{PORT}")
    print(f"Configured public base URL: {BASE_URL}")
    mcp.run(transport="streamable-http")
