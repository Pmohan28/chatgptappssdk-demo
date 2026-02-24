# ChatGPT Apps SDK Finance Demo

Finance-focused MCP server demo for ChatGPT Apps, built with:
- Python backend (`FastMCP`)
- JS/HTML widget resource (`text/html+skybridge`)
- OAuth-style demo authentication + scope-based authorization
- Seeded sample data for PI/WI-style workflows

## Features
- MCP endpoint: `/mcp` (Streamable HTTP)
- Finance tools:
  - `get_business_snapshot`
  - `search_internal_policies`
  - `list_client_accounts` (auth required)
  - `get_rebalance_plan` (auth required)
  - `create_trade_ticket` (auth required, write scope)
- UI widget resource:
  - `ui://widgets/finance-dashboard.html`
- OAuth/demo auth endpoints:
  - `/.well-known/oauth-protected-resource`
  - `/.well-known/oauth-authorization-server`
  - `/oauth/register`
  - `/oauth/authorize`
  - `/oauth/token`

## Repository Structure
- `src/server.py`: Python MCP backend (active implementation)
- `src/server.js`: Earlier Node implementation (kept for reference)
- `TESTAPP_FLOW.md`: End-to-end 1-26 test script for ChatGPT app validation

## Prerequisites
- `uv` installed
- Python `3.12+` (handled by `uv`)
- Optional: `ngrok` account/token for public tunnel

## Local Setup
```bash
uv sync
```

## Run the MCP Server
```bash
PUBLIC_BASE_URL='http://localhost:3000' ./.venv/bin/python src/server.py
```

Health check:
```bash
curl http://localhost:3000/health
```

## Expose Publicly with ngrok
1. Configure ngrok auth token:
```bash
npx ngrok config add-authtoken <YOUR_NGROK_TOKEN>
```
2. Start tunnel:
```bash
npx ngrok http 3000
```
3. Copy the `https://...ngrok-free.app` URL and run server with it:
```bash
PUBLIC_BASE_URL='https://<YOUR_NGROK_DOMAIN>' ./.venv/bin/python src/server.py
```
4. Use this MCP URL in ChatGPT Apps:
```text
https://<YOUR_NGROK_DOMAIN>/mcp
```

## Connect in ChatGPT Apps
1. Add MCP server URL in ChatGPT Apps.
2. Start a chat and invoke tools using prompts.
3. For auth-required tools, complete demo OAuth screen and pick:
   - `Analyst` (read scopes)
   - `Advisor` (includes `trades:write`)

## Example Prompts
- `Get a business snapshot for PI and WI.`
- `Search internal policies for drift tolerance.`
- `List client accounts with drift above 3%.`
- `Create a rebalance plan for account WI-2002.`
- `Create a trade ticket for PI-1002: reduce US equity by 5%.`

## Full Demo/Test Flow
See:
- [TESTAPP_FLOW.md](./TESTAPP_FLOW.md)

## Security Note
This is a demo app with seeded users and mock OAuth behavior. It is not production authentication.
