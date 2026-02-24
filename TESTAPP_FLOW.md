# Test App Flow (1-26)

1. Open ChatGPT in a browser and sign in with your ChatGPT account.
2. Go to the Apps/MCP connection area in ChatGPT.
3. Add a new MCP server connection.
4. Enter this MCP URL: `https://0d58-2401-4900-be98-f4b2-1d1-b8ed-d43c-c3fd.ngrok-free.app/mcp`.
5. Save the MCP server connection.
6. Start a new chat and ensure this app/server is available in the chat tools list.
7. Send prompt: `Get a business snapshot for PI and WI.`
8. Confirm the app invokes `get_business_snapshot`.
9. Confirm you see KPI response text and widget/dashboard rendering.
10. Send prompt: `Search internal policies for drift tolerance.`
11. Confirm the app invokes `search_internal_policies` without authentication challenge.
12. Send prompt: `List client accounts with drift above 3%.`
13. Confirm ChatGPT triggers OAuth authentication flow.
14. In auth UI, select `Analyst`.
15. Click `Authorize` and return to ChatGPT.
16. Confirm ChatGPT retries tool and returns account list (authorized for `accounts:read`).
17. Send prompt: `Create a rebalance plan for account WI-2002.`
18. Confirm tool runs successfully (authorized for `rebalance:read`).
19. Send prompt: `Create a trade ticket for PI-1002: reduce US equity by 5%.`
20. Confirm tool is denied due to missing `trades:write` scope for Analyst.
21. Re-run trade prompt and choose re-authentication when prompted.
22. In auth UI, select `Advisor`.
23. Click `Authorize` and return to ChatGPT.
24. Confirm trade ticket is now created successfully.
25. Send prompt: `List all WI accounts with drift above 1%.` and validate filtered results.
26. Capture screenshots/logs of each checkpoint for demo evidence and regression baseline.
