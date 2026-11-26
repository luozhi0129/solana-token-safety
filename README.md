# Solana Token Safety Check

Read-only MCP server that checks the safety of a Solana token or wallet from
free public data sources only. **No API keys, no accounts, no secrets.**

The value is the analysis — mint/freeze authority checks, holder
concentration math, liquidity lookup, risk flags — not the raw data.
Nothing here resells a free gateway.

## Tools

| Tool | Input | What it returns | Data source (free, no key) |
|---|---|---|---|
| `check_token` | `mint` (SPL token mint, base58, 32–44 chars) | Decimals, supply, mint/freeze authority + revoked flags, top-10 holder concentration, risk flags, verdict | Solana public JSON-RPC |
| `check_wallet` | `address` (Solana wallet, base58, 32–44 chars) | SOL balance (+USD), token accounts, top 5 holdings with USD values, total USD | Solana public RPC + Jupiter Price v3 |
| `token_liquidity` | `mint` (SPL token mint, base58, 32–44 chars) | Best DEX pair (dex, price, liquidity, 24h volume/change, FDV/market cap, pair age), pair count | DexScreener public API |

## Verdicts (`check_token`)

| Verdict | Meaning |
|---|---|
| `LOW_RISK` | Both authorities revoked, no concentration red flags |
| `CAUTION` | A live mint or freeze authority, or moderate concentration |
| `HIGH_RISK` | Top 10 holders own > 80% of supply, or the largest holder owns > 50% |
| `INCONCLUSIVE` | **Not a clean bill of health.** Both authorities are revoked, but holder concentration could not be checked because the public Solana RPC rate-limited `getTokenLargestAccounts` (HTTP 429). A highly concentrated token would look safe if we called this `LOW_RISK`, so the verdict is downgraded. Retry later. |

`CAUTION` is never downgraded to `INCONCLUSIVE`: a live authority is a
known risk, not a missing one. `HIGH_RISK` can only trigger on real holder
numbers, never on missing data.

Note: USDC correctly reports `CAUTION` — Circle keeps mint + freeze
authority. That is the honest verdict for a centralized stablecoin.

## Honest limits

- **Holder COUNT is not available** from the public Solana RPC at all;
  the tool reports top-10 share instead.
- **Holder concentration can be temporarily unavailable.** The public RPC
  rate-limits `getTokenLargestAccounts` per method under load. When that
  happens `check_token` still reports authorities + supply, says plainly
  that concentration is unavailable (`top_holders_note`), and downgrades
  the verdict to `INCONCLUSIVE` instead of inventing holder data.
- **Prices can be missing** for tiny or brand-new tokens; missing prices
  are reported as `null`, never invented.
- **DexScreener pairs are two-sided.** Only pairs where the token is the
  *base* token have a `price_usd` for that token. `token_liquidity`
  filters to base pairs first and falls back to all pairs with a
  `QUOTE_ONLY` flag.

## Run locally (stdio)

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python server.py
```

Requires Python 3.10+ (tested on 3.12.3). Pins: `mcp==1.30.0`
(FastMCP lives inside the `mcp` package; in mcp 2.3.0 FastMCP was
renamed, so do not upgrade blindly), `httpx`.

Any MCP client that speaks stdio can spawn it, e.g.:

```json
{
  "mcpServers": {
    "solana-token-safety": {
      "command": "/path/to/.venv/bin/python",
      "args": ["/path/to/server.py"]
    }
  }
}
```

## Run as HTTP (Streamable HTTP)

When the `PORT` environment variable is set, the server serves
Streamable HTTP on `0.0.0.0:$PORT` instead of stdio, with
`stateless_http=True` (every request stands alone, no persistent
session). This is the mode container hosts use (MCPize, MCPRush, etc.):

```bash
PORT=8080 .venv/bin/python server.py
# then POST MCP requests to http://localhost:8080/mcp
```

When `PORT` is unset, the server uses the stdio transport.

## Environment variables (all optional)

| Variable | Purpose |
|---|---|
| `PORT` | If set, serve Streamable HTTP on `0.0.0.0:$PORT` instead of stdio |
| `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` | Egress proxy URL, read explicitly (`trust_env=False`); only needed behind a proxy that blocks direct egress |
| `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` | Extra CA bundle, loaded when the env points at one; only needed behind a TLS-intercepting proxy |

No API key is needed for any data source. The server never logs or
stores credentials, and there are none to configure.

## Also available hosted

The same server is listed on the MCPize marketplace:

- Marketplace page: https://mcpize.com/mcp/solana-token-safety
- Gateway endpoint: `https://solana-token-safety.mcpize.run/mcp`
  (requires a free MCPize API key sent as `Authorization: Bearer <key>`)

## License

MIT — see [LICENSE](LICENSE).
