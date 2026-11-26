#!/usr/bin/env python3
"""MCP server: Solana token safety checker (read-only, no keys, no account).

Original analysis tools for agents doing on-chain research: given a token
mint or a wallet address, return a safety report built from free public
data sources only -- the Solana public JSON-RPC endpoint, DexScreener's
public API, and Jupiter's public price API. No API keys, no logins, no
secrets anywhere. The value is the analysis (authority checks, holder
concentration, liquidity), not the raw data.

Tools:
- check_token: mint/freeze authority revoked?, supply, decimals, top-10
  holder concentration, risk flags.
- check_wallet: SOL balance (+USD), token accounts, top holdings with USD
  values where Jupiter has a price.
- token_liquidity: best DexScreener pair (dex, liquidity, 24h volume,
  24h price change, FDV/market cap, pair age).

Verified 2026-11-19 on this VM: public Solana RPC, DexScreener and
Jupiter Price v3 all answer from here (see README.md for the test log).

Data-source limits, stated honestly in the outputs:
- Holder COUNT is not available from the public RPC, so check_token
  reports top-holder concentration instead (top-10 share of supply).
- Prices come from Jupiter/DexScreener and can be missing for tiny or
  brand-new tokens; missing prices are reported as null, never invented.
- The public Solana RPC can rate-limit (429) under load; the tools say
  so and ask for a retry instead of failing silently.

Run: .venv/bin/python server.py  (stdio transport)
"""

import asyncio
import json
import os
import ssl
from typing import Optional

import httpx
from pydantic import BaseModel, ConfigDict, Field
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("solana_token_safety")

SOLANA_RPC = "https://api.mainnet-beta.solana.com"
DEXSCREENER = "https://api.dexscreener.com/latest/dex/tokens"
JUPITER_PRICE = "https://api.jup.ag/price/v3"
TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
WSOL = "So11111111111111111111111111111111111111112"

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58_decode(s: str) -> Optional[bytes]:
    """Decode a base58 string to bytes; None if invalid characters."""
    n = 0
    for ch in s:
        idx = _B58_ALPHABET.find(ch)
        if idx < 0:
            return None
        n = n * 58 + idx
    pad = len(s) - len(s.lstrip("1"))
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * pad + raw


def _valid_address(addr: str) -> bool:
    """A Solana address is base58 decoding to exactly 32 bytes."""
    if not isinstance(addr, str) or not (32 <= len(addr) <= 44):
        return False
    decoded = _b58_decode(addr)
    return decoded is not None and len(decoded) == 32


_PROXY_SEEN: bool | None = None


def _make_client(timeout: int) -> httpx.AsyncClient:
    """httpx client that works behind this VM's egress proxy.

    Two lessons baked in here (Kilo MCP server, 2026-11-18, plus this
    server's own debugging 2026-11-19):
    1. httpx's default trust_env=True chokes on this environment's
       NO_PROXY (bracketed IPv6 entries like [::1] fail with
       `InvalidURL: Invalid port: ':1]'`), and direct egress is blocked,
       so the proxy URL must be passed explicitly with trust_env=False.
    2. httpx's default SSL context trusts only certifi's bundle, but this
       VM's egress proxy MITMs TLS with its own CA (named by SSL_CERT_FILE
       / REQUESTS_CA_BUNDLE). Without that CA, hosts the proxy MITMs fail
       with `CERTIFICATE_VERIFY_FAILED: self-signed certificate in
       certificate chain` (DexScreener and Jupiter failed exactly this
       way; api.mainnet-beta.solana.com happened to pass through).
       So build a context that also loads the egress CA bundle when the
       env points at one. On MCPize's cloud there is no MITM proxy, so
       the plain default context applies there. The proxy URL (with
       credentials) is never logged or hardcoded.

    NOTE: MCP stdio clients spawn servers with a minimal env allowlist
    that drops the proxy vars AND the CA-bundle vars. A server spawned
    that way has no proxy to read -- see _PROXY_SEEN and the ConnectError
    branch in _handle_error. The spawning client must forward
    HTTPS_PROXY / HTTP_PROXY and SSL_CERT_FILE / REQUESTS_CA_BUNDLE
    (see test_client.py).
    """
    global _PROXY_SEEN
    proxy_url = (
        os.environ.get("HTTPS_PROXY")
        or os.environ.get("https_proxy")
        or os.environ.get("ALL_PROXY")
        or os.environ.get("all_proxy")
        or os.environ.get("HTTP_PROXY")
        or os.environ.get("http_proxy")
    )
    _PROXY_SEEN = proxy_url is not None
    ctx = ssl.create_default_context()
    ca_bundle = os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE")
    if ca_bundle and os.path.exists(ca_bundle):
        try:
            ctx.load_verify_locations(cafile=ca_bundle)
        except Exception:
            pass
    return httpx.AsyncClient(timeout=timeout, proxy=proxy_url, trust_env=False, verify=ctx)


def _handle_error(e: Exception, source: str) -> str:
    """Consistent, actionable error formatting for upstream calls."""
    if isinstance(e, httpx.HTTPStatusError):
        code = e.response.status_code
        if code == 429:
            return (
                f"Error: {source} rate-limited the request (HTTP 429). "
                "The public endpoint is busy; wait a bit and retry."
            )
        return f"Error: {source} request failed with HTTP {code}."
    if isinstance(e, httpx.TimeoutException):
        return f"Error: {source} request timed out; retry later."
    if isinstance(e, httpx.ConnectError):
        hint = ""
        if _PROXY_SEEN is False:
            hint = (
                " No egress proxy was configured in this server process: "
                "MCP stdio clients spawn servers with a minimal env allowlist "
                "that drops HTTPS_PROXY/HTTP_PROXY, and direct egress is blocked "
                "on this VM. The spawning client must forward the proxy env vars "
                "to the server (see test_client.py)."
            )
        return f"Error: Could not connect to {source} ({type(e).__name__}).{hint}"
    return f"Error: Unexpected error: {type(e).__name__}: {e}"


async def _rpc(method: str, params: list, timeout: int = 30) -> dict:
    """One Solana JSON-RPC call; returns the `result` object or raises.

    The public RPC rate-limits (429) under load, so retry up to 3 times
    with backoff (2s, 4s) before giving up.
    """
    for attempt in range(3):
        async with _make_client(timeout) as client:
            response = await client.post(
                SOLANA_RPC,
                headers={"content-type": "application/json", "accept": "application/json"},
                json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
            )
        if response.status_code == 429 and attempt < 2:
            await asyncio.sleep(2 * (attempt + 1))
            continue
        response.raise_for_status()
        data = response.json()
        if "error" in data:
            raise RuntimeError(f"Solana RPC error: {data['error'].get('message')}")
        return data.get("result")
    raise RuntimeError("Solana RPC rate-limited after 3 attempts")


async def _jupiter_prices(mints: list[str], timeout: int = 30) -> dict:
    """USD prices for mints from Jupiter Price v3 (free, no key).

    Returns {mint: usd_price or None}. A failed lookup returns {} so the
    caller reports prices as null instead of inventing numbers.
    """
    if not mints:
        return {}
    try:
        async with _make_client(timeout) as client:
            response = await client.get(
                JUPITER_PRICE, params={"ids": ",".join(mints)}
            )
            response.raise_for_status()
            data = response.json()
    except Exception:
        return {}
    out = {}
    for mint in mints:
        entry = data.get(mint) if isinstance(data, dict) else None
        out[mint] = entry.get("usdPrice") if isinstance(entry, dict) else None
    return out


class CheckTokenInput(BaseModel):
    """Input for check_token."""

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True)

    mint: str = Field(
        ...,
        description="SPL token mint address (base58, 44 chars, e.g. USDC EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v).",
        min_length=32,
        max_length=44,
    )


class CheckWalletInput(BaseModel):
    """Input for check_wallet."""

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True)

    address: str = Field(
        ...,
        description="Solana wallet address (base58, 44 chars).",
        min_length=32,
        max_length=44,
    )


class TokenLiquidityInput(BaseModel):
    """Input for token_liquidity."""

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True)

    mint: str = Field(
        ...,
        description="SPL token mint address (base58, 44 chars).",
        min_length=32,
        max_length=44,
    )


@mcp.tool(
    name="check_token",
    annotations={
        "title": "Check a Solana token's safety",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def check_token(params: CheckTokenInput) -> str:
    """Check a Solana SPL token's safety: authorities, supply, holder concentration.

    Reads the mint account (parsed), the token supply, and the 20 largest
    token accounts from the public Solana RPC. No key, no account.

    Args:
        params (CheckTokenInput): mint address.

    Returns:
        str: JSON with:
        {
            "mint": str,
            "decimals": int, "supply": str, "supply_ui": float,
            "mint_authority": str | null,      # null = revoked (good)
            "mint_authority_revoked": bool,
            "freeze_authority": str | null,    # null = revoked (good)
            "freeze_authority_revoked": bool,
            "top_holders": [{"address", "ui_amount", "share_pct"} ... top 10],
            "top10_share_pct": float | null,   # share of supply held by top 10
            "largest_holder_pct": float | null,
            "holder_count": null,  # not available from the public RPC; see README
            "top_holders_note": str | null,  # set when the public RPC
                # rate-limits getTokenLargestAccounts and concentration could
                # not be checked; the rest of the report is still valid
            "flags": [str],        # e.g. "MINT_AUTHORITY_ACTIVE", "TOP10_OVER_50PCT"
            "verdict": str         # "LOW_RISK" | "CAUTION" | "HIGH_RISK" | "INCONCLUSIVE"
                # INCONCLUSIVE = both authorities revoked but holder
                # concentration could not be checked (public RPC 429);
                # not a clean bill of health, retry later
        }

        Error responses (plain strings starting with "Error: "):
        - "Error: ... is not a valid Solana address" -> bad mint string
        - "Error: ... mint account not found ..." -> mint does not exist
        - "Error: ... rate-limited (HTTP 429)" -> public RPC busy; retry
    """
    mint = params.mint
    if not _valid_address(mint):
        return f"Error: '{mint}' is not a valid Solana address (must be base58, 32 bytes)."
    try:
        info = await _rpc(
            "getAccountInfo",
            [mint, {"encoding": "jsonParsed"}],
        )
        if not info or not info.get("value"):
            return f"Error: mint account not found on Solana mainnet: {mint}"
        parsed = (info["value"].get("data") or {}).get("parsed") or {}
        mint_info = parsed.get("info") or {}
        supply_res = await _rpc("getTokenSupply", [mint])
    except Exception as e:
        return _handle_error(e, "Solana public RPC")
    # getTokenLargestAccounts is rate-limited per-method on the public RPC
    # (HTTP 429 "Too many requests for a specific RPC call" can persist
    # for a while from a shared egress IP). Degrade gracefully: report
    # authorities + supply, and say plainly that holder concentration is
    # unavailable right now instead of inventing it.
    largest_res = None
    largest_error = None
    try:
        largest_res = await _rpc("getTokenLargestAccounts", [mint, {"commitment": "confirmed"}])
    except Exception as e:
        largest_error = str(e)

    decimals = mint_info.get("decimals")
    supply_raw = (supply_res or {}).get("value") or {}
    supply_ui = supply_raw.get("uiAmount")
    mint_auth = mint_info.get("mintAuthority")
    freeze_auth = mint_info.get("freezeAuthority")

    holders = []
    total = supply_ui or 0
    if largest_res is not None:
        for entry in ((largest_res or {}).get("value") or [])[:10]:
            amt = entry.get("uiAmount")
            holders.append(
                {
                    "address": entry.get("address"),
                    "ui_amount": amt,
                    "share_pct": round(amt / total * 100, 2) if amt is not None and total else None,
                }
            )
    top10 = sum(h["ui_amount"] for h in holders if h["ui_amount"] is not None)
    top10_share = round(top10 / total * 100, 2) if total and holders else None
    largest_share = holders[0]["share_pct"] if holders else None

    flags = []
    if mint_auth is not None:
        flags.append("MINT_AUTHORITY_ACTIVE (new tokens can be minted)")
    if freeze_auth is not None:
        flags.append("FREEZE_AUTHORITY_ACTIVE (holder accounts can be frozen)")
    if largest_res is None:
        flags.append(
            "TOP_HOLDERS_UNAVAILABLE (public Solana RPC rate-limits "
            "getTokenLargestAccounts from this network right now; "
            "concentration could not be checked -- retry later)"
        )
    if top10_share is not None and top10_share > 50:
        flags.append("TOP10_OVER_50PCT (top 10 holders own over half the supply)")
    if largest_share is not None and largest_share > 20:
        flags.append("LARGEST_HOLDER_OVER_20PCT")
    verdict = "LOW_RISK"
    if mint_auth is not None or freeze_auth is not None:
        verdict = "CAUTION"
    if (top10_share is not None and top10_share > 80) or (
        largest_share is not None and largest_share > 50
    ):
        verdict = "HIGH_RISK"
    # Concentration missing means the LOW_RISK verdict would be a green
    # light built on unchecked data: with both authorities revoked and no
    # holder data, a highly concentrated token would look safe. Downgrade
    # to INCONCLUSIVE instead. CAUTION is untouched (a live authority is
    # a known risk, not a missing one), and HIGH_RISK cannot trigger here
    # (both of its conditions need real holder numbers).
    if largest_res is None and verdict == "LOW_RISK":
        verdict = "INCONCLUSIVE"

    return json.dumps(
        {
            "mint": mint,
            "decimals": decimals,
            "supply": supply_raw.get("amount"),
            "supply_ui": supply_ui,
            "mint_authority": mint_auth,
            "mint_authority_revoked": mint_auth is None,
            "freeze_authority": freeze_auth,
            "freeze_authority_revoked": freeze_auth is None,
            "top_holders": holders,
            "top10_share_pct": top10_share,
            "largest_holder_pct": largest_share,
            "holder_count": None,
            "top_holders_note": (
                "Holder concentration unavailable: the public Solana RPC "
                "rate-limits getTokenLargestAccounts from this network "
                "(HTTP 429, persists for a while). Authorities and supply "
                "above are still valid; retry later for concentration."
                if largest_res is None
                else None
            ),
            "flags": flags,
            "verdict": verdict,
        },
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool(
    name="check_wallet",
    annotations={
        "title": "Check a Solana wallet's holdings",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def check_wallet(params: CheckWalletInput) -> str:
    """Check a Solana wallet: SOL balance and top token holdings with USD values.

    Reads SOL balance and parsed token accounts from the public Solana RPC,
    and prices the top holdings via Jupiter Price v3 (free, no key). Tokens
    without a Jupiter price report usd_value as null.

    Args:
        params (CheckWalletInput): wallet address.

    Returns:
        str: JSON with:
        {
            "address": str,
            "sol_balance": float, "sol_usd": float | null,
            "token_accounts": int,   # number of non-empty token accounts
            "top_holdings": [{"mint", "ui_amount", "decimals",
                              "usd_price": float | null,
                              "usd_value": float | null} ... up to 5, by USD value],
            "total_usd": float | null  # SOL + priced holdings; null if nothing priced
        }
    """
    address = params.address
    if not _valid_address(address):
        return f"Error: '{address}' is not a valid Solana address (must be base58, 32 bytes)."
    try:
        balance_res = await _rpc("getBalance", [address])
        accounts_res = await _rpc(
            "getTokenAccountsByOwner",
            [
                address,
                {"programId": TOKEN_PROGRAM},
                {"encoding": "jsonParsed"},
            ],
        )
    except Exception as e:
        return _handle_error(e, "Solana public RPC")

    lamports = (balance_res or {}).get("value") or 0
    sol = lamports / 1_000_000_000

    holdings = []
    for acct in ((accounts_res or {}).get("value") or []):
        info = (acct.get("account") or {}).get("data", {}).get("parsed", {}).get("info") or {}
        amount = info.get("tokenAmount") or {}
        ui_amount = amount.get("uiAmount") or 0
        if ui_amount <= 0:
            continue
        holdings.append(
            {
                "mint": info.get("mint"),
                "ui_amount": ui_amount,
                "decimals": amount.get("decimals"),
            }
        )
    prices = await _jupiter_prices([h["mint"] for h in holdings[:10]])
    sol_price = (await _jupiter_prices([WSOL])).get(WSOL)
    for h in holdings:
        price = prices.get(h["mint"])
        h["usd_price"] = price
        h["usd_value"] = round(h["ui_amount"] * price, 2) if price is not None else None
    holdings.sort(key=lambda h: (h["usd_value"] is not None, h["usd_value"] or 0), reverse=True)

    sol_usd = round(sol * sol_price, 2) if sol_price is not None else None
    priced_total = sum(h["usd_value"] for h in holdings if h["usd_value"] is not None)
    total_usd = None
    if sol_usd is not None or priced_total:
        total_usd = round((sol_usd or 0) + priced_total, 2)

    return json.dumps(
        {
            "address": address,
            "sol_balance": sol,
            "sol_usd": sol_usd,
            "token_accounts": len(holdings),
            "top_holdings": holdings[:5],
            "total_usd": total_usd,
        },
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool(
    name="token_liquidity",
    annotations={
        "title": "Check a Solana token's DEX liquidity",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def token_liquidity(params: TokenLiquidityInput) -> str:
    """Check a Solana token's DEX liquidity via DexScreener (free, no key).

    Returns the highest-liquidity pair plus a pair count. A token with no
    pairs (never listed on a DEX) reports pairs: [] and a note.

    Args:
        params (TokenLiquidityInput): mint address.

    Returns:
        str: JSON with:
        {
            "mint": str, "pairs_found": int,
            "best_pair": {
                "dex": str, "pair_address": str, "pair_url": str,
                "price_usd": float | null, "liquidity_usd": float | null,
                "volume_24h_usd": float | null, "price_change_24h_pct": float | null,
                "fdv_usd": float | null, "market_cap_usd": float | null,
                "pair_created_at": str | null
            } | null,
            "flags": [str]  # e.g. "NO_PAIRS", "LOW_LIQUIDITY_UNDER_10K"
        }
    """
    mint = params.mint
    if not _valid_address(mint):
        return f"Error: '{mint}' is not a valid Solana address (must be base58, 32 bytes)."
    try:
        data = None
        for attempt in range(3):
            async with _make_client(30) as client:
                response = await client.get(f"{DEXSCREENER}/{mint}")
            if response.status_code == 429 and attempt < 2:
                await asyncio.sleep(2 * (attempt + 1))
                continue
            response.raise_for_status()
            data = response.json()
            break
    except Exception as e:
        return _handle_error(e, "DexScreener public API")

    pairs = data.get("pairs") or []
    sol_pairs = [p for p in pairs if p.get("chainId") == "solana"]
    # DexScreener returns pairs where the token is EITHER side. Only pairs
    # where it is the base token have a price_usd for THIS token; in a pair
    # where it is the quote token, price_usd belongs to the other token
    # (e.g. USDC as quote in a memecoin/USDC pair prices the memecoin).
    base_pairs = [
        p for p in sol_pairs if (p.get("baseToken") or {}).get("address") == mint
    ]
    pool = base_pairs if base_pairs else sol_pairs
    if not pool:
        return json.dumps(
            {
                "mint": mint,
                "pairs_found": 0,
                "best_pair": None,
                "flags": ["NO_PAIRS (token has no DEX pair on Solana)"],
            },
            ensure_ascii=False,
            indent=2,
        )
    pool.sort(key=lambda p: ((p.get("liquidity") or {}).get("usd") or 0), reverse=True)
    best = pool[0]
    liq = (best.get("liquidity") or {}).get("usd")
    vol = (best.get("volume") or {}).get("h24")
    chg = (best.get("priceChange") or {}).get("h24")
    created = best.get("pairCreatedAt")
    import datetime

    created_iso = None
    if created:
        try:
            created_iso = datetime.datetime.fromtimestamp(
                created / 1000, tz=datetime.timezone.utc
            ).isoformat()
        except Exception:
            created_iso = None
    flags = []
    if not base_pairs:
        flags.append("QUOTE_ONLY (token only appears as the quote side; price is for the other token)")
    if liq is not None and liq < 10_000:
        flags.append("LOW_LIQUIDITY_UNDER_10K")
    if vol is not None and vol < 1_000:
        flags.append("LOW_VOLUME_24H_UNDER_1K")
    return json.dumps(
        {
            "mint": mint,
            "pairs_found": len(pool),
            "best_pair": {
                "dex": best.get("dexId"),
                "pair_address": best.get("pairAddress"),
                "pair_url": best.get("url"),
                "price_usd": float(best["priceUsd"]) if best.get("priceUsd") else None,
                "liquidity_usd": liq,
                "volume_24h_usd": vol,
                "price_change_24h_pct": chg,
                "fdv_usd": best.get("fdv"),
                "market_cap_usd": best.get("marketCap"),
                "pair_created_at": created_iso,
            },
            "flags": flags,
        },
        ensure_ascii=False,
        indent=2,
    )


if __name__ == "__main__":
    # MCPize (Cloud Run) starts this via startCommand type "http" and sets
    # $PORT: serve Streamable HTTP on that port there. The old stdio-only
    # entrypoint exited instantly in the container (no stdio client), which
    # is why the first MCPize deploy crashed on startup. Everywhere else
    # (local MCP clients, test_client.py) keep the stdio transport.
    _port = os.environ.get("PORT")
    if _port:
        mcp.settings.host = "0.0.0.0"
        mcp.settings.port = int(_port)
        # MCPize's bridge/discovery sends requests outside a persistent
        # session (its deploy-time discovery failed with "Session not
        # found" against the stateful session manager). Stateless mode
        # makes every request stand alone; tool behavior is unchanged.
        mcp.settings.stateless_http = True
        mcp.run(transport="streamable-http")
    else:
        mcp.run()
