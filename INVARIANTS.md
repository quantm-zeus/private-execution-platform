# Non-negotiable invariants

1. Sensitive signing key material is not stored on infrastructure we operate; signing is delegated to Privy.
2. Exact simulated NET balance delta is execution truth; displayed/raw quote is informational.
3. Limit fills never violate the user NET executable limit.
4. Tax/fees/gas/impact/slippage/MEV/failure risk are part of route economics.
5. FOMO and GMGN are reused through their existing services; no bypass clients.
6. Intelligence provider failure never disables exact local execution.
7. AI creates structured TradeIntent only; no generic signing/transfer surface.
8. Edge remains semantically opaque; browser uses own-domain private APIs only.
9. All write paths are idempotent; transaction timeout never causes blind retry.
10. TRADING_ENABLED=false stops execution while read-only intelligence remains available.
