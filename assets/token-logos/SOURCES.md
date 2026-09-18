# Token logo sources and attribution

These are the **real brand marks** for the eleven instruments in the embedded
market snapshot. They are used by `evercrest-terminal.html` (embedded as data
URIs so the artifact stays self-contained) and are the project-local source of
truth for the application.

## Source

All eleven were fetched from the **Trust Wallet assets** repository, which keys
every image by chain + **exact contract address**. That keying is the reason this
source was chosen: it makes a wrong-token look-alike structurally impossible, and
it matches the design's own rule that token identity is `chain + address`, never
`symbol` or `name`.

- Repository: https://github.com/trustwallet/assets
- Path pattern: `blockchains/<chain>/assets/<contract-address>/logo.png`
- License: **MIT** (Copyright © 2019–2023 Trust Wallet) —
  https://github.com/trustwallet/assets/blob/master/LICENSE
- Retrieved: 2026-09-18

## Manifest

Every row records the exact address the image was fetched for. Verify a row by
re-fetching the URL and confirming the address segment matches `assets/market-snapshot.json`.

| File | Symbol | Chain | Contract address | Source path |
|---|---|---|---|---|
| `SOL.png` | SOL | solana | `So11111111111111111111111111111111111111112` | `blockchains/solana/assets/So11111111111111111111111111111111111111112/logo.png` |
| `WIF.png` | WIF | solana | `EKpQGSJtjMFqKZ9KQanSqYXRcF8fBopzLHYxdM65zcjm` | `blockchains/solana/assets/EKpQGSJtjMFqKZ9KQanSqYXRcF8fBopzLHYxdM65zcjm/logo.png` |
| `BONK.png` | BONK | solana | `DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263` | `blockchains/solana/assets/DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263/logo.png` |
| `JUP.png` | JUP | solana | `JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN` | `blockchains/solana/assets/JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN/logo.png` |
| `RAY.png` | RAY | solana | `4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R` | `blockchains/solana/assets/4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R/logo.png` |
| `PYTH.png` | PYTH | solana | `HZ1JovNiVvGrGNiiYvEozEVgZ58xaU3RKwX8eACQBCt3` | `blockchains/solana/assets/HZ1JovNiVvGrGNiiYvEozEVgZ58xaU3RKwX8eACQBCt3/logo.png` |
| `AERO.png` | AERO | base | `0x940181a94A35A4569E4529A3CDfB74e38FD98631` | `blockchains/base/assets/0x940181a94A35A4569E4529A3CDfB74e38FD98631/logo.png` |
| `VIRTUAL.png` | VIRTUAL | base | `0x0b3e328455c4059EEb9e3f84b5543F74E24e7E1b` | `blockchains/base/assets/0x0b3e328455c4059EEb9e3f84b5543F74E24e7E1b/logo.png` |
| `BNB.png` | BNB | bnb_chain | `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c` | `blockchains/smartchain/assets/0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c/logo.png` |
| `ETH.png` | ETH | ethereum | `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2` | `blockchains/ethereum/assets/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2/logo.png` |
| `PEPE.png` | PEPE | ethereum | `0x6982508145454Ce325dDbE47a25d4ec3d2311933` | `blockchains/ethereum/assets/0x6982508145454Ce325dDbE47a25d4ec3d2311933/logo.png` |

Note that `SOL`, `BNB` and `ETH` are the **wrapped** variants (`So111…112`,
`0xbb4C…95c`, `0xC02a…6Cc2`), which is correct: those are the exact addresses the
market snapshot carries, and the address-keyed source returns the matching mark.

## Processing

Originals are 192×192 or 256×256. Each was downscaled to **64×64** with a box
filter (alpha-premultiplied, so soft edges do not darken) and re-encoded as
8-bit RGBA PNG. Nothing else was altered: no recolouring, no cropping, no
redrawing. Total payload fell from 355 KB to 80 KB.

## Verification performed

Because a wrong-token mark is a factual error, each image was checked two ways
before use:

1. **Provenance** — the fetch URL's address segment was compared against the
   address in `assets/market-snapshot.json`. All eleven matched exactly.
2. **Referent** — the dominant hue family of each decoded image was compared with
   the token's known brand colour. Confirmations: BNB `yellow 84%`, PEPE
   `green 82%`, BONK `orange 67% + yellow 23%`, WIF `orange/tan 56%` (a
   photographic dog image), JUP/Raydium/Pyth all dark-dominant with the expected
   accent. `SOL`, `AERO`, `ETH` and `VIRTUAL` are neutral- or light-dominant,
   which is consistent with their monochrome and light-background marks.

## Background handling (a design constraint, not an image defect)

The marks do not share a background convention, and this is why the design
normalises them into a **mark tile** rather than dropping them raw onto the
canvas:

| Background | Symbols |
|---|---|
| Transparent | BNB, ETH |
| Dark, close to the Deep Vault surface ladder | SOL `(17,24,32)`, JUP `(17,23,39)`, RAY `(12,21,48)`, PYTH `(17,15,36)` |
| Saturated full-bleed | BONK `(230,155,21)`, PEPE `(31,121,22)` |
| Light / photographic | WIF `(152,131,112)`, AERO `(224,217,216)`, VIRTUAL `(207,240,222)` |

A 32 px tile with `--radius-sm`, a 1 px `--line` border, and `object-fit: cover`
gives every mark the same hard edge and the same framing regardless of what its
own background does — see `DESIGN.md` §5.7. `contain` was rejected: it leaves a
visible ring of tile tone around light-background marks and around transparent
ones, which reads as an inconsistent asset set rather than a deliberate tile.
