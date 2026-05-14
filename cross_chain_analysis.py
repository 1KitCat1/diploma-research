"""
Cross-Chain Verification Cost Analysis
========================================
For master's thesis: "Anonymous Cross-Chain Proofs of Membership v2"

Models the USD cost of verifying a zero-knowledge proof of membership across
different chains, accounting for:
    - Gas units consumed (from the calibrated zk_scheme_analysis.py model)
    - Native gas price (gwei or equivalent)
    - L2 data-availability cost (L1 calldata posting fee)
    - Native token / USD exchange rate

Chains modelled (data approximate, snapshot Q1 2026):
    - Ethereum mainnet
    - Polygon PoS
    - Arbitrum One   (optimistic rollup)
    - Optimism       (optimistic rollup)
    - Base           (optimistic rollup)
    - zkSync Era     (validity rollup)
    - Polygon zkEVM
    - BNB Chain
    - Avalanche C-Chain

Output:
    - cross_chain_costs.csv
    - fig_cross_chain.pdf/png
"""

import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
import math

# ──────────────────────────────────────────────────────────────────
#  Chain models
# ──────────────────────────────────────────────────────────────────
# Each entry includes:
#   gas_price_gwei   : typical gas price in native token
#   native_usd       : USD value of native token
#   da_cost_per_byte : USD cost of posting 1 byte to L1 (rollups only, else 0)
#   gas_multiplier   : adjustment for chains where the EVM bn254 precompiles
#                      have non-standard pricing (e.g. some L2s)
#
# All numbers approximate and meant for relative comparison only.

CHAINS = [
    {
        "name":            "Ethereum L1",
        "type":            "L1",
        "gas_price_gwei":  20.0,
        "native_usd":      3500.0,
        "da_cost_per_byte": 0.0,
        "gas_multiplier":  1.0,
    },
    {
        "name":            "Polygon PoS",
        "type":            "L1",
        "gas_price_gwei":  60.0,
        "native_usd":      0.40,
        "da_cost_per_byte": 0.0,
        "gas_multiplier":  1.0,
    },
    {
        "name":            "BNB Chain",
        "type":            "L1",
        "gas_price_gwei":  3.0,
        "native_usd":      650.0,
        "da_cost_per_byte": 0.0,
        "gas_multiplier":  1.0,
    },
    {
        "name":            "Avalanche C",
        "type":            "L1",
        "gas_price_gwei":  25.0,
        "native_usd":      35.0,
        "da_cost_per_byte": 0.0,
        "gas_multiplier":  1.0,
    },
    {
        "name":            "Arbitrum One",
        "type":            "L2-OR",
        "gas_price_gwei":  0.1,
        "native_usd":      3500.0,
        "da_cost_per_byte": 0.000015,    # post-EIP-4844 blob storage cost
        "gas_multiplier":  1.0,
    },
    {
        "name":            "Optimism",
        "type":            "L2-OR",
        "gas_price_gwei":  0.05,
        "native_usd":      3500.0,
        "da_cost_per_byte": 0.000015,
        "gas_multiplier":  1.0,
    },
    {
        "name":            "Base",
        "type":            "L2-OR",
        "gas_price_gwei":  0.04,
        "native_usd":      3500.0,
        "da_cost_per_byte": 0.000010,
        "gas_multiplier":  1.0,
    },
    {
        "name":            "zkSync Era",
        "type":            "L2-ZK",
        "gas_price_gwei":  0.25,
        "native_usd":      3500.0,
        "da_cost_per_byte": 0.000010,
        "gas_multiplier":  1.5,        # zkSync charges more per pairing
    },
    {
        "name":            "Polygon zkEVM",
        "type":            "L2-ZK",
        "gas_price_gwei":  0.5,
        "native_usd":      3500.0,
        "da_cost_per_byte": 0.000010,
        "gas_multiplier":  1.0,
    },
]

# ──────────────────────────────────────────────────────────────────
#  Schemes (proof size, gas) — re-used from the calibrated zk_scheme_analysis
# ──────────────────────────────────────────────────────────────────

SCHEMES = [
    {"name": "Groth16",      "gas": 263_000,   "proof_size": 192},
    {"name": "PLONK",        "gas": 380_000,   "proof_size": 480},
    {"name": "Halo2",        "gas": 600_000,   "proof_size": 1500},
    {"name": "Bulletproofs", "gas": 1_410_000, "proof_size": 1584},
    {"name": "zk-STARK",     "gas": 2_256_000, "proof_size": 84_747},
]


# ──────────────────────────────────────────────────────────────────
#  Cost calculation
# ──────────────────────────────────────────────────────────────────

def verification_cost_usd(chain, scheme):
    """Computes (gas_cost_native, da_cost_native, total_usd, gas_used_eff)."""
    gas_used = scheme["gas"] * chain["gas_multiplier"]
    gas_price_native = chain["gas_price_gwei"] * 1e-9            # native units per gas
    gas_cost_native  = gas_used * gas_price_native
    gas_cost_usd     = gas_cost_native * chain["native_usd"]

    da_cost_usd = scheme["proof_size"] * chain["da_cost_per_byte"]

    total_usd = gas_cost_usd + da_cost_usd
    return gas_used, gas_cost_usd, da_cost_usd, total_usd


def build_cost_matrix():
    rows = []
    for chain in CHAINS:
        for scheme in SCHEMES:
            gas_used, gas_usd, da_usd, total_usd = verification_cost_usd(chain, scheme)
            rows.append({
                "Chain":          chain["name"],
                "Type":           chain["type"],
                "Scheme":         scheme["name"],
                "Gas used":       int(gas_used),
                "Gas cost (USD)": round(gas_usd, 6),
                "DA cost (USD)":  round(da_usd, 6),
                "Total (USD)":    round(total_usd, 6),
            })
    return pd.DataFrame(rows)


def plot_cost_heatmap(df):
    """Stacked horizontal bar: per-chain breakdown across schemes."""
    pivot = df.pivot(index="Chain", columns="Scheme", values="Total (USD)")
    # preserve chain ordering
    pivot = pivot.loc[[c["name"] for c in CHAINS]]

    fig, ax = plt.subplots(figsize=(8, 5.5))
    pivot.plot(kind="barh", ax=ax,
               color=["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd"],
               edgecolor="black", linewidth=0.4, width=0.78)
    ax.set_xlabel("Verification cost (USD per proof)")
    ax.set_xscale("log")
    ax.set_title("Cross-Chain Verification Cost by ZK Scheme")
    ax.legend(title="Scheme", loc="lower right", fontsize=9)
    ax.grid(True, axis="x", which="both", linestyle=":", alpha=0.5)
    ax.invert_yaxis()
    plt.tight_layout()

    fig.savefig("/mnt/user-data/outputs/fig_cross_chain.pdf", dpi=300, bbox_inches="tight")
    fig.savefig("/mnt/user-data/outputs/fig_cross_chain.png", dpi=200, bbox_inches="tight")
    plt.close(fig)


def plot_cheapest_paths():
    """For each scheme, show the 3 cheapest chains."""
    df = build_cost_matrix()
    fig, axes = plt.subplots(1, 5, figsize=(14, 3.6), sharey=True)

    for ax, scheme in zip(axes, SCHEMES):
        sub = df[df["Scheme"] == scheme["name"]].nsmallest(3, "Total (USD)")
        ax.bar(sub["Chain"], sub["Total (USD)"],
               color="#1f77b4", edgecolor="black", linewidth=0.6)
        for i, (_, row) in enumerate(sub.iterrows()):
            ax.text(i, row["Total (USD)"] * 1.05,
                    f"${row['Total (USD)']:.4f}",
                    ha="center", fontsize=7)
        ax.set_title(scheme["name"], fontsize=10)
        ax.tick_params(axis="x", rotation=30)
        ax.set_yscale("log")
        ax.grid(True, axis="y", linestyle=":", alpha=0.5)

    axes[0].set_ylabel("Cost per verification (USD)")
    fig.suptitle("Three Cheapest Chains for Each ZK Scheme", fontsize=12)
    plt.tight_layout()
    fig.savefig("/mnt/user-data/outputs/fig_cheapest_chains.pdf", dpi=300, bbox_inches="tight")
    fig.savefig("/mnt/user-data/outputs/fig_cheapest_chains.png", dpi=200, bbox_inches="tight")
    plt.close(fig)


# ──────────────────────────────────────────────────────────────────
#  Main
# ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 70)
    print(" Cross-Chain Verification Cost Analysis")
    print(" (assumes calibrated ZK gas model from zk_scheme_analysis.py)")
    print("=" * 70)

    df = build_cost_matrix()
    df.to_csv("/mnt/user-data/outputs/cross_chain_costs.csv", index=False)
    print(f"\n✓ {len(df)} chain×scheme entries → cross_chain_costs.csv")

    # Pivot view for paper Table
    pivot = df.pivot(index="Chain", columns="Scheme", values="Total (USD)")
    pivot = pivot.loc[[c["name"] for c in CHAINS]]
    print("\n──── Verification cost (USD per proof) ────")
    print(pivot.round(5).to_string())

    plot_cost_heatmap(df)
    print("\n✓ fig_cross_chain.pdf / .png saved")

    plot_cheapest_paths()
    print("✓ fig_cheapest_chains.pdf / .png saved")

    # Spotlights for paper narrative
    print("\n─" * 35)
    print(" Notable findings for paper:")
    print("─" * 70)
    cheapest = df.loc[df["Total (USD)"].idxmin()]
    most_exp = df.loc[df["Total (USD)"].idxmax()]
    print(f"  Cheapest combination : {cheapest['Scheme']:>13s} on {cheapest['Chain']:<14s} = "
          f"${cheapest['Total (USD)']:.6f}")
    print(f"  Most expensive       : {most_exp['Scheme']:>13s} on {most_exp['Chain']:<14s} = "
          f"${most_exp['Total (USD)']:.4f}")
    print(f"  Cost ratio (max/min) : {most_exp['Total (USD)'] / cheapest['Total (USD)']:,.0f}×")

    # Per-scheme cheapest chain
    print()
    print("  Cheapest chain for each scheme:")
    for scheme in SCHEMES:
        sub = df[df["Scheme"] == scheme["name"]]
        best = sub.loc[sub["Total (USD)"].idxmin()]
        print(f"    {scheme['name']:<15s} → {best['Chain']:<15s} (${best['Total (USD)']:.6f})")
