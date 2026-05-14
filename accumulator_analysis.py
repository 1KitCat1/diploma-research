"""
Accumulator Comparison Analysis
================================
For master's thesis: "Anonymous Cross-Chain Proofs of Membership v2"

Compares cryptographic accumulators along the dimensions that matter for
anonymous proof-of-membership systems:

    - Inclusion proof size (bytes)
    - Witness update cost (operations on add/remove)
    - On-chain verification cost (EVM operations)
    - ZK-friendliness (constraints needed in a SNARK circuit)
    - Trusted setup requirement

Output:
    - accumulator_table.csv     (numerical data)
    - fig_proof_size.pdf/png    (Figure for paper)
    - fig_zk_constraints.pdf/png
"""

import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
import math

# ──────────────────────────────────────────────────────────────────
#  Theoretical models
# ──────────────────────────────────────────────────────────────────

def merkle_poseidon_proof_size(n):
    """Inclusion proof: ceil(log2 n) sibling hashes × 32 bytes (BN254 field)."""
    return math.ceil(math.log2(max(n, 2))) * 32

def merkle_keccak_proof_size(n):
    """Same depth but Keccak-friendly = 32-byte siblings + index path."""
    return math.ceil(math.log2(max(n, 2))) * 32 + 32

def verkle_proof_size(n, branching=256):
    """
    Verkle tree with KZG commitments.
    Depth = ceil(log_branching(n)). Single multiproof regardless of depth.
    Proof = 1 KZG opening proof (48 B BLS12-381 G1) + commitments along path.
    """
    depth = max(1, math.ceil(math.log(max(n, 2), branching)))
    # 48-byte commitment per level + single 48-byte opening proof
    return depth * 48 + 48

def rsa_accumulator_proof_size(n):
    """RSA accumulator: witness is single group element, ~3072-bit modulus = 384 B."""
    return 384  # constant, independent of n

def pairing_accumulator_proof_size(n):
    """BLS-based pairing accumulator (e.g., Nguyen 2005). G1 element = 48 B."""
    return 48  # constant

def merkle_zk_constraints(n):
    """Poseidon Merkle proof inside a Groth16 circuit.
    ~214 constraints per Poseidon hash × tree depth (from original 2023 paper, Table IV).
    """
    depth = math.ceil(math.log2(max(n, 2)))
    return depth * 214

def verkle_zk_constraints(n, branching=256):
    """KZG opening proof in-circuit: heavier per level (~2-pairing equiv ≈ 50k constraints
    when emulated, or far less if proof is verified outside SNARK and only commitment chain
    is in-circuit). Conservative emulated estimate.
    """
    depth = max(1, math.ceil(math.log(max(n, 2), branching)))
    return depth * 50_000  # KZG verify in-circuit is expensive

def rsa_zk_constraints(n):
    """RSA accumulator inside SNARK: single modular exp on ~3072 bit modulus.
    Empirically ~2-4M constraints per modular exp in BN254 SNARKs.
    """
    return 3_000_000  # roughly constant in n

def pairing_zk_constraints(n):
    """BLS pairing inside circuit: ~5-7M constraints per pairing op when emulated."""
    return 5_000_000

# ──────────────────────────────────────────────────────────────────
#  Static comparison table
# ──────────────────────────────────────────────────────────────────

ACCUMULATORS = [
    {
        "name":           "Merkle (Poseidon)",
        "proof_size_fn":  merkle_poseidon_proof_size,
        "zk_fn":          merkle_zk_constraints,
        "trusted_setup":  "No",
        "post_quantum":   "Yes (hash-based)",
        "update_cost":    "O(log n)",
        "non_membership": "Hard (sorted variant)",
        "evm_verify":     "O(log n) hashes",
    },
    {
        "name":           "Sparse Merkle (Poseidon)",
        "proof_size_fn":  merkle_poseidon_proof_size,
        "zk_fn":          merkle_zk_constraints,
        "trusted_setup":  "No",
        "post_quantum":   "Yes",
        "update_cost":    "O(log n)",
        "non_membership": "Native",
        "evm_verify":     "O(log n) hashes",
    },
    {
        "name":           "Merkle (Keccak256)",
        "proof_size_fn":  merkle_keccak_proof_size,
        "zk_fn":          lambda n: math.ceil(math.log2(max(n,2))) * 183_927,  # from Table IV of original paper
        "trusted_setup":  "No",
        "post_quantum":   "Yes",
        "update_cost":    "O(log n)",
        "non_membership": "Hard",
        "evm_verify":     "Native (cheap on EVM)",
    },
    {
        "name":           "Verkle Tree (KZG)",
        "proof_size_fn":  verkle_proof_size,
        "zk_fn":          verkle_zk_constraints,
        "trusted_setup":  "Yes (KZG SRS)",
        "post_quantum":   "No",
        "update_cost":    "O(log_b n) MSM",
        "non_membership": "Native",
        "evm_verify":     "1 pairing + scalar muls",
    },
    {
        "name":           "RSA Accumulator",
        "proof_size_fn":  rsa_accumulator_proof_size,
        "zk_fn":          rsa_zk_constraints,
        "trusted_setup":  "Yes (RSA modulus)",
        "post_quantum":   "No",
        "update_cost":    "O(1) mod-exp",
        "non_membership": "Native (Wesolowski)",
        "evm_verify":     "Mod-exp precompile",
    },
    {
        "name":           "Pairing-based (BLS)",
        "proof_size_fn":  pairing_accumulator_proof_size,
        "zk_fn":          pairing_zk_constraints,
        "trusted_setup":  "Yes (q-SDH SRS)",
        "post_quantum":   "No",
        "update_cost":    "O(1) for prover",
        "non_membership": "Native",
        "evm_verify":     "1 pairing",
    },
]


def build_static_table():
    """Static comparison at n = 2^20 ≈ 1M elements (matches original paper)."""
    n = 2**20
    rows = []
    for a in ACCUMULATORS:
        rows.append({
            "Accumulator":         a["name"],
            "Proof size (B)":      a["proof_size_fn"](n),
            "ZK constraints":      f"{a['zk_fn'](n):,}",
            "Trusted setup":       a["trusted_setup"],
            "Post-quantum":        a["post_quantum"],
            "Update cost":         a["update_cost"],
            "Non-membership":      a["non_membership"],
            "EVM verify":          a["evm_verify"],
        })
    return pd.DataFrame(rows)


def plot_proof_sizes():
    """Figure: proof size vs. set size n, log-log."""
    n_range = np.logspace(2, 9, 50, dtype=int)  # 100 → 1B elements

    fig, ax = plt.subplots(figsize=(7, 4.2))

    styles = {
        "Merkle (Poseidon)":        ("o-",  "#1f77b4"),
        "Verkle Tree (KZG)":        ("s-",  "#2ca02c"),
        "RSA Accumulator":          ("^-",  "#d62728"),
        "Pairing-based (BLS)":      ("D-",  "#9467bd"),
    }

    for a in ACCUMULATORS:
        if a["name"] not in styles:
            continue
        marker, color = styles[a["name"]]
        sizes = [a["proof_size_fn"](int(n)) for n in n_range]
        ax.plot(n_range, sizes, marker, color=color,
                label=a["name"], markersize=4, linewidth=1.2,
                markevery=6)

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Set size n (number of members)")
    ax.set_ylabel("Inclusion proof size (bytes)")
    ax.set_title("Inclusion Proof Size vs. Set Size, by Accumulator Type")
    ax.grid(True, which="both", linestyle=":", alpha=0.5)
    ax.legend(loc="upper left", fontsize=9, framealpha=0.95)
    plt.tight_layout()

    fig.savefig("/mnt/user-data/outputs/fig_proof_size.pdf", dpi=300, bbox_inches="tight")
    fig.savefig("/mnt/user-data/outputs/fig_proof_size.png", dpi=200, bbox_inches="tight")
    plt.close(fig)
    return n_range


def plot_zk_constraints():
    """Figure: in-circuit constraint cost vs. set size."""
    n_range = np.logspace(2, 9, 50, dtype=int)

    fig, ax = plt.subplots(figsize=(7, 4.2))

    styles = {
        "Merkle (Poseidon)":   ("o-",  "#1f77b4"),
        "Merkle (Keccak256)":  ("v--", "#ff7f0e"),
        "Verkle Tree (KZG)":   ("s-",  "#2ca02c"),
        "RSA Accumulator":     ("^-",  "#d62728"),
        "Pairing-based (BLS)": ("D-",  "#9467bd"),
    }

    for a in ACCUMULATORS:
        if a["name"] not in styles:
            continue
        marker, color = styles[a["name"]]
        c = [a["zk_fn"](int(n)) for n in n_range]
        ax.plot(n_range, c, marker, color=color, label=a["name"],
                markersize=4, linewidth=1.2, markevery=6)

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Set size n (number of members)")
    ax.set_ylabel("R1CS constraints for inclusion proof in-circuit")
    ax.set_title("ZK Circuit Cost of Inclusion Proof, by Accumulator Type")
    ax.grid(True, which="both", linestyle=":", alpha=0.5)
    ax.legend(loc="upper left", fontsize=9, framealpha=0.95)
    plt.tight_layout()

    fig.savefig("/mnt/user-data/outputs/fig_zk_constraints.pdf", dpi=300, bbox_inches="tight")
    fig.savefig("/mnt/user-data/outputs/fig_zk_constraints.png", dpi=200, bbox_inches="tight")
    plt.close(fig)


# ──────────────────────────────────────────────────────────────────
#  Main
# ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 70)
    print(" Accumulator Comparison — at n = 2^20 (≈1M members)")
    print("=" * 70)

    df = build_static_table()
    print()
    print(df.to_string(index=False))
    print()

    df.to_csv("/mnt/user-data/outputs/accumulator_table.csv", index=False)
    print("✓ accumulator_table.csv saved")

    plot_proof_sizes()
    print("✓ fig_proof_size.pdf / .png saved")

    plot_zk_constraints()
    print("✓ fig_zk_constraints.pdf / .png saved")

    # Concrete numbers for paper at multiple n
    print()
    print("─" * 70)
    print(" Proof size (bytes) at several scales — for Table in paper")
    print("─" * 70)
    for n in [2**10, 2**16, 2**20, 2**25, 2**30]:
        print(f"\nn = 2^{int(math.log2(n))}  ({n:,} members)")
        for a in ACCUMULATORS:
            print(f"  {a['name']:<28s} : {a['proof_size_fn'](n):>6} B")
