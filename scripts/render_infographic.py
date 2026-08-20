#!/usr/bin/env python3
"""Render AuthGate README infographic charts into docs/figures/.

Run:  python scripts/render_infographic.py
Deps: matplotlib (dev machine / CI optional job).
"""
from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "figures"
OUT.mkdir(parents=True, exist_ok=True)

# Product palette — slate / teal / amber (avoid purple-on-white AI defaults)
SLATE = "#1e293b"
TEAL = "#0f766e"
AMBER = "#b45309"
STEEL = "#475569"
MUTED = "#94a3b8"
BG = "#f8fafc"
DENY = "#b91c1c"
PERMIT = "#047857"


def _style(ax) -> None:
    ax.set_facecolor(BG)
    for spine in ax.spines.values():
        spine.set_color(MUTED)
    ax.tick_params(colors=STEEL)
    ax.title.set_color(SLATE)


def chart_verification_stack() -> Path:
    """Bar chart: verification evidence by layer."""
    labels = ["Python\ntests", "Rust\nlib tests", "API +\nboundary", "Redteam\nsample", "TLC\nstates"]
    values = [1303, 293, 16, 42, 4227]
    colors = [TEAL, SLATE, AMBER, DENY, STEEL]

    fig, ax = plt.subplots(figsize=(9, 4.2), dpi=160)
    fig.patch.set_facecolor(BG)
    _style(ax)
    bars = ax.bar(labels, values, color=colors, width=0.65, edgecolor="white", linewidth=0.8)
    ax.set_ylabel("Count")
    ax.set_title("AuthGate — verification evidence (local green runs)")
    ax.set_yscale("log")
    for bar, v in zip(bars, values, strict=True):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() * 1.08,
            f"{v:,}",
            ha="center",
            va="bottom",
            fontsize=9,
            color=SLATE,
            fontweight="medium",
        )
    fig.tight_layout()
    path = OUT / "verification_stack.png"
    fig.savefig(path, bbox_inches="tight", facecolor=BG)
    plt.close(fig)
    return path


def chart_gate_pipeline() -> Path:
    """Horizontal pipeline: decision → gate → IO."""
    fig, ax = plt.subplots(figsize=(10, 2.8), dpi=160)
    fig.patch.set_facecolor(BG)
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 3)
    ax.axis("off")
    ax.set_title("Authority path — no proof, no execution", color=SLATE, pad=12)

    boxes = [
        (0.3, 1.0, 2.2, 1.2, "Decision\nmaker", STEEL),
        (3.0, 1.0, 2.4, 1.2, "CallGate\nverify + audit", TEAL),
        (6.0, 1.0, 2.2, 1.2, "IO / tool", SLATE),
    ]
    for x, y, w, h, text, color in boxes:
        ax.add_patch(
            FancyBboxPatch(
                (x, y),
                w,
                h,
                boxstyle="round,pad=0.04,rounding_size=0.15",
                linewidth=1.5,
                edgecolor=color,
                facecolor="white",
            )
        )
        ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", color=color, fontsize=11)

    ax.annotate("", xy=(2.95, 1.6), xytext=(2.55, 1.6), arrowprops=dict(arrowstyle="->", color=MUTED, lw=2))
    ax.annotate("", xy=(5.95, 1.6), xytext=(5.45, 1.6), arrowprops=dict(arrowstyle="->", color=MUTED, lw=2))

    ax.text(4.2, 0.35, "Permit → execute   ·   Deny → stop + hash-chained audit", ha="center", color=STEEL, fontsize=9)
    ax.text(4.2, 2.55, "Rust TCB is the security boundary · Python is compatibility", ha="center", color=AMBER, fontsize=9)

    path = OUT / "gate_pipeline.png"
    fig.savefig(path, bbox_inches="tight", facecolor=BG)
    plt.close(fig)
    return path


def chart_formal_coverage() -> Path:
    """Horizontal bars: formal methods status."""
    items = [
        ("TLC (bounded)", 1.0, "green"),
        ("Rust lib tests", 1.0, "green"),
        ("Kani harnesses", 0.85, "teal"),
        ("Lean theorems", 0.55, "amber"),
        ("Ed25519 HACL*/Fiat", 0.15, "deny"),
        ("Larger TLC + WF", 0.2, "deny"),
    ]
    color_map = {"green": PERMIT, "teal": TEAL, "amber": AMBER, "deny": DENY}

    fig, ax = plt.subplots(figsize=(8.5, 3.8), dpi=160)
    fig.patch.set_facecolor(BG)
    _style(ax)
    y = range(len(items))
    labels = [i[0] for i in items]
    vals = [i[1] for i in items]
    cols = [color_map[i[2]] for i in items]
    ax.barh(list(y), vals, color=cols, height=0.55, edgecolor="white")
    ax.set_yticks(list(y), labels)
    ax.set_xlim(0, 1.05)
    ax.set_xlabel("Completeness (honest scale — not a marketing score)")
    ax.set_title("Formal / evidence coverage")
    ax.invert_yaxis()
    fig.tight_layout()
    path = OUT / "formal_coverage.png"
    fig.savefig(path, bbox_inches="tight", facecolor=BG)
    plt.close(fig)
    return path


def chart_api_boundary() -> Path:
    """Simple breakdown of API surface roles."""
    labels = ["Admin\nmutate", "Delegate\nattenuate", "Verify\n(open to pod)", "Probes\n/metrics"]
    sizes = [25, 25, 35, 15]
    colors = [AMBER, TEAL, SLATE, MUTED]

    fig, ax = plt.subplots(figsize=(6.5, 4.2), dpi=160)
    fig.patch.set_facecolor(BG)
    wedges, texts, autotexts = ax.pie(
        sizes,
        labels=labels,
        colors=colors,
        autopct="%1.0f%%",
        startangle=90,
        wedgeprops=dict(width=0.45, edgecolor="white"),
        textprops=dict(color=SLATE, fontsize=9),
    )
    for t in autotexts:
        t.set_color("white")
        t.set_fontsize(8)
    ax.set_title("HTTP surface (infra-ready)")
    path = OUT / "api_surface.png"
    fig.savefig(path, bbox_inches="tight", facecolor=BG)
    plt.close(fig)
    return path


def main() -> None:
    paths = [
        chart_gate_pipeline(),
        chart_verification_stack(),
        chart_formal_coverage(),
        chart_api_boundary(),
    ]
    index = OUT / "README.md"
    index.write_text(
        "# AuthGate figures\n\n"
        "Generated by `python scripts/render_infographic.py`.\n\n"
        + "\n".join(f"- `{p.name}`" for p in paths)
        + "\n",
        encoding="utf-8",
    )
    for p in paths:
        print(str(p))


if __name__ == "__main__":
    main()
