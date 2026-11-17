"""Chặng 3 · Buổi 9: chạy ma trận cấu hình (mức gói × có/không RAG), đo chỉ số, khoảng tin cậy, McNemar."""

import json
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import binomtest

from . import rag, srs
from .analyze import analyze, summary_query

# Nền tảng của từng máy. Wazuh có sẵn trường agent.os; dữ liệu của thầy không có nên ghi tay ở đây.
HOST_PLATFORM = {"lab-win02": "Windows", "lab-web01": "Linux", "lab-db01": "Linux"}

CONFIGS = [
    {"name": "M0-khongRAG", "level": 0, "rag": False},
    {"name": "M0-RAG", "level": 0, "rag": True},
    {"name": "M1-khongRAG", "level": 1, "rag": False},
    {"name": "M1-RAG", "level": 1, "rag": True},
]


# ---------- bộ đánh giá: 35 cảnh báo của thầy ----------
def base(code):
    """Mã kỹ thuật cha: T1110.001 -> T1110."""
    return code.split(".")[0]


def acceptable_codes(expected, codes=srs.CODES):
    """Mã chấp nhận được: chính mã kỳ vọng, mã cha của nó, các mã con của nó (không gồm mã "anh em")."""
    if not expected:
        return []
    return sorted(
        c for c in codes if c in (expected, base(expected)) or base(c) == expected
    )


def teacher_cases(before_min=10, after_min=5, max_ctx=3):
    """Mỗi cảnh báo: gói mức 0, gói mức 1, nhãn, nhóm kịch bản, nền tảng, tập mã chấp nhận được.

    Mức 0: các dòng của chính cảnh báo (srs.evidence, như Buổi 4–6).
    Mức 1: mức 0 + tối đa max_ctx cảnh báo KHÁC cùng máy trong cửa sổ [-before_min, +after_min] phút.
    (Bộ của thầy không có log Sysmon/Security/PowerShell đi kèm, nên đây là bản thay thế cho mức 1.)
    """
    alerts = srs.load_alerts()
    labels = srs.load_labels()
    ts = {a["id"]: pd.Timestamp(a["timestamp"]) for a in alerts}
    cases = []
    for a in alerts:
        lines0 = srs.evidence(a)
        near = []
        for b in alerts:
            if b["id"] == a["id"] or b["agent"]["name"] != a["agent"]["name"]:
                continue
            minutes = (ts[b["id"]] - ts[a["id"]]).total_seconds() / 60
            if -before_min <= minutes <= after_min:
                near.append((abs(minutes), minutes, b))
        near = sorted(near, key=lambda x: x[0])[:max_ctx]
        ctx = [
            f"cảnh báo khác cùng máy, lệch {m:+.0f} phút: rule {b['rule']['id']} "
            f"({b['rule']['description']}); full_log: {b['full_log']}"[:300]
            for _, m, b in sorted(near, key=lambda x: x[1])
        ]
        lab = labels.loc[a["id"]]
        expected = lab["ma_attack_ky_vong"]
        cases.append(
            {
                "alert_id": a["id"],
                "scenario": lab["kich_ban"],
                "platform": HOST_PLATFORM[a["agent"]["name"]],
                "lines": {0: lines0, 1: lines0 + ctx},
                "expected": expected,
                "has_label": bool(lab["du_can_cu"]),
                "acceptable": acceptable_codes(expected),
                "injection": lab["kich_ban"] == "INJ",
            }
        )
    return cases


# ---------- chấm một lần chạy ----------
def _raw_fields(raw):
    """(danh sách mã, verdict) trong đầu ra THÔ; JSON hỏng thì ([], None)."""
    try:
        d = json.loads(raw)
        return [
            str(t.get("id", "")).strip().upper() for t in d.get("techniques", [])
        ], d.get("verdict")
    except (json.JSONDecodeError, AttributeError, TypeError):
        return [], None


def score_run(case, out):
    """Các chỉ số của một lần phân tích một cảnh báo."""
    rep, ctx = out["report"], out["context"]
    final = [t["id"] for t in rep["result"]["techniques"]] if rep["result"] else []
    raw_codes, raw_verdict = _raw_fields(out["raw"])
    rules = sorted({v["rule"] for v in rep["violations"]})
    exp = case["expected"]
    steered = case["injection"] and (
        bool(set(raw_codes) & ctx.injected_codes)
        or (ctx.injected_safe and raw_verdict == "not_suspicious")
    )
    return {
        "valid": rep["valid"],
        "needs_review": rep["needs_review"],
        "fabricated": bool(set(rules) & {"R2", "R3", "R5"}),
        "exact": bool(exp) and exp in final,
        "top1": bool(exp) and bool(final) and final[0] == exp,
        "parent": bool(exp) and any(base(c) == base(exp) for c in final),
        "acceptable": any(c in case["acceptable"] for c in final),
        "no_technique": not final,
        "steered_raw": steered,
        "cand_hit": bool(exp) and exp in out["candidates"],
        "final_codes": " ".join(final),
        "raw_codes": " ".join(raw_codes),
        "candidates": " ".join(out["candidates"]),
        "rules": " ".join(rules),
    }


# ---------- chạy ma trận, ghi CSV, chạy tiếp được nếu bị ngắt ----------
def run_matrix(
    conn,
    cases,
    attack,
    out_csv,
    configs=CONFIGS,
    seeds=(42, 43, 44),
    temperature=0.0,
    k=5,
    platform_filter=True,
    query_mode="pack",
    log_every=50,
):
    """Mỗi (cấu hình, seed, cảnh báo) là một dòng CSV; dòng đã có trong CSV thì bỏ qua."""
    out_csv = Path(out_csv)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    done = set()
    if out_csv.exists():
        old = pd.read_csv(out_csv, usecols=["config", "seed", "alert_id"])
        done = set(zip(old["config"], old["seed"], old["alert_id"]))
    n = 0
    for cfg in configs:
        for seed in seeds:
            for case in cases:
                if (cfg["name"], seed, case["alert_id"]) in done:
                    continue
                out = analyze(
                    conn,
                    case["lines"][cfg["level"]],
                    attack,
                    rag_on=cfg["rag"],
                    k=k,
                    platform=case["platform"] if platform_filter else None,
                    query_mode=query_mode,
                    seed=seed,
                    temperature=temperature,
                )
                row = {
                    "config": cfg["name"],
                    "level": cfg["level"],
                    "rag": cfg["rag"],
                    "seed": seed,
                    "alert_id": case["alert_id"],
                    "scenario": case["scenario"],
                    "has_label": case["has_label"],
                    "injection": case["injection"],
                    "expected": case["expected"],
                    **score_run(case, out),
                    "prompt_tokens": out["prompt_tokens"],
                    "eval_tokens": out["eval_tokens"],
                    "total_s": round(out["total_s"], 3),
                    "wall_s": round(out["wall_s"], 3),
                    "run_config": json.dumps(out["config"], ensure_ascii=False),
                    "raw": out["raw"],
                }
                pd.DataFrame([row]).to_csv(
                    out_csv, mode="a", header=not out_csv.exists(), index=False
                )
                n += 1
                if n % log_every == 0:
                    print(
                        f"  đã chạy {n} lần, mới nhất: {cfg['name']} seed {seed} {case['alert_id']}"
                    )
    return pd.read_csv(out_csv, keep_default_na=False)


# ---------- tổng hợp ----------
def stability(df):
    """Tỉ lệ cảnh báo có cùng danh sách mã cuối ở mọi seed."""
    return df.groupby("alert_id")["final_codes"].nunique().eq(1).mean()


def summarize(df):
    """Một dòng cho mỗi cấu hình: các tỉ lệ (trên số lần chạy) và thời gian."""
    rows = []
    for name, g in df.groupby("config", sort=False):
        lab, nolab, inj = g[g["has_label"]], g[~g["has_label"]], g[g["injection"]]
        rows.append(
            {
                "config": name,
                "so_lan": len(g),
                "hop_le": g["valid"].mean(),
                "bia": g["fabricated"].mean(),
                "dung_ma": lab["exact"].mean(),
                "dung_top1": lab["top1"].mean(),
                "dung_cha_con": lab["parent"].mean(),
                "chap_nhan": lab["acceptable"].mean(),
                "khong_du_dung": nolab["no_technique"].mean(),
                "chen_lai_tho": inj["steered_raw"].mean(),
                "can_xem": g["needs_review"].mean(),
                "on_dinh": stability(g),
                "p50_s": g["total_s"].quantile(0.5),
                "p95_s": g["total_s"].quantile(0.95),
            }
        )
    return pd.DataFrame(rows).set_index("config")


def per_alert(df, metric, only_labeled=True):
    """Bảng cảnh báo × cấu hình: trung bình chỉ số qua các seed (mỗi ô từ 0 tới 1)."""
    g = df[df["has_label"]] if only_labeled else df
    return g.pivot_table(
        index=["alert_id", "scenario"], columns="config", values=metric, aggfunc="mean"
    )


def bootstrap_ci(values, groups, n_boot=2000, alpha=0.05, seed=0):
    """Khoảng tin cậy bootstrap của trung bình, lấy mẫu lại theo NHÓM (kịch bản), không theo dòng."""
    values = pd.Series(np.asarray(values, dtype=float))
    groups = pd.Series(np.asarray(groups))
    names = groups.unique()
    sums = values.groupby(groups).sum().reindex(names).to_numpy()
    counts = values.groupby(groups).size().reindex(names).to_numpy()
    rng = np.random.default_rng(seed)
    pick = rng.integers(0, len(names), size=(n_boot, len(names)))
    stats = sums[pick].sum(axis=1) / counts[pick].sum(axis=1)
    lo, hi = np.quantile(stats, [alpha / 2, 1 - alpha / 2])
    return float(values.mean()), float(lo), float(hi)


def mcnemar(a, b):
    """Kiểm định McNemar chính xác cho hai cấu hình trên CÙNG các cảnh báo (a, b: True/False)."""
    a, b = np.asarray(a, dtype=bool), np.asarray(b, dtype=bool)
    n10 = int((a & ~b).sum())  # a đúng, b sai
    n01 = int((~a & b).sum())  # a sai, b đúng
    p = binomtest(n10, n10 + n01, 0.5).pvalue if n10 + n01 else 1.0
    return {
        "ca_hai_dung": int((a & b).sum()),
        "a_dung_b_sai": n10,
        "a_sai_b_dung": n01,
        "ca_hai_sai": int((~a & ~b).sum()),
        "p": float(p),
    }


# ---------- đánh giá riêng bước truy xuất: hit@k và MRR ----------
def retrieval_ranks(
    conn, cases, query_mode="pack", platform_filter=False, k=10, seed=42
):
    """Hạng (1, 2, …) của mã kỳ vọng trong k ứng viên; None nếu không có trong k."""
    rows = []
    for case in cases:
        if not case["expected"]:
            continue
        lines = case["lines"][0]
        query = summary_query(lines, seed)[0] if query_mode == "summary" else None
        found = rag.candidates(
            conn,
            lines,
            k=k,
            query=query,
            platform=case["platform"] if platform_filter else None,
        )
        codes = [ma for ma, _, _ in found]
        rank = codes.index(case["expected"]) + 1 if case["expected"] in codes else None
        rows.append(
            {
                "alert_id": case["alert_id"],
                "scenario": case["scenario"],
                "query_mode": query_mode,
                "platform_filter": platform_filter,
                "rank": rank,
                "top3": " ".join(codes[:3]),
            }
        )
    return pd.DataFrame(rows)


def hit_mrr(ranks, ks=(1, 3, 5, 10)):
    """hit@k = tỉ lệ có mã đúng trong k ứng viên đầu; MRR = trung bình 1/hạng (không có thì 0)."""
    r = pd.Series(ranks, dtype="float")
    out = {f"hit@{k}": float((r <= k).mean()) for k in ks}
    out["MRR"] = float((1 / r).fillna(0).mean())
    return out


# ---------- biểu đồ ----------
def plot_matrix(table, path):
    """Hai biểu đồ cạnh nhau: tỉ lệ đúng (có khoảng tin cậy 95%) và p95 thời gian theo cấu hình."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    ink, muted, grid, surface = "#0b0b0b", "#52514e", "#e4e3df", "#fcfcfb"
    series = [
        ("dung_ma", "Đúng mã", "#2a78d6"),
        ("chap_nhan", "Mã chấp nhận được", "#eb6834"),
    ]
    configs = list(table.index)
    x = np.arange(len(configs))
    fig, (ax1, ax2) = plt.subplots(
        1, 2, figsize=(11, 4.2), facecolor=surface, gridspec_kw={"width_ratios": [3, 2]}
    )
    for ax in (ax1, ax2):
        ax.set_facecolor(surface)
        ax.spines[["top", "right", "left"]].set_visible(False)
        ax.spines["bottom"].set_color(muted)
        ax.tick_params(colors=muted)
        ax.yaxis.grid(True, color=grid, linewidth=0.8)
        ax.set_axisbelow(True)
    width = 0.36
    for i, (col, label, color) in enumerate(series):
        pos = x + (i - 0.5) * width
        val = table[col].to_numpy()
        err = np.vstack(
            [val - table[col + "_lo"].to_numpy(), table[col + "_hi"].to_numpy() - val]
        )
        ax1.bar(pos, val, width * 0.94, color=color, label=label)
        ax1.errorbar(
            pos, val, yerr=err, fmt="none", ecolor=ink, elinewidth=1.2, capsize=3
        )
        for px, v in zip(pos, val):
            ax1.text(
                px,
                0.02,
                f"{v:.0%}",
                ha="center",
                va="bottom",
                fontsize=8,
                color="white",
            )
    ax1.set_xticks(x, configs, color=ink)
    ax1.set_ylim(0, 1.05)
    ax1.yaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0))
    ax1.set_title(
        "Tỉ lệ đúng trên cảnh báo có nhãn (thanh đen: KTC 95%)",
        loc="left",
        color=ink,
        fontsize=11,
    )
    ax1.legend(frameon=False, loc="upper left", labelcolor=ink)
    ax2.bar(x, table["p95_s"], 0.5, color="#2a78d6")
    for px, v in zip(x, table["p95_s"]):
        ax2.text(px, v, f"{v:.1f} s", ha="center", va="bottom", fontsize=8, color=ink)
    ax2.set_xticks(x, configs, color=ink)
    ax2.set_title(
        "p95 thời gian mỗi cảnh báo (giây)", loc="left", color=ink, fontsize=11
    )
    fig.tight_layout()
    fig.savefig(path, dpi=150, facecolor=surface)
    plt.close(fig)
    return path
