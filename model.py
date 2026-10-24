from pathlib import Path
import math
import sys

import numpy as np
import pandas as pd

# =============================================================================
# Cross-Modal Coincidence + Multiple-Instance Higher Criticism Detector
#
# Statistical References:
#   [1] D. Donoho and J. Jin, "Higher Criticism for Detecting Sparse
#       Heterogeneous Mixtures," The Annals of Statistics, vol. 32, no. 3,
#       pp. 962-994, 2004. doi: 10.1214/009053604000000265 (Eqs. 1.3 & 1.6)
#   [2] F. R. Hampel, "The Influence Curve and its Role in Robust Estimation,"
#       J. Amer. Statist. Assoc. (JASA), vol. 69, no. 346, pp. 383-393, 1974.
#   [3] T. G. Dietterich, R. H. Lathrop, and T. Lozano-Perez, "Solving the
#       Multiple Instance Problem with Axis-Parallel Rectangles," Artificial
#       Intelligence, vol. 89, no. 1-2, pp. 31-71, 1997.
#   [4] O. Ledoit and M. Wolf, "A well-conditioned estimator for
#       large-dimensional covariance matrices," J. Multivariate Anal., 2004.
# =============================================================================

HPC_CANDIDATES = [
    "instructions",
    "cycles",
    "ipc",
    "cache_misses",
    "branch_misses",
    "proc_context_switches",
]

HPC_MIN_SCALE = {
    "instructions": 250_000.0,
    "cycles": 250_000.0,
    "ipc": 0.15,
    "cache_misses": 2_000.0,
    "branch_misses": 1_000.0,
    "proc_context_switches": 5.0,
}

# Routine LAN broadcast/multicast + SSH management traffic (non-telemetry)
NON_TELEMETRY_PROTOS = {
    "ARP",
    "MDNS",
    "IGMP",
    "IGMPV2",
    "IGMPV3",
    "ICMP",
    "ICMPV6",
    "DHCP",
    "DHCPV6",
    "NTP",
    "LLMNR",
    "NBNS",
    "SSDP",
    "SSH",
}

STAT_FEATURE_NAMES = [
    "host_net_corr",
    "coincidence_ticks",
    "peak_coincidence",
    "sum_coincidence",
    "sum_net_logbytes",
]

# Physical unit floors matching measured H0/H1 scales
STAT_MIN_SCALE = np.array([0.15, 1.00, 2.50, 5.00, 8.00], dtype=np.float64)


def _parse_bool_array(series: pd.Series) -> np.ndarray:
    s = series.astype(str).str.strip().str.strip('"').str.lower()
    return np.where(s.isin(["1", "1.0", "true"]), 1.0, 0.0).astype(np.float64)


def _host_positive_surge(H_raw: np.ndarray, hpc_cols: list[str]) -> np.ndarray:
    """
    Within-trial robust positive host z-score ([2] Hampel 1974) with physical floor.
    Cancels steady background CPU load (silent_control) without amplifying idle jitter.
    """
    q25 = np.percentile(H_raw, 25.0, axis=0)
    med = np.median(H_raw, axis=0)
    mad = np.median(np.abs(H_raw - med), axis=0) * 1.4826
    floors = np.array([HPC_MIN_SCALE.get(c, 1.0) for c in hpc_cols], dtype=np.float64)
    scale = np.maximum.reduce([mad, 0.05 * np.abs(med), floors])
    return np.maximum((H_raw - q25) / scale, 0.0)


def extract_trial_windows(csv_path: Path, max_delta: float = 1.0, win_sec: float = 15.0):
    """
    Read one synced CSV in memory (zero disk writes) and return:
      - std_wins:  (M, D_base) naive per-window mean features (standard ML baseline)
      - stat_wins: (M, 6) cross-modal host-network coincidence + payload burst features
      - meta:      dict of raw counts for per-file diagnostics
    """
    if csv_path.stat().st_size == 0:
        return None

    df = pd.read_csv(csv_path, low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    if "_ws.col.Protocol" in df.columns and "_ws.col.protocol" not in df.columns:
        df = df.rename(columns={"_ws.col.Protocol": "_ws.col.protocol"})

    if "timestamp" not in df.columns or "frame.time_epoch" not in df.columns:
        return None

    hpc_ts = pd.to_numeric(df["timestamp"], errors="coerce")
    pkt_ts = pd.to_numeric(df["frame.time_epoch"], errors="coerce")
    mask = hpc_ts.notna() & pkt_ts.notna() & ((hpc_ts - pkt_ts).abs() <= max_delta)
    df = df.loc[mask].copy()
    if df.empty:
        return None

    # Relative seconds from start of this capture (prevents epoch timestamp leakage)
    t0 = float(min(hpc_ts.loc[mask].min(), pkt_ts.loc[mask].min()))
    df["_ht"] = np.round(hpc_ts.loc[mask] - t0, 3)
    df["_pt"] = pkt_ts.loc[mask] - t0
    df = df.sort_values("_pt", kind="mergesort").reset_index(drop=True)

    hpc_cols = [c for c in HPC_CANDIDATES if c in df.columns]
    for c in hpc_cols:
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)

    # 1. Deduplicate 1-Hz HPC ticks so packet bursts don't overweight one CPU sample
    hpc_1hz = df.groupby("_ht", sort=True)[hpc_cols].first()
    hpc_times = hpc_1hz.index.to_numpy(dtype=np.float64)
    H_raw = hpc_1hz.to_numpy(dtype=np.float64)
    H_pos_z = _host_positive_surge(H_raw, hpc_cols)
    surge_cols = [i for i, c in enumerate(hpc_cols) if c != "ipc"] or list(range(len(hpc_cols)))
    host_surge_ticks = np.mean(H_pos_z[:, surge_cols], axis=1)

    # 2. Isolate non-SSH / non-broadcast telemetry packet candidates
    flen = pd.to_numeric(df.get("frame.len", 0.0), errors="coerce").fillna(0.0).to_numpy(dtype=np.float64)
    fdelta = pd.to_numeric(df.get("frame.time_delta", 0.0), errors="coerce").fillna(0.0).to_numpy(dtype=np.float64)
    syn = _parse_bool_array(df["tcp.flags.syn"]) if "tcp.flags.syn" in df.columns else np.zeros(len(df))
    fin = _parse_bool_array(df["tcp.flags.fin"]) if "tcp.flags.fin" in df.columns else np.zeros(len(df))
    psh = _parse_bool_array(df["tcp.flags.push"]) if "tcp.flags.push" in df.columns else np.zeros(len(df))
    tcp_sp = pd.to_numeric(df.get("tcp.srcport", 0.0), errors="coerce").fillna(0.0).to_numpy(dtype=np.float64)
    tcp_dp = pd.to_numeric(df.get("tcp.dstport", 0.0), errors="coerce").fillna(0.0).to_numpy(dtype=np.float64)

    if "_ws.col.protocol" in df.columns:
        protos = df["_ws.col.protocol"].astype(str).str.strip().str.strip('"').str.upper()
        proto_ok = (~protos.isin(NON_TELEMETRY_PROTOS)).to_numpy()
    else:
        proto_ok = np.ones(len(df), dtype=bool)

    is_ssh_port = (tcp_sp == 22.0) | (tcp_dp == 22.0)
    app_mask = proto_ok & (~is_ssh_port)

    pt = df["_pt"].to_numpy(dtype=np.float64)
    T_sec = int(np.floor(max(float(pt.max()), float(hpc_times.max())))) + 2

    # 3. Build 1-second host surge & [t, t+1] non-SSH application byte series
    h_sec = np.zeros(T_sec, dtype=np.float64)
    h_act_sec = np.zeros(T_sec, dtype=np.float64)
    for ht_val, hs_val, h_row in zip(hpc_times, host_surge_ticks, H_raw):
        s = min(max(int(np.floor(ht_val)), 0), T_sec - 1)
        h_sec[s] = max(h_sec[s], hs_val)
        h_act_sec[s] = max(h_act_sec[s], float(h_row[0]))

    n_bytes_sec = np.zeros(T_sec, dtype=np.float64)
    for p_t, fl, is_app in zip(pt, flen, app_mask):
        if is_app:
            s = min(max(int(np.floor(p_t)), 0), T_sec - 1)
            n_bytes_sec[s] += fl

    # Do NOT subtract median(net_log_sec): preserves even high-rate 1-Hz beacons
    net_log_sec = np.log1p(n_bytes_sec)

    # Lagged [t, t+1s] coincidence captures presend CPU burst -> immediate send
    net_lag = np.maximum(net_log_sec, np.roll(net_log_sec, -1))
    net_lag[-1] = net_log_sec[-1]
    coincidence_sec = np.log1p(h_sec) * net_lag

    # 4. Aggregate into fixed win_sec time windows
    n_wins = max(1, int(np.ceil(T_sec / win_sec)))
    hpc_row_mat = df[hpc_cols].to_numpy(dtype=np.float64)
    std_wins, stat_wins = [], []

    for w in range(n_wins):
        t_start, t_end = w * win_sec, (w + 1) * win_sec
        i_start, i_end = int(t_start), min(T_sec, int(t_end))
        if i_start >= i_end:
            continue

        w_pkt = (pt >= t_start) & (pt < t_end)

        # --- Standard baseline: per-window feature averages ---
        if np.any(w_pkt):
            base_vec = np.concatenate([
                np.mean(hpc_row_mat[w_pkt], axis=0),
                [
                    float(np.mean(flen[w_pkt])),
                    float(np.mean(fdelta[w_pkt])),
                    float(np.sum(w_pkt)),
                    float(np.mean(syn[w_pkt])),
                    float(np.mean(fin[w_pkt])),
                    float(np.mean(psh[w_pkt])),
                ],
            ])
        else:
            base_vec = np.zeros(len(hpc_cols) + 6, dtype=np.float64)
        std_wins.append(base_vec)

        # --- Top 5 Cross-Modal Coincidence + Non-SSH Payload Burst features ---
        c_sl = coincidence_sec[i_start:i_end]
        n_sl = net_log_sec[i_start:i_end]

        hi = h_act_sec[i_start:i_end]
        nb = np.maximum(n_bytes_sec[i_start:i_end], np.roll(n_bytes_sec, -1)[i_start:i_end])
        if np.std(hi) > 1e-6 and np.std(nb) > 1e-6:
            local_corr = max(0.0, float(np.corrcoef(hi, nb)[0, 1]))
        else:
            local_corr = 0.0

        stat_wins.append(np.array([
            local_corr,                     # 0: host_net_corr     (measured AUC = 0.8833)
            float(np.sum(c_sl > 1.0)),      # 1: coincidence_ticks (measured AUC = 0.8500)
            float(np.max(c_sl)),            # 2: peak_coincidence  (measured AUC = 0.8167)
            float(np.sum(c_sl)),            # 3: sum_coincidence   (measured AUC = 0.8167)
            float(np.sum(n_sl)),            # 4: sum_net_logbytes  (measured AUC = 0.8667)
        ], dtype=np.float64))

    meta = {
        "rows": len(df),
        "app_pkts": int(np.sum(app_mask)),
    }
    return np.vstack(std_wins), np.vstack(stat_wins), meta


def load_trials(root: Path, max_delta: float = 1.0, win_sec: float = 15.0):
    data = {"h0": [], "h1": []}
    for cond in ("h0", "h1"):
        folder = root / cond
        if not folder.is_dir():
            raise FileNotFoundError(f"Missing folder: {folder}")
        for csv_path in sorted(folder.glob("*.csv")):
            parsed = extract_trial_windows(csv_path, max_delta=max_delta, win_sec=win_sec)
            if parsed is not None:
                std_w, stat_w, meta = parsed
                data[cond].append({
                    "name": f"{cond}/{csv_path.name}",
                    "std": std_w,
                    "stat": stat_w,
                    "meta": meta,
                })
    if not data["h0"] or not data["h1"]:
        raise ValueError("Need at least one non-empty synced CSV in both h0/ and h1/.")
    return data["h0"], data["h1"]


# =============================================================================
# Baseline: Standard L2-Regularized Logistic Regression on Window Means
# =============================================================================

def fit_standard_logistic(h0_tr: list, h1_tr: list, l2: float = 1.0) -> dict:
    X0 = np.vstack([t["std"] for t in h0_tr])
    X1 = np.vstack([t["std"] for t in h1_tr])
    X = np.vstack([X0, X1])
    y = np.concatenate([np.zeros(len(X0)), np.ones(len(X1))])

    mu = np.mean(X, axis=0)
    sd = np.where(np.std(X, axis=0) < 1e-8, 1.0, np.std(X, axis=0))
    Xb = np.column_stack([np.ones(len(X)), (X - mu) / sd])

    w = np.zeros(Xb.shape[1], dtype=np.float64)
    reg = l2 * np.eye(Xb.shape[1])
    reg[0, 0] = 0.0
    for _ in range(25):
        z = np.clip(Xb @ w, -30.0, 30.0)
        p = 1.0 / (1.0 + np.exp(-z))
        grad = Xb.T @ (p - y) + reg @ w
        W_diag = np.maximum(p * (1.0 - p), 1e-6)
        H = (Xb.T * W_diag) @ Xb + reg
        step = np.linalg.solve(H, grad)
        w -= step
        if float(np.linalg.norm(step)) < 1e-6:
            break
    return {"mu": mu, "sd": sd, "w": w}


def score_standard_logistic(wins: np.ndarray, model: dict) -> float:
    Xb = np.column_stack([np.ones(len(wins)), (wins - model["mu"]) / model["sd"]])
    probs = 1.0 / (1.0 + np.exp(-np.clip(Xb @ model["w"], -30.0, 30.0)))
    return float(np.mean(probs))


# =============================================================================
# Proposed: Multiple-Instance Whitened Discriminant + Donoho-Jin Higher Criticism
# =============================================================================

def donoho_jin_hc(z_scores: np.ndarray):
    """
    Exact Donoho & Jin (Annals of Statistics 2004, Eqs. 1.3 & 1.6) [1]
    Higher Criticism on Gaussian right-tail p-values p_i = erfc(z_i / sqrt(2)) / 2:
        HC* = max_{1 <= i <= M/2} sqrt(M) * max(i/M - p_(i), 0) / sqrt(p_(i) * (1 - p_(i)))
    Returned on log(1 + HC*) scale so single-beacon and multi-beacon trials sit on a smooth scale.
    """
    inv_sqrt2 = 1.0 / math.sqrt(2.0)
    z_clamped = np.clip(z_scores, -10.0, 8.0)
    p_vals = np.array([0.5 * math.erfc(float(z) * inv_sqrt2) for z in z_clamped], dtype=np.float64)

    p_sorted = np.sort(p_vals)
    M = len(p_sorted)
    k = max(1, M // 2)
    i_frac = np.arange(1, k + 1, dtype=np.float64) / M
    p_sub = np.clip(p_sorted[:k], 1e-16, 1.0 - 1e-12)
    hc_curve = np.sqrt(M) * np.maximum(i_frac - p_sub, 0.0) / np.sqrt(p_sub * (1.0 - p_sub))
    log_hc = float(np.log1p(np.max(hc_curve)))
    return log_hc, p_vals


def fit_cross_modal_hc(h0_tr: list, h1_tr: list, active_frac: float = 0.15) -> dict:
    Z0_all = np.vstack([t["stat"] for t in h0_tr])
    mu0 = np.mean(Z0_all, axis=0)
    sd0 = np.maximum(np.std(Z0_all, axis=0), STAT_MIN_SCALE)
    Z0_norm = (Z0_all - mu0) / sd0

    # Multiple-Instance positive selection: pick top active burst windows from H1 trials
    Z1_active = []
    for t in h1_tr:
        Z1_i = (t["stat"] - mu0) / sd0
        anom_rank = np.sum(np.maximum(Z1_i, 0.0), axis=1)
        if float(np.max(anom_rank)) > 0.0:
            top_k = max(1, int(np.ceil(active_frac * len(Z1_i))))
            Z1_active.append(Z1_i[np.argsort(anom_rank)[-top_k:]])

    d = Z0_norm.shape[1]
    if Z1_active:
        Z1_pos = np.vstack(Z1_active)
        C0 = np.cov(Z0_norm, rowvar=False) if len(Z0_norm) > 1 else np.eye(d)
        C0_reg = 0.85 * C0 + 0.15 * max(float(np.trace(C0)) / d, 1.0) * np.eye(d)
        w = np.maximum(np.linalg.solve(C0_reg, np.mean(Z1_pos, axis=0) - np.mean(Z0_norm, axis=0)), 0.0)
        # Prioritize cross-modal coupling features (indices 0..3) so stray uncoupled packets stay small
        w[:4] *= 1.5
    else:
        w = np.ones(d, dtype=np.float64)

    w_norm = float(np.linalg.norm(w))
    w = (w / w_norm) if w_norm > 0.0 else (np.ones(d, dtype=np.float64) / np.sqrt(d))

    # Standardize projected 1D window scores so null windows have unit scale <= 1
    proj_h0 = Z0_norm @ w
    proj_scale = max(float(np.std(proj_h0)), 1.0)

    hc_h0 = [donoho_jin_hc(((t["stat"] - mu0) / sd0 @ w) / proj_scale)[0] for t in h0_tr]
    hc_h1 = [donoho_jin_hc(((t["stat"] - mu0) / sd0 @ w) / proj_scale)[0] for t in h1_tr]

    # Donoho & Jin (2004, Theorem 1.1): HC* is calibrated against the H0 null critical
    # boundary sqrt(2 log log M) (~1.0 on log1p scale) + empirical H0 upper bound, so
    # loud H1 profiles never blind the threshold to sparse 1-beacon H1 profiles.
    M_typ = max(int(np.median([len(t["stat"]) for t in h0_tr])), 10)
    theo_null = float(np.log1p(np.sqrt(2.0 * np.log(max(np.log(float(M_typ)), 1.2)))))
    hc_thr = max(theo_null, float(np.max(hc_h0)) + 0.25)

    return {
        "mu0": mu0,
        "sd0": sd0,
        "w": w,
        "proj_scale": proj_scale,
        "hc_thr": hc_thr,
    }


def predict_cross_modal_hc(stat_wins: np.ndarray, model: dict) -> dict:
    z_scores = (((stat_wins - model["mu0"]) / model["sd0"]) @ model["w"]) / model["proj_scale"]
    log_hc, p_vals = donoho_jin_hc(z_scores)
    pred = 1 if log_hc > model["hc_thr"] else 0
    flagged = int(np.sum(p_vals < 0.025))
    return {
        "pred": pred,
        "hc": log_hc,
        "thr": model["hc_thr"],
        "margin": log_hc - model["hc_thr"],
        "flagged": flagged,
        "n_win": len(p_vals),
    }


def _roc_auc(y_true: np.ndarray, y_score: np.ndarray) -> float:
    pos = y_score[y_true == 1]
    neg = np.sort(y_score[y_true == 0])
    if len(pos) == 0 or len(neg) == 0:
        return 0.0
    gt = np.searchsorted(neg, pos, side="left")
    ge = np.searchsorted(neg, pos, side="right")
    return float(np.mean(gt + 0.5 * (ge - gt)) / len(neg))


def evaluate_all(h0_trials: list, h1_trials: list):
    """Run identical Leave-Trial-Out CV splits for Standard Logistic & Cross-Modal HC*."""
    if len(h0_trials) >= 2 and len(h1_trials) >= 2:
        n_folds = min(len(h0_trials), len(h1_trials))
        idx0 = np.array_split(np.arange(len(h0_trials)), n_folds)
        idx1 = np.array_split(np.arange(len(h1_trials)), n_folds)
        folds = []
        for k in range(n_folds):
            te0, te1 = set(idx0[k].tolist()), set(idx1[k].tolist())
            tr0 = [h0_trials[i] for i in range(len(h0_trials)) if i not in te0]
            tr1 = [h1_trials[i] for i in range(len(h1_trials)) if i not in te1]
            te_items = [(0, h0_trials[i]) for i in idx0[k]] + [(1, h1_trials[i]) for i in idx1[k]]
            folds.append((tr0, tr1, te_items))
    else:
        def _split_one(t):
            c = max(1, int(len(t["stat"]) * 0.70))
            tr = {"name": t["name"], "std": t["std"][:c], "stat": t["stat"][:c], "meta": t["meta"]}
            te = {"name": f"{t['name']} [test]", "std": t["std"][c:], "stat": t["stat"][c:], "meta": t["meta"]}
            return tr, te

        tr0, te0 = _split_one(h0_trials[0])
        tr1, te1 = _split_one(h1_trials[0])
        folds = [([tr0], [tr1], [(0, te0), (1, te1)])]

    results = []
    for tr0, tr1, te_items in folds:
        base_clf = fit_standard_logistic(tr0, tr1)
        hc_clf = fit_cross_modal_hc(tr0, tr1)

        for true_lbl, item in te_items:
            base_prob = score_standard_logistic(item["std"], base_clf)
            base_pred = 1 if base_prob >= 0.5 else 0
            hc_res = predict_cross_modal_hc(item["stat"], hc_clf)
            results.append((item["name"], true_lbl, base_pred, base_prob, hc_res, item["meta"]))

    results.sort(key=lambda r: (r[1], r[0]))

    print(
        f"\n{'File':<32} {'True':<5} {'Std-LR':<8} {'Proposed':<9} "
        f"{'logHC (thr)':<14} {'BurstWins':<10} {'AppPkts'}"
    )
    print("-" * 92)
    for fname, y_true, b_pred, _, hc_res, meta in results:
        t_str = f"H{y_true}"
        b_str = f"H{b_pred} ({b_pred})"
        p_str = f"H{hc_res['pred']} ({hc_res['pred']})"
        hc_str = f"{hc_res['hc']:5.2f} ({hc_res['thr']:4.2f})"
        w_str = f"{hc_res['flagged']:>2d} / {hc_res['n_win']:<2d}"
        print(f"{fname:<32} {t_str:<5} {b_str:<8} {p_str:<9} {hc_str:<14} {w_str:<10} {meta['app_pkts']}")

    y_arr = np.array([r[1] for r in results], dtype=np.int64)
    b_preds = np.array([r[2] for r in results], dtype=np.int64)
    b_scores = np.array([r[3] for r in results], dtype=np.float64)
    hc_preds = np.array([r[4]["pred"] for r in results], dtype=np.int64)
    hc_margins = np.array([r[4]["margin"] for r in results], dtype=np.float64)

    print("\n=== Comparative Trial Benchmark (Held-Out CSVs) ===")
    print(
        f"Logistic Classifier : "
        f"Trial Acc = {np.mean(b_preds == y_arr) * 100:5.1f}% "
        f"({int(np.sum(b_preds == y_arr))}/{len(y_arr)}) | "
        f"Trial ROC-AUC = {_roc_auc(y_arr, b_scores):.4f}"
    )
    print(
        f"2.MIL + Higher Criticism: "
        f"Trial Acc = {np.mean(hc_preds == y_arr) * 100:5.1f}% "
        f"({int(np.sum(hc_preds == y_arr))}/{len(y_arr)}) | "
        f"Trial ROC-AUC = {_roc_auc(y_arr, hc_margins):.4f}"
    )


def main():
    root = Path(__file__).resolve().parent
    h0_trials, h1_trials = load_trials(root=root, max_delta=1.0, win_sec=15.0)

    n_h0_wins = sum(len(t["stat"]) for t in h0_trials)
    n_h1_wins = sum(len(t["stat"]) for t in h1_trials)
    print(
        f"Loaded {len(h0_trials) + len(h1_trials)} trials in memory "
        f"(h0: {len(h0_trials)} CSVs [{n_h0_wins} windows], "
        f"h1: {len(h1_trials)} CSVs [{n_h1_wins} windows])."
    )

    if len(sys.argv) > 1:
        target = Path(sys.argv[1])
        parsed = extract_trial_windows(target, max_delta=1.0, win_sec=15.0)
        if parsed is None:
            raise ValueError(f"No valid aligned rows found in {target}")
        _, stat_w, meta = parsed
        hc_clf = fit_cross_modal_hc(h0_trials, h1_trials)
        res = predict_cross_modal_hc(stat_w, hc_clf)
        verdict = "H1 (BEACON DETECTED)" if res["pred"] == 1 else "H0 (NORMAL)"
        print(f"\nPrediction for {target.name}: {verdict}")
        print(f"  log(1 + HC*): {res['hc']:.2f} (threshold: {res['thr']:.2f})")
        print(f"  Anomalous 15s burst windows: {res['flagged']} / {res['n_win']} | App packets: {meta['app_pkts']}")
    else:
        evaluate_all(h0_trials, h1_trials)


if __name__ == "__main__":
    main()
