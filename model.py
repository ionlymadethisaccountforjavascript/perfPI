from pathlib import Path
import hashlib

import numpy as np
import pandas as pd

# Leakage / raw address string columns to drop after timestamp alignment check
DROP_COLS = {
    "timestamp",
    "frame.time_epoch",
    "pid",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
}

BOOL_COLS = {
    "tcp.flags.syn",
    "tcp.flags.fin",
    "tcp.flags.push",
}

PROTOCOL_MAP = {
    "TCP": 1.0,
    "UDP": 2.0,
    "TLS": 3.0,
    "TLSV1.2": 3.0,
    "TLSV1.3": 3.0,
    "DNS": 4.0,
    "MDNS": 4.0,
    "HTTP": 5.0,
    "HTTP2": 5.0,
    "QUIC": 6.0,
    "ICMP": 7.0,
    "ICMPV6": 7.0,
    "ARP": 8.0,
    "SSH": 9.0,
    "DTLS": 10.0,
}


def _parse_hex_col(series: pd.Series) -> np.ndarray:
    out = np.zeros(len(series), dtype=np.float64)
    for idx, val in enumerate(series):
        if pd.isna(val):
            continue
        s = str(val).strip().strip('"')
        if not s:
            continue
        try:
            out[idx] = float(int(s, 16) if s.lower().startswith("0x") else float(s))
        except ValueError:
            out[idx] = 0.0
    return out


def _parse_bool_col(series: pd.Series) -> np.ndarray:
    s = series.astype(str).str.strip().str.strip('"').str.lower()
    return np.where(s.isin(["1", "1.0", "true"]), 1.0, 0.0).astype(np.float64)


def _parse_protocol_col(series: pd.Series) -> np.ndarray:
    out = np.zeros(len(series), dtype=np.float64)
    for idx, val in enumerate(series):
        if pd.isna(val):
            continue
        proto = str(val).strip().strip('"').upper()
        if not proto:
            continue
        if proto in PROTOCOL_MAP:
            out[idx] = PROTOCOL_MAP[proto]
        else:
            # Deterministic numeric ID across all trials for any unseen protocol
            digest = hashlib.blake2b(proto.encode("utf-8"), digest_size=2).digest()
            out[idx] = float(100 + (int.from_bytes(digest, "big") % 900))
    return out


def clean_csv(csv_path: Path, max_delta: float = 1.0, feature_cols=None):
    if csv_path.stat().st_size == 0:
        return None, feature_cols

    df = pd.read_csv(csv_path, low_memory=False)
    df.columns = [c.strip() for c in df.columns]

    if "_ws.col.Protocol" in df.columns and "_ws.col.protocol" not in df.columns:
        df = df.rename(columns={"_ws.col.Protocol": "_ws.col.protocol"})

    # Keep rows within max_delta seconds and preserve chronological order
    if "timestamp" in df.columns and "frame.time_epoch" in df.columns:
        hpc_ts = pd.to_numeric(df["timestamp"], errors="coerce")
        pkt_ts = pd.to_numeric(df["frame.time_epoch"], errors="coerce")
        mask = hpc_ts.notna() & pkt_ts.notna() & ((hpc_ts - pkt_ts).abs() <= max_delta)
        df = df.loc[mask].copy()
        df["_sort_ts"] = pkt_ts.loc[mask]
        df = (
            df.sort_values("_sort_ts", kind="mergesort")
            .drop(columns=["_sort_ts"])
            .reset_index(drop=True)
        )
    elif "timestamp" in df.columns:
        ts = pd.to_numeric(df["timestamp"], errors="coerce")
        df = df.loc[ts.notna()].copy()
        df["_sort_ts"] = ts.loc[ts.notna()]
        df = (
            df.sort_values("_sort_ts", kind="mergesort")
            .drop(columns=["_sort_ts"])
            .reset_index(drop=True)
        )

    if df.empty:
        return None, feature_cols

    if feature_cols is None:
        feature_cols = [c for c in df.columns if c not in DROP_COLS]

    n_rows = len(df)
    cols_np = []

    for col in feature_cols:
        if col not in df.columns:
            cols_np.append(np.zeros(n_rows, dtype=np.float64))
        elif col == "_ws.col.protocol":
            cols_np.append(_parse_protocol_col(df[col]))
        elif col == "tcp.flags":
            cols_np.append(_parse_hex_col(df[col]))
        elif col in BOOL_COLS:
            cols_np.append(_parse_bool_col(df[col]))
        else:
            vals = (
                pd.to_numeric(df[col], errors="coerce")
                .fillna(0.0)
                .to_numpy(dtype=np.float64)
            )
            cols_np.append(vals)

    matrix = np.column_stack(cols_np)
    np.nan_to_num(matrix, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
    return matrix, feature_cols


def clean_condition(folder: Path, label: int, max_delta: float = 1.0, feature_cols=None):
    csv_paths = sorted(folder.glob("*.csv"))
    if not csv_paths:
        raise FileNotFoundError(f"No CSV files found in: {folder}")

    arrays = []
    labels = []

    for csv_path in csv_paths:
        arr, feature_cols = clean_csv(
            csv_path, max_delta=max_delta, feature_cols=feature_cols
        )
        if arr is not None and arr.shape[0] > 0:
            arrays.append(arr)
            labels.append(label)

    return arrays, labels, feature_cols


def load_cleaned_data(root=None, max_delta: float = 1.0):
    if root is None:
        root = Path(__file__).resolve().parent
    else:
        root = Path(root)

    csv_list = []
    trial_labels = []
    by_condition = {}
    feature_cols = None

    for name, label in [("h0", 0), ("h1", 1)]:
        folder = root / name
        if not folder.is_dir():
            raise FileNotFoundError(f"Missing folder: {folder}")

        arrays, labels, feature_cols = clean_condition(
            folder, label, max_delta=max_delta, feature_cols=feature_cols
        )
        by_condition[name] = arrays
        csv_list.extend(arrays)
        trial_labels.extend(labels)

    if not csv_list:
        raise ValueError("No valid rows remained after cleaning.")

    trial_labels_np = np.array(trial_labels, dtype=np.int64)
    X_all = np.vstack(csv_list)
    y_all = np.concatenate([
        np.full(arr.shape[0], lbl, dtype=np.int64)
        for arr, lbl in zip(csv_list, trial_labels)
    ])

    return (
        csv_list,
        trial_labels_np,
        by_condition["h0"],
        by_condition["h1"],
        X_all,
        y_all,
        feature_cols,
    )


def main():
    csv_list, trial_labels, h0_list, h1_list, X, y, feature_cols = load_cleaned_data(
        max_delta=1.0
    )

    print(
        f"Cleaned and stored {len(csv_list)} CSVs in memory "
        f"(h0: {len(h0_list)}, h1: {len(h1_list)} | "
        f"total rows: {X.shape[0]}, features: {X.shape[1]})."
    )

    # Ready for your group theory model directly from here:
    # - csv_list:     list[np.ndarray] -> each CSV as a (N_i, D) float64 matrix
    # - trial_labels: np.ndarray       -> (num_csvs,) int64 labels (0 = h0, 1 = h1)
    # - h0_list:      list[np.ndarray] -> only H0 trial matrices
    # - h1_list:      list[np.ndarray] -> only H1 trial matrices
    # - X, y:         np.ndarray       -> stacked (sum N_i, D) matrix and row labels
    # - feature_cols: list[str]        -> column names corresponding to axis 1


if __name__ == "__main__":
    main()
