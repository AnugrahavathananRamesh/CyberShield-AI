"""
Shared preprocessing. BOTH training and prediction import this file, so the
feature order is guaranteed to be identical in both places.
"""
import pandas as pd

NUMERIC_FEATURES = [
    "duration", "src_bytes", "dst_bytes", "packet_count",
    "connection_count", "failed_logins", "logged_in", "error_rate",
]
PROTOCOLS = ["tcp", "udp", "icmp"]
SERVICES = ["http", "dns", "ssh", "ftp", "smtp"]

# Final column order the model sees (numeric + one-hot encoded categories)
FEATURE_COLUMNS = (
    NUMERIC_FEATURES
    + [f"protocol_{p}" for p in PROTOCOLS]
    + [f"service_{s}" for s in SERVICES]
)


def build_feature_frame(df, medians=None):
    """Turn raw activity rows into the exact numeric table the model expects."""
    out = pd.DataFrame(index=df.index)
    for col in NUMERIC_FEATURES:
        out[col] = pd.to_numeric(df[col], errors="coerce")
        if medians is not None:                      # missing values -> median
            out[col] = out[col].fillna(medians[col])
    protocol = df["protocol"].astype(str).str.lower()
    service = df["service"].astype(str).str.lower()
    for p in PROTOCOLS:                              # one-hot encoding
        out[f"protocol_{p}"] = (protocol == p).astype(int)
    for s in SERVICES:
        out[f"service_{s}"] = (service == s).astype(int)
    return out[FEATURE_COLUMNS]                      # force the column order
