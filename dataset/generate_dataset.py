"""
Creates dataset/cybersecurity_data.csv

*** THIS IS A SYNTHETIC DEMONSTRATION DATASET ***
It is generated from hand-written statistical profiles of normal and attack
traffic (inspired by features in KDD / UNSW-NB15 / CICIDS2017). It is NOT real
captured network traffic, so accuracy measured on it says nothing about
real-world performance. To use a real dataset, see README section "Using a real dataset".

Run:  python dataset/generate_dataset.py
"""
from pathlib import Path

import numpy as np
import pandas as pd

rng = np.random.default_rng(42)
N_ROWS = 6000
SERVICES = ["http", "dns", "ssh", "ftp", "smtp"]
CLASS_SHARE = {
    "Normal": 0.60, "Brute Force": 0.12, "DoS": 0.10,
    "Port Scan": 0.10, "Data Exfiltration": 0.08,
}


def pick(options, probs, n):
    return rng.choice(options, size=n, p=probs)


def normal(n):
    return dict(
        duration=np.clip(rng.lognormal(1.0, 1.1, n), 0.01, 600),
        protocol=pick(["tcp", "udp", "icmp"], [.70, .27, .03], n),
        service=pick(SERVICES, [.45, .25, .10, .05, .15], n),
        src_bytes=rng.lognormal(7, 1.5, n), dst_bytes=rng.lognormal(8.5, 1.7, n),
        packet_count=rng.poisson(45, n) + 1, connection_count=rng.poisson(8, n) + 1,
        failed_logins=np.clip(rng.poisson(0.25, n), 0, 6),
        logged_in=rng.binomial(1, .85, n), error_rate=rng.beta(1, 40, n),
    )


def brute_force(n):
    failed = rng.integers(6, 100, n)
    weak = rng.random(n) < 0.08                      # a few attacks look mild
    failed[weak] = rng.integers(2, 6, weak.sum())
    return dict(
        duration=np.clip(rng.lognormal(3, 0.9, n), 0.5, 3000),
        protocol=pick(["tcp", "udp"], [.95, .05], n),
        service=pick(SERVICES, [.15, 0, .50, .25, .10], n),
        src_bytes=rng.lognormal(6.5, 0.8, n), dst_bytes=rng.lognormal(6.3, 0.8, n),
        packet_count=rng.integers(40, 500, n), connection_count=rng.integers(10, 90, n),
        failed_logins=failed, logged_in=rng.binomial(1, .08, n),
        error_rate=rng.beta(3, 8, n),
    )


def dos(n):
    return dict(
        duration=np.clip(rng.lognormal(0.5, 0.8, n), 0.01, 120),
        protocol=pick(["tcp", "udp", "icmp"], [.50, .35, .15], n),
        service=pick(SERVICES, [.50, .30, .05, .05, .10], n),
        src_bytes=rng.lognormal(11, 1.2, n), dst_bytes=rng.lognormal(3, 1.5, n),
        packet_count=rng.integers(3000, 60000, n),
        connection_count=rng.integers(250, 3000, n),
        failed_logins=rng.poisson(0.05, n), logged_in=rng.binomial(1, .03, n),
        error_rate=rng.beta(6, 3, n),
    )


def port_scan(n):
    return dict(
        duration=np.clip(rng.lognormal(-1, 0.8, n), 0.01, 30),
        protocol=pick(["tcp", "udp"], [.85, .15], n),
        service=pick(SERVICES, [.2] * 5, n),
        src_bytes=rng.lognormal(4, 0.7, n), dst_bytes=rng.lognormal(3, 1.0, n),
        packet_count=rng.integers(80, 900, n), connection_count=rng.integers(90, 700, n),
        failed_logins=rng.poisson(0.3, n), logged_in=np.zeros(n, dtype=int),
        error_rate=rng.beta(7, 2, n),
    )


def exfiltration(n):
    return dict(
        duration=np.clip(rng.lognormal(6.2, 0.7, n), 30, 20000),
        protocol=pick(["tcp", "udp"], [.90, .10], n),
        service=pick(SERVICES, [.30, .20, .10, .25, .15], n),
        src_bytes=rng.lognormal(17, 0.9, n), dst_bytes=rng.lognormal(6, 1.0, n),
        packet_count=rng.integers(4000, 120000, n), connection_count=rng.integers(1, 9, n),
        failed_logins=rng.poisson(0.1, n), logged_in=rng.binomial(1, .90, n),
        error_rate=rng.beta(1, 30, n),
    )


GENERATORS = {
    "Normal": normal, "Brute Force": brute_force, "DoS": dos,
    "Port Scan": port_scan, "Data Exfiltration": exfiltration,
}


def main():
    frames = []
    for name, share in CLASS_SHARE.items():
        n = int(N_ROWS * share)
        df = pd.DataFrame(GENERATORS[name](n))
        df["attack_type"] = name
        frames.append(df)
    data = pd.concat(frames, ignore_index=True).sample(frac=1, random_state=42)

    # Realistic imperfection 1: ~1.5% wrong labels (label noise)
    flip = rng.random(len(data)) < 0.015
    data.loc[flip, "attack_type"] = rng.choice(list(CLASS_SHARE), flip.sum())

    # Tidy types
    data["duration"] = data["duration"].round(2)
    data["error_rate"] = data["error_rate"].round(3)
    for col in ["src_bytes", "dst_bytes"]:
        data[col] = data[col].round().astype(int)
    for col in ["packet_count", "connection_count", "failed_logins", "logged_in"]:
        data[col] = data[col].astype(int)
    data["label"] = np.where(data["attack_type"] == "Normal", "Normal", "Attack")

    # Realistic imperfection 2: ~1% missing values (teaches cleaning)
    for col in ["duration", "packet_count", "protocol", "service"]:
        data.loc[rng.random(len(data)) < 0.01, col] = np.nan

    out = Path(__file__).resolve().parent / "cybersecurity_data.csv"
    data.to_csv(out, index=False)
    print(f"Saved {len(data)} rows to {out}")
    print(data["attack_type"].value_counts().to_string())


if __name__ == "__main__":
    main()
