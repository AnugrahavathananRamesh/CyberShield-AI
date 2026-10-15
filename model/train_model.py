"""
Trains the Random Forest threat classifier.

Run from the project root:   python model/train_model.py

Steps: 1 load  2 clean  3 missing values  4 encode  5 select features
       6 split  7 train  8 evaluate  9 save (joblib)
"""
import json
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, f1_score, precision_score,
                             recall_score)
from sklearn.model_selection import cross_val_score, train_test_split

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from utils.preprocessing import (FEATURE_COLUMNS, NUMERIC_FEATURES,  # noqa: E402
                                 PROTOCOLS, SERVICES, build_feature_frame)

DATA_FILE = ROOT / "dataset" / "cybersecurity_data.csv"
TARGET = "attack_type"

# 1. LOAD ---------------------------------------------------------------
if not DATA_FILE.exists():
    sys.exit("Dataset missing. Run:  python dataset/generate_dataset.py")
df = pd.read_csv(DATA_FILE)
print(f"[1] Loaded {len(df)} rows, {df.shape[1]} columns")

# 2. CLEAN --------------------------------------------------------------
before = len(df)
df = df.drop_duplicates()
df = df.dropna(subset=[TARGET])                       # a row with no label is useless
for col in ("protocol", "service"):
    df[col] = df[col].astype("string").str.strip().str.lower()
for col in NUMERIC_FEATURES:
    df[col] = pd.to_numeric(df[col], errors="coerce")
    df.loc[df[col] < 0, col] = float("nan")           # negative counts are invalid
print(f"[2] Cleaning removed {before - len(df)} rows")

# 3. MISSING VALUES -----------------------------------------------------
print(f"[3] Missing values before filling:\n{df[NUMERIC_FEATURES + ['protocol', 'service']].isna().sum().to_string()}")
medians = {c: float(df[c].median()) for c in NUMERIC_FEATURES}   # numbers -> median
for col, allowed in (("protocol", PROTOCOLS), ("service", SERVICES)):
    mode = df[col][df[col].isin(allowed)].mode()[0]               # categories -> most common
    df[col] = df[col].where(df[col].isin(allowed), mode)

# 4 + 5. ENCODE and SELECT FEATURES (shared with the prediction code) ----
X = build_feature_frame(df, medians)
y = df[TARGET]
print(f"[4] One-hot encoded protocol/service. [5] {len(FEATURE_COLUMNS)} features used.")

# 6. SPLIT ---------------------------------------------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y)
print(f"[6] Train rows: {len(X_train)}  Test rows: {len(X_test)}")

# 7. TRAIN ---------------------------------------------------------------
model = RandomForestClassifier(
    n_estimators=200, max_depth=20, class_weight="balanced",
    random_state=42, n_jobs=-1)
model.fit(X_train, y_train)
print("[7] Random Forest trained (200 trees)")

# 8. EVALUATE ------------------------------------------------------------
pred = model.predict(X_test)
labels = sorted(y.unique())
print("\n[8] EVALUATION ON UNSEEN TEST DATA (multi-class)")
print(f"Accuracy : {accuracy_score(y_test, pred):.4f}")
print(f"Precision: {precision_score(y_test, pred, average='weighted', zero_division=0):.4f} (weighted)")
print(f"Recall   : {recall_score(y_test, pred, average='weighted', zero_division=0):.4f} (weighted)")
print(f"F1-score : {f1_score(y_test, pred, average='weighted', zero_division=0):.4f} (weighted)")
print("\nPer-class report:\n" + classification_report(y_test, pred, zero_division=0))
cm = confusion_matrix(y_test, pred, labels=labels)
print("Confusion matrix (rows = actual, columns = predicted):")
print(pd.DataFrame(cm, index=labels, columns=labels).to_string())

# Simplified view: Normal vs Attack
yt_bin, yp_bin = (y_test != "Normal"), (pd.Series(pred, index=y_test.index) != "Normal")
bin_metrics = {
    "accuracy": accuracy_score(yt_bin, yp_bin), "precision": precision_score(yt_bin, yp_bin),
    "recall": recall_score(yt_bin, yp_bin), "f1": f1_score(yt_bin, yp_bin),
}
print("\nNormal vs Attack only: " + "  ".join(f"{k}={v:.4f}" for k, v in bin_metrics.items()))
cv = cross_val_score(model, X, y, cv=5, n_jobs=-1)
print(f"5-fold cross-validation accuracy: {cv.mean():.4f} (+/- {cv.std():.4f})")

importances = sorted(zip(FEATURE_COLUMNS, model.feature_importances_), key=lambda t: -t[1])
print("\nTop features:")
for name, value in importances[:6]:
    print(f"  {name:<18} {value:.3f}")

# 9. SAVE -----------------------------------------------------------------
joblib.dump(model, ROOT / "model" / "threat_model.pkl")
joblib.dump({"feature_columns": FEATURE_COLUMNS, "medians": medians,
             "protocols": PROTOCOLS, "services": SERVICES},
            ROOT / "model" / "preprocessing.pkl")
metrics = {
    "dataset": "Synthetic demonstration dataset (not real traffic)",
    "rows": int(len(df)), "algorithm": "Random Forest (200 trees)",
    "accuracy": round(accuracy_score(y_test, pred), 4),
    "precision_weighted": round(precision_score(y_test, pred, average="weighted", zero_division=0), 4),
    "recall_weighted": round(recall_score(y_test, pred, average="weighted", zero_division=0), 4),
    "f1_weighted": round(f1_score(y_test, pred, average="weighted", zero_division=0), 4),
    "normal_vs_attack": {k: round(v, 4) for k, v in bin_metrics.items()},
    "labels": labels, "confusion_matrix": cm.tolist(),
    "top_features": [[n, round(float(v), 4)] for n, v in importances[:8]],
}
(ROOT / "model" / "metrics.json").write_text(json.dumps(metrics, indent=2))
print("\n[9] Saved model/threat_model.pkl, model/preprocessing.pkl, model/metrics.json")
