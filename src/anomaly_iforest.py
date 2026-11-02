import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (roc_auc_score, average_precision_score,
                             classification_report, confusion_matrix)
from src.dataset import load_dataset


def main():
    X, y, cat = load_dataset()
    print("Training Isolation Forest (labels not used)...")
    iso = IsolationForest(n_estimators=200, max_samples=20000,
                          n_jobs=-1, random_state=42)
    iso.fit(X)
    score = -iso.score_samples(X)  # higher = more anomalous

    print("ROC-AUC:", round(roc_auc_score(y, score), 4))
    print("PR-AUC:", round(average_precision_score(y, score), 4),
          "(random baseline:", round(y.mean(), 4), ")")

    threshold = np.quantile(score, 1 - y.mean())
    pred = (score >= threshold).astype(int)
    print("\nFlagging the top", round(100 * y.mean(), 2), "% most anomalous events")
    print(classification_report(y, pred, digits=4,
                                target_names=["normal", "attack"]))
    print("Confusion matrix [[TN FP], [FN TP]]:")
    print(confusion_matrix(y, pred))

    df = pd.DataFrame({"category": cat, "flagged": pred})
    print("\nShare flagged as anomaly, by category:")
    print(df.groupby("category")["flagged"].mean().round(4)
          .sort_values(ascending=False))


if __name__ == "__main__":
    main()
