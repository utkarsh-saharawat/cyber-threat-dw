import numpy as np
import pandas as pd
from sklearn.cluster import MiniBatchKMeans
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score
from mlxtend.frequent_patterns import fpgrowth, association_rules
from src.db import get_engine

pd.set_option("display.width", 200)
pd.set_option("display.max_colwidth", 70)

QUERY = """
SELECT f.label, a.attack_cat, p.proto, p.service, p.state,
       f.duration, f.src_bytes, f.dst_bytes, f.src_pkts, f.dst_pkts,
       f.src_load, f.dst_load, f.src_jitter, f.dst_jitter
FROM fact_attack_events f
JOIN dim_attack_type a ON f.attack_key = a.attack_key
JOIN dim_protocol p ON f.proto_key = p.proto_key
"""
NUM = ["duration", "src_bytes", "dst_bytes", "src_pkts", "dst_pkts",
       "src_load", "dst_load", "src_jitter", "dst_jitter"]


def run_clustering(df):
    print("=== K-Means clustering (10 clusters) ===")
    X = StandardScaler().fit_transform(np.log1p(df[NUM].clip(lower=0)))
    km = MiniBatchKMeans(n_clusters=10, batch_size=10000, n_init=10, random_state=42)
    df["cluster"] = km.fit_predict(X)
    idx = np.random.RandomState(42).choice(len(X), 10000, replace=False)
    print("Silhouette (10k sample):",
          round(silhouette_score(X[idx], df["cluster"].values[idx]), 4))
    g = df.groupby("cluster")
    summary = pd.DataFrame({
        "size": g.size(),
        "attack_pct": (100 * g["label"].mean()).round(2),
        "top_attack": g["attack_cat"].agg(
            lambda s: s[s != "Normal"].mode().iat[0] if (s != "Normal").any() else "-"),
    })
    print(summary.sort_values("attack_pct", ascending=False))


def run_rules(df):
    print("\n=== FP-Growth association rules (attack events only) ===")
    att = df[df["label"] == 1]
    cats = att[["proto", "service", "state", "attack_cat"]].copy()
    for c in ["duration", "src_bytes", "dst_bytes"]:
        cats[c] = pd.qcut(att[c].rank(method="first"), 3,
                          labels=["low", "mid", "high"]).astype(str)
    basket = pd.get_dummies(cats, prefix_sep="=").astype(bool)
    freq = fpgrowth(basket, min_support=0.02, use_colnames=True)
    print("Frequent itemsets:", len(freq))
    try:
        rules = association_rules(freq, num_itemsets=len(basket),
                                  metric="confidence", min_threshold=0.7)
    except TypeError:
        rules = association_rules(freq, metric="confidence", min_threshold=0.7)
    is_cat = rules["consequents"].apply(
        lambda s: len(s) == 1 and next(iter(s)).startswith("attack_cat="))
    rules = rules[is_cat].sort_values("lift", ascending=False).head(15).copy()
    for col in ["antecedents", "consequents"]:
        rules[col] = rules[col].apply(lambda s: ", ".join(sorted(s)))
    print(rules[["antecedents", "consequents", "support", "confidence", "lift"]]
          .round(3).to_string(index=False))


def main():
    df = pd.read_sql(QUERY, get_engine())
    run_clustering(df)
    run_rules(df)


if __name__ == "__main__":
    main()
