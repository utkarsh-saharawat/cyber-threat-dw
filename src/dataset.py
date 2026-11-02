import pandas as pd
from src.db import get_engine

QUERY = """
SELECT f.label, a.attack_cat,
       f.duration, f.src_bytes, f.dst_bytes, f.src_pkts, f.dst_pkts,
       f.src_ttl, f.dst_ttl, f.src_load, f.dst_load,
       f.src_jitter, f.dst_jitter, f.src_port, d.port AS dst_port,
       p.proto, p.service, p.state
FROM fact_attack_events f
JOIN dim_attack_type a ON f.attack_key = a.attack_key
JOIN dim_destination d ON f.dst_key = d.dst_key
JOIN dim_protocol p ON f.proto_key = p.proto_key
"""


def load_dataset(top_protos=6):
    df = pd.read_sql(QUERY, get_engine())
    top = df["proto"].value_counts().nlargest(top_protos).index
    df["proto"] = df["proto"].where(df["proto"].isin(top), "other")
    df = pd.get_dummies(df, columns=["proto", "service", "state"], dtype=int)
    y_bin = df["label"]
    y_multi = df["attack_cat"]
    X = df.drop(columns=["label", "attack_cat"])
    return X, y_bin, y_multi


if __name__ == "__main__":
    X, y_bin, y_multi = load_dataset()
    print("Features:", X.shape)
    print(y_bin.value_counts())
