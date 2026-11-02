import pandas as pd
from sqlalchemy import text
from src.db import get_engine

CSV = "data/UNSW-NB15_1.csv"
COLS = ["srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes",
        "dbytes", "sttl", "dttl", "sloss", "dloss", "service", "sload", "dload",
        "spkts", "dpkts", "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz",
        "trans_depth", "res_bdy_len", "sjit", "djit", "stime", "ltime", "sintpkt",
        "dintpkt", "tcprtt", "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl",
        "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst",
        "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm",
        "ct_dst_src_ltm", "attack_cat", "label"]


def to_port(v):
    try:
        s = str(v).strip()
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except ValueError:
        return -1


def main():
    engine = get_engine()

    print("Reading CSV...")
    df = pd.read_csv(CSV, header=None, names=COLS, low_memory=False,
                     dtype={"sport": str, "dsport": str, "attack_cat": str})
    print(f"  {len(df):,} rows")

    print("Cleaning...")
    df["src_port"] = df["sport"].apply(to_port)
    df["dst_port"] = df["dsport"].apply(to_port)
    for c in ["proto", "service", "state"]:
        df[c] = df[c].astype(str).str.strip()
    df["attack_cat"] = (df["attack_cat"].fillna("Normal").str.strip()
                        .replace({"Backdoor": "Backdoors"}))
    df["start_time"] = pd.to_datetime(df["stime"], unit="s")
    df["ts_hour"] = df["start_time"].dt.floor("h")

    print("Clearing old data...")
    with engine.begin() as conn:
        conn.execute(text(
            "TRUNCATE fact_attack_events, dim_time, dim_source_ip, "
            "dim_destination, dim_protocol, dim_attack_type RESTART IDENTITY CASCADE"))

    print("Loading dimensions...")
    t = pd.DataFrame({"ts_hour": df["ts_hour"].unique()})
    t["date"] = t["ts_hour"].dt.date
    t["year"] = t["ts_hour"].dt.year
    t["month"] = t["ts_hour"].dt.month
    t["day"] = t["ts_hour"].dt.day
    t["hour"] = t["ts_hour"].dt.hour
    t["day_of_week"] = t["ts_hour"].dt.dayofweek
    t.to_sql("dim_time", engine, if_exists="append", index=False)

    s = df[["srcip"]].drop_duplicates().rename(columns={"srcip": "ip_address"})
    s.to_sql("dim_source_ip", engine, if_exists="append", index=False)

    d = (df[["dstip", "dst_port"]].drop_duplicates()
         .rename(columns={"dstip": "ip_address", "dst_port": "port"}))
    d.to_sql("dim_destination", engine, if_exists="append", index=False)

    p = df[["proto", "service", "state"]].drop_duplicates()
    p.to_sql("dim_protocol", engine, if_exists="append", index=False)

    a = df[["attack_cat"]].drop_duplicates()
    a["is_attack"] = a["attack_cat"] != "Normal"
    a.to_sql("dim_attack_type", engine, if_exists="append", index=False)

    print("Looking up keys...")
    df = df.merge(pd.read_sql("SELECT time_key, ts_hour FROM dim_time", engine),
                  on="ts_hour")
    df = df.merge(pd.read_sql("SELECT src_ip_key, ip_address FROM dim_source_ip", engine),
                  left_on="srcip", right_on="ip_address").drop(columns="ip_address")
    df = df.merge(pd.read_sql("SELECT dst_key, ip_address, port FROM dim_destination", engine),
                  left_on=["dstip", "dst_port"], right_on=["ip_address", "port"]
                  ).drop(columns=["ip_address", "port"])
    df = df.merge(pd.read_sql("SELECT proto_key, proto, service, state FROM dim_protocol", engine),
                  on=["proto", "service", "state"])
    df = df.merge(pd.read_sql("SELECT attack_key, attack_cat FROM dim_attack_type", engine),
                  on="attack_cat")

    fact = df.rename(columns={
        "dur": "duration", "sbytes": "src_bytes", "dbytes": "dst_bytes",
        "spkts": "src_pkts", "dpkts": "dst_pkts", "sttl": "src_ttl",
        "dttl": "dst_ttl", "sload": "src_load", "dload": "dst_load",
        "sjit": "src_jitter", "djit": "dst_jitter"})[[
        "time_key", "src_ip_key", "dst_key", "proto_key", "attack_key",
        "src_port", "start_time", "duration", "src_bytes", "dst_bytes",
        "src_pkts", "dst_pkts", "src_ttl", "dst_ttl", "src_load", "dst_load",
        "src_jitter", "dst_jitter", "label"]]

    print(f"Loading {len(fact):,} fact rows (a few minutes)...")
    fact.to_sql("fact_attack_events", engine, if_exists="append", index=False,
                chunksize=10000, method="multi")
    print("Done.")


if __name__ == "__main__":
    main()
