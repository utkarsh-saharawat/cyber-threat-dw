import pandas as pd
import plotly.express as px
import streamlit as st
from sqlalchemy import text
from src.db import get_engine

st.set_page_config(page_title="Cyber Threat Intelligence DW", layout="wide")


@st.cache_resource
def engine():
    return get_engine()


@st.cache_data
def q(sql, params=None):
    return pd.read_sql(text(sql), engine(), params=params or {})


st.title("Cyber Threat Intelligence Data Warehouse")
st.caption("UNSW-NB15 (part 1) in a PostgreSQL star schema")

cats = q("SELECT attack_cat FROM dim_attack_type ORDER BY 1")["attack_cat"].tolist()
protos = q("""SELECT p.proto FROM fact_attack_events f JOIN dim_protocol p ON f.proto_key = p.proto_key GROUP BY p.proto ORDER BY COUNT(*) DESC LIMIT 10""")["proto"].tolist()

st.sidebar.header("Filters (slice / dice)")
sel_cats = st.sidebar.multiselect("Attack category", cats, default=cats)
sel_protos = st.sidebar.multiselect("Protocol", protos, default=protos)
P = {"cats": sel_cats or cats, "protos": sel_protos or protos}

tab1, tab2, tab3, tab4 = st.tabs(["Overview", "OLAP explorer", "Model results", "MITRE ATT&CK"])

with tab1:
    k = q("""SELECT COUNT(*) AS total, SUM(label) AS attacks,
                    (SELECT COUNT(*) FROM dim_source_ip) AS src_ips
             FROM fact_attack_events""").iloc[0]
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total events", f"{int(k.total):,}")
    c2.metric("Attack events", f"{int(k.attacks):,}")
    c3.metric("Attack share", f"{100 * k.attacks / k.total:.2f}%")
    c4.metric("Source IPs", int(k.src_ips))
    roll = q("""SELECT a.attack_cat, COUNT(*) AS events
                FROM fact_attack_events f
                JOIN dim_attack_type a ON f.attack_key = a.attack_key
                WHERE a.is_attack GROUP BY a.attack_cat ORDER BY events DESC""")
    st.subheader("Attacks by category (roll-up)")
    st.plotly_chart(px.bar(roll, x="attack_cat", y="events", log_y=True),
                    width="stretch")
    st.caption("Log scale: Generic has about 7,500 events, Worms only 24.")

with tab2:
    st.subheader("Hourly drill-down (filtered)")
    hr = q("""SELECT t.ts_hour, COUNT(*) AS total_events, SUM(f.label) AS attacks
              FROM fact_attack_events f
              JOIN dim_time t ON f.time_key = t.time_key
              JOIN dim_attack_type a ON f.attack_key = a.attack_key
              JOIN dim_protocol p ON f.proto_key = p.proto_key
              WHERE a.attack_cat = ANY(:cats) AND p.proto = ANY(:protos)
              GROUP BY t.ts_hour ORDER BY t.ts_hour""", P)
    st.plotly_chart(px.line(hr, x="ts_hour", y=["total_events", "attacks"],
                            markers=True), width="stretch")
    st.subheader("Attack category by protocol (filtered)")
    hm = q("""SELECT a.attack_cat, p.proto, COUNT(*) AS events
              FROM fact_attack_events f
              JOIN dim_attack_type a ON f.attack_key = a.attack_key
              JOIN dim_protocol p ON f.proto_key = p.proto_key
              WHERE a.is_attack AND a.attack_cat = ANY(:cats)
                AND p.proto = ANY(:protos)
              GROUP BY a.attack_cat, p.proto""", P)
    if hm.empty:
        st.info("No attack events match the current filters.")
    else:
        piv = hm.pivot(index="attack_cat", columns="proto", values="events").fillna(0)
        st.plotly_chart(px.imshow(piv, text_auto=True, aspect="auto",
                                  color_continuous_scale="Reds"), width="stretch")
    st.subheader("Top destination ports under attack (filtered)")
    pt = q("""SELECT d.port, COUNT(*) AS attacks
              FROM fact_attack_events f
              JOIN dim_destination d ON f.dst_key = d.dst_key
              JOIN dim_attack_type a ON f.attack_key = a.attack_key
              JOIN dim_protocol p ON f.proto_key = p.proto_key
              WHERE a.is_attack AND a.attack_cat = ANY(:cats)
                AND p.proto = ANY(:protos)
              GROUP BY d.port ORDER BY attacks DESC LIMIT 10""", P)
    pt["port"] = pt["port"].astype(str)
    st.plotly_chart(px.bar(pt, x="port", y="attacks").update_xaxes(type="category", title="destination port"), width="stretch")

with tab3:
    st.subheader("Attack detection: supervised vs unsupervised")
    res = pd.DataFrame({
        "Model": ["Random Forest", "XGBoost", "Isolation Forest"],
        "Uses labels": ["Yes", "Yes", "No"],
        "Precision": [0.9535, 0.8558, 0.3014],
        "Recall": [0.9545, 0.9980, 0.3014],
        "PR-AUC": [0.9920, 0.9925, 0.3132],
    })
    st.dataframe(res, hide_index=True, width="stretch")
    st.caption("Random Forest and XGBoost: stratified 80/20 test split. "
               "Isolation Forest: scored on all events after flagging the top 3.17%. "
               "PR-AUC random baseline: 0.0317.")
    fl = pd.DataFrame({
        "category": ["Backdoors", "Analysis", "DoS", "Shellcode", "Exploits",
                     "Fuzzers", "Worms", "Generic", "Reconnaissance"],
        "flagged": [0.6067, 0.5684, 0.5304, 0.5067, 0.4254,
                    0.3267, 0.2917, 0.1692, 0.0625]})
    st.plotly_chart(px.bar(fl, x="category", y="flagged",
                           title="Share flagged by Isolation Forest, by attack category"),
                    width="stretch")




with tab4:
    st.subheader("Attack events by ATT&CK tactic")
    tac = q("""WITH ct AS (
                   SELECT DISTINCT b.attack_key,
                          trim(unnest(string_to_array(t.tactic, ','))) AS tactic
                   FROM bridge_attack_mitre b
                   JOIN dim_mitre_technique t ON b.technique_key = t.technique_key),
               ev AS (
                   SELECT attack_key, COUNT(*) AS events
                   FROM fact_attack_events GROUP BY attack_key)
               SELECT ct.tactic, SUM(ev.events) AS events
               FROM ct JOIN ev ON ev.attack_key = ct.attack_key
               GROUP BY ct.tactic ORDER BY events DESC""")
    st.plotly_chart(px.bar(tac, x="tactic", y="events"), width="stretch")
    st.caption("An attack category can span several tactics, so an event may count "
               "under more than one bar. The mapping is analyst-defined from the "
               "UNSW-NB15 category descriptions, not a label from the dataset.")
    st.subheader("Attack category to ATT&CK technique mapping")
    mp = q("""SELECT a.attack_cat AS category, t.technique_id, t.technique_name,
                     t.tactic, b.confidence
              FROM bridge_attack_mitre b
              JOIN dim_attack_type a ON a.attack_key = b.attack_key
              JOIN dim_mitre_technique t ON t.technique_key = b.technique_key
              ORDER BY a.attack_cat, t.technique_id""")
    st.dataframe(mp, hide_index=True, width="stretch")
