# Cyber Threat Intelligence Data Warehouse for Attack Pattern and Anomaly Detection

A data warehousing and data mining project: network traffic from the UNSW-NB15 dataset is loaded into a PostgreSQL star schema, queried with OLAP operations, and mined with classification, anomaly detection and pattern discovery, with a Streamlit dashboard on top.

## Architecture

    UNSW-NB15 CSV -> ETL (pandas) -> PostgreSQL star schema -> OLAP queries
                                                            -> Mining (RF, XGBoost, Isolation Forest, K-Means, FP-Growth)
                                                            -> Streamlit dashboard

## Data

UNSW-NB15 raw file `UNSW-NB15_1.csv` (700,001 flows, 3.17% attacks, 9 attack categories). Only part 1 of 4 is loaded.

## Warehouse design (star schema)

- Fact table: `fact_attack_events` (one row per network flow: duration, bytes, packets, TTL, load, jitter, label)
- Dimensions: `dim_time`, `dim_source_ip`, `dim_destination`, `dim_protocol`, `dim_attack_type`

OLAP operations (roll-up, drill-down, slice and dice) are in `sql/02_olap_queries.sql`.

## Results

| Model | Uses labels | Attack precision | Attack recall | PR-AUC |
|---|---|---|---|---|
| Random Forest | Yes | 0.9535 | 0.9545 | 0.9920 |
| XGBoost | Yes | 0.8558 | 0.9980 | 0.9925 |
| Isolation Forest | No | 0.3014 | 0.3014 | 0.3132 |

Supervised models use a stratified 80/20 split with class weighting. The PR-AUC random baseline is 0.0317.

- XGBoost misses 9 of 4,443 test attacks (747 false alarms); Random Forest misses 202 (207 false alarms).
- Isolation Forest flags Backdoors, Analysis, DoS and Shellcode more than 50% of the time, but only 17% of Generic and 6% of Reconnaissance.
- K-Means (10 clusters, silhouette 0.52) puts 60% attacks in one cluster, mostly Generic.
- FP-Growth finds rules such as UDP + state INT + low destination bytes -> Reconnaissance (confidence 0.77, lift 9.7).

## How to run

1. Install PostgreSQL and create the database: `CREATE DATABASE cyber_threat_dw;`
2. Create a virtual environment and install dependencies: `pip install -r requirements.txt`
3. Create a `.env` file in the project root:

        DB_USER=postgres
        DB_PASSWORD=your_password
        DB_HOST=localhost
        DB_PORT=5432
        DB_NAME=cyber_threat_dw

4. Download `UNSW-NB15_1.csv` from the official UNSW-NB15 page and place it in `data/`.
5. Run in order:

        psql -U postgres -d cyber_threat_dw -f sql/01_schema.sql
        python -m src.etl
        python -m src.train_classifiers
        python -m src.anomaly_iforest
        python -m src.pattern_mining
        streamlit run app.py

## Limitations

- All attacks fall in the first three hours of the capture, so time is excluded as a model feature and a stratified random split is used instead of a time-based split.
- UNSW-NB15 is simulated lab traffic with only 40 source IPs, so geographic analysis is not possible. A random split also leaves near-duplicate flows in both train and test, so scores are optimistic compared with real-world traffic.
- Only part 1 of the four raw CSV files is loaded.

## Possible extensions

MITRE ATT&CK mapping, an autoencoder anomaly detector, SHAP feature explanations, and a per-source risk score.
