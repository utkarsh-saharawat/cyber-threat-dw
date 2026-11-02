CREATE TABLE IF NOT EXISTS dim_time (
    time_key     SERIAL PRIMARY KEY,
    ts_hour      TIMESTAMP UNIQUE NOT NULL,
    date         DATE NOT NULL,
    year         INT NOT NULL,
    month        INT NOT NULL,
    day          INT NOT NULL,
    hour         INT NOT NULL,
    day_of_week  INT NOT NULL
);

CREATE TABLE IF NOT EXISTS dim_source_ip (
    src_ip_key  SERIAL PRIMARY KEY,
    ip_address  VARCHAR(45) UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS dim_destination (
    dst_key     SERIAL PRIMARY KEY,
    ip_address  VARCHAR(45) NOT NULL,
    port        INT,
    UNIQUE (ip_address, port)
);

CREATE TABLE IF NOT EXISTS dim_protocol (
    proto_key   SERIAL PRIMARY KEY,
    proto       VARCHAR(20) NOT NULL,
    service     VARCHAR(20) NOT NULL,
    state       VARCHAR(20) NOT NULL,
    UNIQUE (proto, service, state)
);

CREATE TABLE IF NOT EXISTS dim_attack_type (
    attack_key  SERIAL PRIMARY KEY,
    attack_cat  VARCHAR(30) UNIQUE NOT NULL,
    is_attack   BOOLEAN NOT NULL
);

CREATE TABLE IF NOT EXISTS fact_attack_events (
    event_id     BIGSERIAL PRIMARY KEY,
    time_key     INT REFERENCES dim_time(time_key),
    src_ip_key   INT REFERENCES dim_source_ip(src_ip_key),
    dst_key      INT REFERENCES dim_destination(dst_key),
    proto_key    INT REFERENCES dim_protocol(proto_key),
    attack_key   INT REFERENCES dim_attack_type(attack_key),
    src_port     INT,
    start_time   TIMESTAMP,
    duration     DOUBLE PRECISION,
    src_bytes    BIGINT,
    dst_bytes    BIGINT,
    src_pkts     INT,
    dst_pkts     INT,
    src_ttl      INT,
    dst_ttl      INT,
    src_load     DOUBLE PRECISION,
    dst_load     DOUBLE PRECISION,
    src_jitter   DOUBLE PRECISION,
    dst_jitter   DOUBLE PRECISION,
    label        SMALLINT NOT NULL,
    anomaly_score DOUBLE PRECISION
);

CREATE INDEX IF NOT EXISTS idx_fact_time   ON fact_attack_events(time_key);
CREATE INDEX IF NOT EXISTS idx_fact_src    ON fact_attack_events(src_ip_key);
CREATE INDEX IF NOT EXISTS idx_fact_attack ON fact_attack_events(attack_key);
