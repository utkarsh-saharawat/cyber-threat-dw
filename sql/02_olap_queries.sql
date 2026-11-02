-- 1. ROLL-UP: events by attack category
SELECT a.attack_cat, COUNT(*) AS events,
       ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 2) AS pct,
       ROUND(AVG(f.duration)::numeric, 4) AS avg_duration
FROM fact_attack_events f
JOIN dim_attack_type a ON f.attack_key = a.attack_key
GROUP BY a.attack_cat
ORDER BY events DESC;

-- 2. DRILL-DOWN: attack share per hour
SELECT t.ts_hour, COUNT(*) AS total_events, SUM(f.label) AS attacks,
       ROUND(100.0 * SUM(f.label) / COUNT(*), 2) AS attack_pct
FROM fact_attack_events f
JOIN dim_time t ON f.time_key = t.time_key
GROUP BY t.ts_hour
ORDER BY t.ts_hour;

-- 3. SLICE + DICE: attacks only (slice), TCP/UDP only (dice)
SELECT a.attack_cat, p.proto, COUNT(*) AS events
FROM fact_attack_events f
JOIN dim_attack_type a ON f.attack_key = a.attack_key
JOIN dim_protocol p ON f.proto_key = p.proto_key
WHERE a.is_attack AND p.proto IN ('tcp', 'udp')
GROUP BY a.attack_cat, p.proto
ORDER BY a.attack_cat, events DESC;
