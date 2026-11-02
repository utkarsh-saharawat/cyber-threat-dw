CREATE TABLE IF NOT EXISTS dim_mitre_technique (
    technique_key   SERIAL PRIMARY KEY,
    technique_id    VARCHAR(12) UNIQUE NOT NULL,
    technique_name  VARCHAR(80) NOT NULL,
    tactic          VARCHAR(60) NOT NULL
);

CREATE TABLE IF NOT EXISTS bridge_attack_mitre (
    attack_key     INT REFERENCES dim_attack_type(attack_key),
    technique_key  INT REFERENCES dim_mitre_technique(technique_key),
    confidence     VARCHAR(10) NOT NULL,
    PRIMARY KEY (attack_key, technique_key)
);

INSERT INTO dim_mitre_technique (technique_id, technique_name, tactic) VALUES
    ('T1595',     'Active Scanning',                        'Reconnaissance'),
    ('T1595.002', 'Vulnerability Scanning',                 'Reconnaissance'),
    ('T1590',     'Gather Victim Network Information',      'Reconnaissance'),
    ('T1046',     'Network Service Discovery',              'Discovery'),
    ('T1190',     'Exploit Public-Facing Application',      'Initial Access'),
    ('T1203',     'Exploitation for Client Execution',      'Execution'),
    ('T1133',     'External Remote Services',               'Initial Access, Persistence'),
    ('T1071',     'Application Layer Protocol',             'Command and Control'),
    ('T1498',     'Network Denial of Service',              'Impact'),
    ('T1499',     'Endpoint Denial of Service',             'Impact'),
    ('T1600',     'Weaken Encryption',                      'Defense Evasion'),
    ('T1055',     'Process Injection',                      'Defense Evasion, Privilege Escalation'),
    ('T1059',     'Command and Scripting Interpreter',      'Execution'),
    ('T1210',     'Exploitation of Remote Services',        'Lateral Movement'),
    ('T1570',     'Lateral Tool Transfer',                  'Lateral Movement')
ON CONFLICT (technique_id) DO NOTHING;

INSERT INTO bridge_attack_mitre (attack_key, technique_key, confidence)
SELECT a.attack_key, t.technique_key, m.confidence
FROM (VALUES
    ('Fuzzers',        'T1595.002', 'Medium'),
    ('Fuzzers',        'T1190',     'Medium'),
    ('Analysis',       'T1595',     'Medium'),
    ('Analysis',       'T1046',     'Medium'),
    ('Backdoors',      'T1133',     'Medium'),
    ('Backdoors',      'T1071',     'Medium'),
    ('DoS',            'T1498',     'High'),
    ('DoS',            'T1499',     'High'),
    ('Exploits',       'T1190',     'High'),
    ('Exploits',       'T1203',     'Medium'),
    ('Generic',        'T1600',     'Low'),
    ('Reconnaissance', 'T1595',     'High'),
    ('Reconnaissance', 'T1046',     'High'),
    ('Reconnaissance', 'T1590',     'Medium'),
    ('Shellcode',      'T1055',     'Medium'),
    ('Shellcode',      'T1059',     'Medium'),
    ('Worms',          'T1210',     'High'),
    ('Worms',          'T1570',     'Medium')
) AS m(attack_cat, technique_id, confidence)
JOIN dim_attack_type a ON a.attack_cat = m.attack_cat
JOIN dim_mitre_technique t ON t.technique_id = m.technique_id
ON CONFLICT DO NOTHING;
