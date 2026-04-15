-- ═══════════════════════════════════════════════════════════════
--  ThreatPulse — Seed / Sample Data
--  Run AFTER schema.sql:  SOURCE /path/to/seed.sql;
-- ═══════════════════════════════════════════════════════════════
USE threatpulse;

-- ── DEMO USER  (password: Demo@1234 — bcrypt hash below) ──────
INSERT IGNORE INTO users (first_name, last_name, email, password, avatar, plan, role, is_verified, verified_at)
VALUES
  ('Analyst', 'User',  'analyst@threatpulse.io',
   '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', -- Demo@1234
   'AN', 'pro', 'analyst', 1, NOW()),
  ('Admin',   'Root',  'admin@threatpulse.io',
   '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy',
   'AD', 'enterprise', 'admin', 1, NOW());

-- ── IOC FEED SOURCES ──────────────────────────────────────────
INSERT IGNORE INTO ioc_sources (name, feed_type, status, iocs_24h, sync_frequency, last_synced_at) VALUES
  ('MISP',           'Threat Intel',           'online',   847, 'hourly',   NOW()),
  ('AlienVault OTX', 'Open Threat Exchange',   'online',   612, 'hourly',   NOW()),
  ('VirusTotal',     'File / URL Intel',        'online',   391, 'hourly',   NOW()),
  ('Shodan',         'Exposed Service Intel',   'degraded', 284, 'daily',    NOW() - INTERVAL 2 HOUR),
  ('CISA KEV',       'Known Exploited Vulns',   'online',   127, 'daily',    NOW()),
  ('NVD',            'CVE Database',            'online',    96, 'daily',    NOW()),
  ('Abuse.ch',       'Malware / Botnet Intel',  'online',   103, 'hourly',   NOW()),
  ('Cisco Talos',    'Threat Research Feed',    'online',    27, 'hourly',   NOW());

-- ── SAMPLE IOC ENTRIES ────────────────────────────────────────
INSERT INTO iocs (source_id, ioc_type, value, severity, confidence, tags, description) VALUES
  (1, 'ip',          '185.220.101.47',                  'critical', 95, '["c2","cobalt-strike"]',    'Known Cobalt Strike C2 server'),
  (1, 'domain',      'malicious-update.ru',             'high',     88, '["phishing","dropper"]',    'Phishing dropper domain'),
  (2, 'hash_sha256', 'd41d8cd98f00b204e9800998ecf8427e','high',     90, '["ransomware","lockbit"]',  'LockBit ransomware payload hash'),
  (3, 'url',         'http://evil-cdn.xyz/payload.exe', 'critical', 97, '["malware","downloader"]',  'Active malware download URL'),
  (4, 'ip',          '45.142.212.100',                  'medium',   72, '["scanner","shodan"]',      'Port scanner — repeated probing'),
  (5, 'cve',         'CVE-2025-8812',                   'critical', 99, '["apache","rce"]',          'Apache RCE — actively exploited'),
  (6, 'cve',         'CVE-2024-3400',                   'high',     95, '["panos","firewall"]',      'PAN-OS command injection'),
  (7, 'domain',      'pay-invoice-secure.com',          'high',     84, '["phishing","bec"]',        'BEC phishing domain'),
  (8, 'ip',          '192.168.99.1',                    'low',      50, '["internal"]',              'Internal scan — false positive candidate');

-- ── INCIDENTS ─────────────────────────────────────────────────
INSERT INTO incidents (ref_id, title, description, severity, status, assignee_id, ioc_id, tags) VALUES
  ('INC-0042', 'Cobalt Strike C2 Beacon Detected',
   'EDR telemetry shows beacon traffic to 185.220.101.47 from workstation WS-042. Process tree: explorer.exe → cmd.exe → rundll32.',
   'critical', 'open', 1, 1, '["c2","edr","cobalt-strike"]'),
  ('INC-0041', 'Mass Phishing Campaign — 103 Domains',
   'Threat intel correlates 103 newly registered typo-squatting domains targeting corporate email users. DMARC bypass techniques observed.',
   'high', 'investigating', 1, 8, '["phishing","email","campaign"]'),
  ('INC-0040', 'CVE-2025-8812 — Apache RCE Exposure',
   'Shodan scan reveals 14 externally facing Apache instances running vulnerable versions. PoC exploit code published on GitHub.',
   'high', 'open', 2, 6, '["cve","apache","rce","patch-required"]'),
  ('INC-0039', 'LockBit Ransomware Sample in Quarantine',
   'AV quarantined suspicious binary matching LockBit 3.0 hash on endpoint END-107. Lateral movement not confirmed.',
   'critical', 'investigating', 1, 3, '["ransomware","lockbit","endpoint"]'),
  ('INC-0038', 'Insider Threat Anomaly — Bulk Export',
   'UEBA alert: user account exported >50 000 records from SIEM at 03:14 AM outside business hours.',
   'medium', 'closed', 2, NULL, '["insider","ueba","data-loss"]');

-- ── INCIDENT COMMENTS ─────────────────────────────────────────
INSERT INTO incident_comments (incident_id, user_id, body, is_system) VALUES
  (1, NULL, 'Incident created automatically by EDR integration.', 1),
  (1, 1,    'Isolating WS-042 from network. Running full memory dump.', 0),
  (2, 1,    'Blocking all 103 domains at DNS layer. Notifying affected users.', 0),
  (3, 2,    'Patch window scheduled for this Saturday 02:00 UTC.', 0),
  (5, NULL, 'Incident closed after HR review. No malicious intent confirmed.', 1);

-- ── ALERTS ───────────────────────────────────────────────────
INSERT INTO alerts (user_id, incident_id, alert_type, message, is_read) VALUES
  (NULL, 1, 'critical', 'Critical: Cobalt Strike beacon detected on 185.220.101.47 — INC-0042 opened.', 0),
  (NULL, 2, 'high',     'High: 103 new phishing domains detected and auto-blocked.', 0),
  (NULL, NULL, 'medium','Medium: MISP feed sync completed — 847 new IOCs ingested.', 1),
  (NULL, NULL, 'info',  'Info: Feed health check passed — all 8 sources online.', 1),
  (1,    3, 'high',     'High: CVE-2025-8812 affects 14 internal Apache hosts — patch required.', 0),
  (1,    4, 'critical', 'Critical: LockBit hash matched in quarantine on END-107.', 0);

-- ── ACTIVITY LOG ─────────────────────────────────────────────
INSERT INTO activity_log (event_type, title, description, source, user_id, incident_id) VALUES
  ('detection',     'Cobalt Strike beacon detected',   'EDR flagged C2 traffic to 185.220.101.47',        'EDR Agent',       1, 1),
  ('feed_sync',     'MISP feed sync completed',        '847 new IOCs ingested from MISP community feed',  'MISP',            NULL, NULL),
  ('cve_published', 'CVE-2025-8812 published',         'Apache RCE — CVSS 9.8 — active exploitation',     'NVD',             NULL, NULL),
  ('correlation',   'Phishing campaign correlated',    '103 domains linked to single threat actor group', 'AlienVault OTX',  1, 2),
  ('feed_sync',     'AlienVault OTX sync',             '612 new IOCs ingested',                           'AlienVault OTX',  NULL, NULL),
  ('detection',     'LockBit hash matched',            'Quarantine hit on END-107',                       'AV Engine',       1, 4),
  ('user_action',   'Incident INC-0042 escalated',     'Severity raised to critical by analyst',          'Dashboard',       1, 1),
  ('system',        'Daily threat digest generated',   'Automated digest sent to 2 subscribers',          'Scheduler',       NULL, NULL);

-- ── THREAT MAP ───────────────────────────────────────────────
INSERT INTO threat_map (region, country_code, latitude, longitude, threat_level, threat_name, ioc_count, description) VALUES
  ('Eastern Europe', 'RUS',  55.7558,  37.6176, 'critical', 'APT29 C2 Cluster',      312, 'SVR-linked APT infrastructure — Cobalt Strike & custom implants'),
  ('North America',  'USA',  37.0902, -95.7129, 'high',     'Ransomware Distribution', 187, 'LockBit affiliate staging servers'),
  ('East Asia',      'CHN',  35.8617, 104.1954, 'high',     'APT41 Espionage Ops',    231, 'Dual espionage and financially motivated campaigns'),
  ('Western Europe', 'DEU',  51.1657,  10.4515, 'medium',   'BEC Phishing Wave',       98, 'Business email compromise targeting German finance sector'),
  ('Southeast Asia', 'SGP',   1.3521, 103.8198, 'medium',   'Botnet C2 Nodes',         74, 'Mirai variant botnet command infrastructure'),
  ('Middle East',    'IRN',  32.4279,  53.6880, 'high',     'Destructive Malware Ops', 143, 'Wiper malware campaigns targeting critical infrastructure'),
  ('South America',  'BRA', -14.2350, -51.9253, 'low',      'Banking Trojan Campaign',  41, 'Grandoreiro banking trojan targeting Brazilian financial users');

-- ── WORKSPACES ───────────────────────────────────────────────
INSERT IGNORE INTO workspaces (id, name, description) VALUES
  ('soc',       'SOC Team',   'Security Operations Center — 24/7 monitoring and incident response'),
  ('redteam',   'Red Team',   'Offensive security — adversary simulation and penetration testing'),
  ('executive', 'Executive',  'Executive risk dashboard — board-level security posture view');

INSERT IGNORE INTO workspace_metrics (workspace_id, metric_key, metric_label, metric_value) VALUES
  ('soc',       'active_cases',    'Active Cases',      '14'),
  ('soc',       'pending_triage',  'Pending Triage',    '7'),
  ('soc',       'resolved_today',  'Resolved Today',    '23'),
  ('redteam',   'engagements',     'Active Engagements','3'),
  ('redteam',   'vulns_found',     'Discovered Vulns',  '11'),
  ('redteam',   'reports_pending', 'Reports Pending',   '2'),
  ('executive', 'risk_score',      'Risk Score',        'HIGH'),
  ('executive', 'posture',         'Security Posture',  'Fair'),
  ('executive', 'mtd_incidents',   'MTD Incidents',     '47');

-- ── NOTIFICATION SETTINGS (for demo user) ────────────────────
INSERT IGNORE INTO notification_settings (user_id, setting_key, label, is_enabled) VALUES
  (1, 'email',  'Email Alerts',            1),
  (1, 'push',   'Critical Threat Push',    1),
  (1, 'digest', 'Daily Digest',            0),
  (1, 'feed',   'Feed Sync Notifications', 1),
  (1, 'weekly', 'Weekly Summary',          0);

-- ── DASHBOARD STATS CACHE ────────────────────────────────────
INSERT INTO dashboard_stats (stat_key, stat_value) VALUES
  ('active_threats',  '1544'),
  ('iocs_ingested',   '2487'),
  ('open_incidents',  '27'),
  ('global_risk_pct', '64'),
  ('feed_health_pct', '92')
ON DUPLICATE KEY UPDATE stat_value = VALUES(stat_value), updated_at = NOW();
