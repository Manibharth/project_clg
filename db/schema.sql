-- ═══════════════════════════════════════════════════════════════
--  ThreatPulse — MySQL Schema
--  Run in MySQL Workbench:  SOURCE /path/to/schema.sql;
--  Or paste directly into the Query tab and Execute All.
-- ═══════════════════════════════════════════════════════════════

CREATE DATABASE IF NOT EXISTS threatpulse CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE threatpulse;

-- ─────────────────────────────────────────
--  USERS
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id           INT          NOT NULL AUTO_INCREMENT,
    first_name   VARCHAR(100) NOT NULL,
    last_name    VARCHAR(100) NOT NULL DEFAULT '',
    email        VARCHAR(255) NOT NULL UNIQUE,
    password     VARCHAR(255) NOT NULL,           -- bcrypt hash
    avatar       VARCHAR(10)  NOT NULL DEFAULT 'AN',
    plan         ENUM('free','pro','enterprise')  NOT NULL DEFAULT 'free',
    role         ENUM('analyst','admin','viewer') NOT NULL DEFAULT 'analyst',
    is_active    TINYINT(1)   NOT NULL DEFAULT 1,
    is_verified  TINYINT(1)   NOT NULL DEFAULT 0,
    verified_at  TIMESTAMP    NULL,
    created_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_email (email)
) ENGINE=InnoDB;

-- ─────────────────────────────────────────
--  IOC FEED SOURCES
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ioc_sources (
    id             INT          NOT NULL AUTO_INCREMENT,
    name           VARCHAR(100) NOT NULL,
    feed_type      VARCHAR(100) NOT NULL,
    status         ENUM('online','degraded','offline') NOT NULL DEFAULT 'online',
    iocs_24h       INT          NOT NULL DEFAULT 0,
    sync_frequency VARCHAR(50)  NOT NULL DEFAULT 'hourly',
    last_synced_at TIMESTAMP    NULL,
    api_url        VARCHAR(500) NULL,
    created_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
) ENGINE=InnoDB;

-- ─────────────────────────────────────────
--  IOC ENTRIES  (individual indicators)
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS iocs (
    id           INT          NOT NULL AUTO_INCREMENT,
    source_id    INT          NOT NULL,
    ioc_type     ENUM('ip','domain','url','hash_md5','hash_sha1','hash_sha256','email','cve') NOT NULL,
    value        VARCHAR(500) NOT NULL,
    severity     ENUM('critical','high','medium','low','info') NOT NULL DEFAULT 'medium',
    confidence   TINYINT      NOT NULL DEFAULT 80,   -- 0-100
    tags         JSON         NULL,                  -- ["ransomware","c2"]
    description  TEXT         NULL,
    first_seen   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_active    TINYINT(1)   NOT NULL DEFAULT 1,
    PRIMARY KEY (id),
    INDEX idx_source  (source_id),
    INDEX idx_type    (ioc_type),
    INDEX idx_severity(severity),
    FULLTEXT idx_value(value),
    CONSTRAINT fk_ioc_source FOREIGN KEY (source_id) REFERENCES ioc_sources(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ─────────────────────────────────────────
--  INCIDENTS
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS incidents (
    id           INT          NOT NULL AUTO_INCREMENT,
    ref_id       VARCHAR(20)  NOT NULL UNIQUE,       -- e.g. INC-0042
    title        VARCHAR(255) NOT NULL,
    description  TEXT         NULL,
    severity     ENUM('critical','high','medium','low') NOT NULL DEFAULT 'medium',
    status       ENUM('open','investigating','closed','resolved') NOT NULL DEFAULT 'open',
    assignee_id  INT          NULL,
    ioc_id       INT          NULL,                  -- linked IOC if any
    tags         JSON         NULL,
    created_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    resolved_at  TIMESTAMP    NULL,
    PRIMARY KEY (id),
    INDEX idx_status   (status),
    INDEX idx_severity (severity),
    CONSTRAINT fk_inc_assignee FOREIGN KEY (assignee_id) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT fk_inc_ioc      FOREIGN KEY (ioc_id)      REFERENCES iocs(id)  ON DELETE SET NULL
) ENGINE=InnoDB;

-- ─────────────────────────────────────────
--  INCIDENT COMMENTS / TIMELINE
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS incident_comments (
    id          INT  NOT NULL AUTO_INCREMENT,
    incident_id INT  NOT NULL,
    user_id     INT  NULL,
    body        TEXT NOT NULL,
    is_system   TINYINT(1) NOT NULL DEFAULT 0,   -- 1 = auto-generated status event
    created_at  TIMESTAMP  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_incident (incident_id),
    CONSTRAINT fk_cm_incident FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
    CONSTRAINT fk_cm_user     FOREIGN KEY (user_id)     REFERENCES users(id)     ON DELETE SET NULL
) ENGINE=InnoDB;

-- ─────────────────────────────────────────
--  ALERTS / NOTIFICATIONS
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
    id           INT  NOT NULL AUTO_INCREMENT,
    user_id      INT  NULL,                      -- NULL = broadcast to all
    incident_id  INT  NULL,
    alert_type   ENUM('critical','high','medium','info') NOT NULL DEFAULT 'info',
    message      TEXT NOT NULL,
    is_read      TINYINT(1) NOT NULL DEFAULT 0,
    created_at   TIMESTAMP  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_user    (user_id),
    INDEX idx_is_read (is_read),
    CONSTRAINT fk_alert_user     FOREIGN KEY (user_id)     REFERENCES users(id)      ON DELETE CASCADE,
    CONSTRAINT fk_alert_incident FOREIGN KEY (incident_id) REFERENCES incidents(id)  ON DELETE SET NULL
) ENGINE=InnoDB;

-- ─────────────────────────────────────────
--  ACTIVITY LOG
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS activity_log (
    id          INT          NOT NULL AUTO_INCREMENT,
    event_type  ENUM('detection','feed_sync','cve_published','correlation','user_action','system') NOT NULL,
    title       VARCHAR(255) NOT NULL,
    description TEXT         NULL,
    source      VARCHAR(100) NULL,               -- "AlienVault OTX", "MISP Feed" etc.
    user_id     INT          NULL,
    incident_id INT          NULL,
    metadata    JSON         NULL,
    created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_type      (event_type),
    INDEX idx_created   (created_at),
    CONSTRAINT fk_al_user     FOREIGN KEY (user_id)     REFERENCES users(id)     ON DELETE SET NULL,
    CONSTRAINT fk_al_incident FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ─────────────────────────────────────────
--  THREAT MAP NODES
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS threat_map (
    id           INT            NOT NULL AUTO_INCREMENT,
    region       VARCHAR(100)   NOT NULL,
    country_code CHAR(3)        NULL,
    latitude     DECIMAL(9,6)   NULL,
    longitude    DECIMAL(9,6)   NULL,
    threat_level ENUM('critical','high','medium','low') NOT NULL DEFAULT 'medium',
    threat_name  VARCHAR(255)   NOT NULL,
    ioc_count    INT            NOT NULL DEFAULT 0,
    description  TEXT           NULL,
    last_seen    TIMESTAMP      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    created_at   TIMESTAMP      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_region (region),
    INDEX idx_level  (threat_level)
) ENGINE=InnoDB;

-- ─────────────────────────────────────────
--  WORKSPACES
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS workspaces (
    id          ENUM('soc','redteam','executive') NOT NULL,
    name        VARCHAR(100) NOT NULL,
    description TEXT         NULL,
    PRIMARY KEY (id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS workspace_metrics (
    id           INT          NOT NULL AUTO_INCREMENT,
    workspace_id ENUM('soc','redteam','executive') NOT NULL,
    metric_key   VARCHAR(100) NOT NULL,
    metric_label VARCHAR(150) NOT NULL,
    metric_value VARCHAR(100) NOT NULL,
    updated_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_workspace_key (workspace_id, metric_key),
    CONSTRAINT fk_wm_workspace FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ─────────────────────────────────────────
--  USER NOTIFICATION SETTINGS
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS notification_settings (
    id           INT  NOT NULL AUTO_INCREMENT,
    user_id      INT  NOT NULL,
    setting_key  ENUM('email','push','digest','feed','weekly') NOT NULL,
    label        VARCHAR(150) NOT NULL,
    is_enabled   TINYINT(1)   NOT NULL DEFAULT 1,
    PRIMARY KEY (id),
    UNIQUE KEY uq_user_key (user_id, setting_key),
    CONSTRAINT fk_ns_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ─────────────────────────────────────────
--  CHAT MESSAGES  (AI assistant history)
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS chat_messages (
    id         INT     NOT NULL AUTO_INCREMENT,
    user_id    INT     NOT NULL,
    role       ENUM('user','assistant') NOT NULL,
    content    TEXT    NOT NULL,
    model      VARCHAR(100) NULL DEFAULT 'gemini-2.0-flash',
    mode       ENUM('chat','code','search') NOT NULL DEFAULT 'chat',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_user_chat (user_id, created_at),
    CONSTRAINT fk_chat_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ─────────────────────────────────────────
--  DASHBOARD STATS CACHE  (refreshed by cron)
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS dashboard_stats (
    stat_key   VARCHAR(100) NOT NULL,
    stat_value VARCHAR(255) NOT NULL,
    updated_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (stat_key)
) ENGINE=InnoDB;
