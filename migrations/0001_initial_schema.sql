-- Sentinel Database Schema
-- Initial migration for D1 database

-- Analyses table: stores all indicator analysis results
CREATE TABLE IF NOT EXISTS analyses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  indicator TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('ip', 'domain', 'url', 'hash')),
  result TEXT NOT NULL, -- JSON blob with full analysis
  risk_score INTEGER,
  classification TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),

  -- Indexes for common queries
  UNIQUE (indicator, type)
);

CREATE INDEX IF NOT EXISTS idx_analyses_indicator ON analyses(indicator);
CREATE INDEX IF NOT EXISTS idx_analyses_type ON analyses(type);
CREATE INDEX IF NOT EXISTS idx_analyses_created_at ON analyses(created_at);
CREATE INDEX IF NOT EXISTS idx_analyses_risk_score ON analyses(risk_score);

-- API Keys table: for authentication
CREATE TABLE IF NOT EXISTS api_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key_hash TEXT NOT NULL UNIQUE, -- SHA-256 hash of the API key
  name TEXT NOT NULL,
  description TEXT,
  permissions TEXT NOT NULL DEFAULT '["read", "analyze"]', -- JSON array of permissions
  rate_limit_per_minute INTEGER DEFAULT 60,
  rate_limit_per_day INTEGER DEFAULT 10000,
  is_active INTEGER NOT NULL DEFAULT 1,
  last_used_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_is_active ON api_keys(is_active);

-- Rate limiting table: tracks API usage
CREATE TABLE IF NOT EXISTS rate_limits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key_hash TEXT NOT NULL,
  window_start TEXT NOT NULL,
  window_type TEXT NOT NULL CHECK (window_type IN ('minute', 'day')),
  request_count INTEGER NOT NULL DEFAULT 1,

  UNIQUE (key_hash, window_start, window_type)
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_key_hash ON rate_limits(key_hash);
CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limits(window_start, window_type);

-- Threat intel cache table: caches external API responses
CREATE TABLE IF NOT EXISTS threat_intel_cache (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  indicator TEXT NOT NULL,
  source TEXT NOT NULL, -- 'virustotal', 'abuseipdb', 'shodan', 'greynoise', 'dns'
  response TEXT NOT NULL, -- JSON response
  fetched_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,

  UNIQUE (indicator, source)
);

CREATE INDEX IF NOT EXISTS idx_cache_indicator ON threat_intel_cache(indicator);
CREATE INDEX IF NOT EXISTS idx_cache_expires ON threat_intel_cache(expires_at);

-- Audit log table: tracks all API calls for security
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  api_key_id INTEGER,
  action TEXT NOT NULL,
  indicator TEXT,
  ip_address TEXT,
  user_agent TEXT,
  request_path TEXT,
  response_status INTEGER,
  duration_ms INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),

  FOREIGN KEY (api_key_id) REFERENCES api_keys(id)
);

CREATE INDEX IF NOT EXISTS idx_audit_api_key ON audit_log(api_key_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);

-- Saved investigations table: for analyst workflows
CREATE TABLE IF NOT EXISTS investigations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'closed', 'escalated')),
  priority TEXT NOT NULL DEFAULT 'medium' CHECK (priority IN ('low', 'medium', 'high', 'critical')),
  indicators TEXT NOT NULL DEFAULT '[]', -- JSON array of indicator IDs
  notes TEXT,
  analyst_id TEXT, -- External user ID
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  closed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_investigations_status ON investigations(status);
CREATE INDEX IF NOT EXISTS idx_investigations_priority ON investigations(priority);
CREATE INDEX IF NOT EXISTS idx_investigations_analyst ON investigations(analyst_id);

-- Trigger to update updated_at timestamp
CREATE TRIGGER IF NOT EXISTS analyses_updated_at
AFTER UPDATE ON analyses
BEGIN
  UPDATE analyses SET updated_at = datetime('now') WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS investigations_updated_at
AFTER UPDATE ON investigations
BEGIN
  UPDATE investigations SET updated_at = datetime('now') WHERE id = NEW.id;
END;
