CREATE TABLE cve_records (
  id TEXT PRIMARY KEY,
  published_at TIMESTAMPTZ,
  last_modified TIMESTAMPTZ,
  description TEXT,
  cvss_score NUMERIC(3,1),
  cvss_severity TEXT,
  cvss_vector TEXT,
  cwe_id TEXT,
  cpe_list JSONB,
  "references" JSONB,
  in_kev BOOLEAN DEFAULT FALSE,
  kev_date_added DATE,
  kev_due_date DATE,
  kev_required_action TEXT,
  kev_ransomware TEXT,
  kev_description TEXT,
  osv_data JSONB,
  affected_packages JSONB,
  ghsa_id TEXT,
  github_advisory JSONB,
  patch_versions JSONB,
  otx_pulse_count INTEGER,
  otx_campaigns JSONB,
  otx_industries JSONB,
  otx_malware_families JSONB,
  partial_enrichment BOOLEAN DEFAULT FALSE,
  enriched_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_cvss ON cve_records(cvss_score DESC);
CREATE INDEX idx_kev ON cve_records(in_kev);
CREATE INDEX idx_published ON cve_records(published_at DESC);
CREATE INDEX idx_kev_due ON cve_records(kev_due_date);
