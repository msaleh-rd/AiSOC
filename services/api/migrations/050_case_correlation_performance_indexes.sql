-- 050_case_correlation_performance_indexes.sql
--
-- Performance optimization for automated case correlation and grouping (Phase 3).
--
-- 1. GIN indexes on alerts JSONB entity arrays (affected_hosts, affected_ips, affected_users, affected_assets)
--    Enables fast index-scan evaluation for jsonb array overlap operator (?|) during correlation.
-- 2. Composite B-Tree indexes on aisoc_cases (tenant_id, status, updated_at DESC) and (tenant_id, updated_at DESC)
--    Enables fast index range scans when querying active cases within the sliding correlation window.

BEGIN;

-- GIN indexes for fast JSONB entity intersection
CREATE INDEX IF NOT EXISTS idx_alerts_affected_hosts_gin ON alerts USING GIN (affected_hosts);
CREATE INDEX IF NOT EXISTS idx_alerts_affected_ips_gin ON alerts USING GIN (affected_ips);
CREATE INDEX IF NOT EXISTS idx_alerts_affected_users_gin ON alerts USING GIN (affected_users);
CREATE INDEX IF NOT EXISTS idx_alerts_affected_assets_gin ON alerts USING GIN (affected_assets);

-- Composite B-Tree indexes for active case correlation window lookups
CREATE INDEX IF NOT EXISTS idx_aisoc_cases_tenant_status_updated ON aisoc_cases (tenant_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_aisoc_cases_tenant_updated ON aisoc_cases (tenant_id, updated_at DESC);

COMMIT;
