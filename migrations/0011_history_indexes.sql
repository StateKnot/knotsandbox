-- Project-scoped stable keyset history reads. No derived display tables.
CREATE INDEX operations_project_history ON operations(tenant_id,project_id,created_at DESC,id DESC);
CREATE INDEX domain_events_project_history ON domain_events(tenant_id,project_id,occurred_at DESC,id DESC);
CREATE INDEX audit_events_project_history ON audit_events(tenant_id,project_id,occurred_at DESC,id DESC);
