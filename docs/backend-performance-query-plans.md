# Backend query plan diagnostics

Captured from the actual `get_raw_finding_page` function on an in-memory SQLite database with 1,000 active vulnerabilities in one service, a second empty service, no exceptions, and no observations. Page 2 contains 50 findings. Fresh ORM session; schema indexes are those created by the application models. These plans describe the raw active page only; they do not demonstrate simplified grouping or dashboard performance.

PostgreSQL statements compile with the SQLAlchemy PostgreSQL dialect; no PostgreSQL server was available, so no PostgreSQL execution or EXPLAIN result is claimed. The second pass removes Unicode severity/search Python fallbacks by maintaining normalized scalar columns. Updated simplified/member SQLite plans are embedded in backend-performance-pages.json; the raw plans below document the first-pass checkpoint.

Reproduce the route measurements with `scripts/benchmark-backend.py`. The portable compilation regression is `portal/tests/test_findings_sql.py::test_actual_raw_page_statements_compile_for_sqlite_and_postgresql`.

## Actual SQLite plans

### Statement 1

```sql
SELECT count(*) AS count_1
FROM (SELECT ? AS kind, findings.id AS id, findings.episode_started AS episode, findings.cve AS name
FROM findings
WHERE findings.service_id = ? AND findings.active IS 1 AND NOT (EXISTS (SELECT exceptions.id
FROM exceptions
WHERE exceptions.finding_id = findings.id AND exceptions.revoked_at IS NULL AND exceptions.starts_at <= ? AND exceptions.expires_at > ?)) UNION ALL SELECT ? AS kind, policy_findings.id AS id, policy_findings.episode_started AS episode, policy_findings.finding AS name
FROM policy_findings
WHERE policy_findings.service_id = ? AND policy_findings.active IS 1 AND NOT (EXISTS (SELECT policy_exceptions.id
FROM policy_exceptions
WHERE policy_exceptions.policy_finding_id = policy_findings.id AND policy_exceptions.revoked_at IS NULL AND policy_exceptions.starts_at <= ? AND policy_exceptions.expires_at > ?))) AS anon_1
```

```text
(2, 0, 0, 'CO-ROUTINE anon_1')
(3, 2, 0, 'COMPOUND QUERY')
(4, 3, 0, 'LEFT-MOST SUBQUERY')
(7, 4, 61, 'SEARCH findings USING INDEX ix_findings_active (active=?)')
(15, 4, 0, 'CORRELATED SCALAR SUBQUERY 1')
(20, 15, 60, 'SEARCH exceptions USING INDEX ix_exceptions_finding_id (finding_id=?)')
(42, 3, 0, 'UNION ALL')
(45, 42, 60, 'SEARCH policy_findings USING INDEX ix_policy_findings_service_id (service_id=?)')
(55, 42, 0, 'CORRELATED SCALAR SUBQUERY 3')
(60, 55, 60, 'SEARCH policy_exceptions USING INDEX ix_policy_exceptions_policy_finding_id (policy_finding_id=?)')
(84, 0, 57, 'SCAN anon_1')
```

PostgreSQL compilation (unexecuted):

```sql
SELECT count(*) AS count_1
FROM (SELECT %(param_1)s AS kind, findings.id AS id, findings.episode_started AS episode, findings.cve AS name
FROM findings
WHERE findings.service_id = %(service_id_1)s AND findings.active IS true AND NOT (EXISTS (SELECT exceptions.id
FROM exceptions
WHERE exceptions.finding_id = findings.id AND exceptions.revoked_at IS NULL AND exceptions.starts_at <= %(starts_at_1)s AND exceptions.expires_at > %(expires_at_1)s)) UNION ALL SELECT %(param_2)s AS kind, policy_findings.id AS id, policy_findings.episode_started AS episode, policy_findings.finding AS name
FROM policy_findings
WHERE policy_findings.service_id = %(service_id_2)s AND policy_findings.active IS true AND NOT (EXISTS (SELECT policy_exceptions.id
FROM policy_exceptions
WHERE policy_exceptions.policy_finding_id = policy_findings.id AND policy_exceptions.revoked_at IS NULL AND policy_exceptions.starts_at <= %(starts_at_2)s AND policy_exceptions.expires_at > %(expires_at_2)s))) AS anon_1
```

### Statement 2

```sql
SELECT anon_1.kind, anon_1.id
FROM (SELECT ? AS kind, findings.id AS id, findings.episode_started AS episode, findings.cve AS name
FROM findings
WHERE findings.service_id = ? AND findings.active IS 1 AND NOT (EXISTS (SELECT exceptions.id
FROM exceptions
WHERE exceptions.finding_id = findings.id AND exceptions.revoked_at IS NULL AND exceptions.starts_at <= ? AND exceptions.expires_at > ?)) UNION ALL SELECT ? AS kind, policy_findings.id AS id, policy_findings.episode_started AS episode, policy_findings.finding AS name
FROM policy_findings
WHERE policy_findings.service_id = ? AND policy_findings.active IS 1 AND NOT (EXISTS (SELECT policy_exceptions.id
FROM policy_exceptions
WHERE policy_exceptions.policy_finding_id = policy_findings.id AND policy_exceptions.revoked_at IS NULL AND policy_exceptions.starts_at <= ? AND policy_exceptions.expires_at > ?))) AS anon_1 ORDER BY anon_1.kind, anon_1.episode, anon_1.name, anon_1.id
 LIMIT ? OFFSET ?
```

```text
(2, 0, 0, 'CO-ROUTINE anon_1')
(3, 2, 0, 'COMPOUND QUERY')
(4, 3, 0, 'LEFT-MOST SUBQUERY')
(7, 4, 61, 'SEARCH findings USING INDEX ix_findings_active (active=?)')
(15, 4, 0, 'CORRELATED SCALAR SUBQUERY 1')
(20, 15, 60, 'SEARCH exceptions USING INDEX ix_exceptions_finding_id (finding_id=?)')
(42, 3, 0, 'UNION ALL')
(45, 42, 60, 'SEARCH policy_findings USING INDEX ix_policy_findings_service_id (service_id=?)')
(55, 42, 0, 'CORRELATED SCALAR SUBQUERY 3')
(60, 55, 60, 'SEARCH policy_exceptions USING INDEX ix_policy_exceptions_policy_finding_id (policy_finding_id=?)')
(88, 0, 57, 'SCAN anon_1')
(103, 0, 0, 'USE TEMP B-TREE FOR ORDER BY')
```

PostgreSQL compilation (unexecuted):

```sql
SELECT anon_1.kind, anon_1.id
FROM (SELECT %(param_1)s AS kind, findings.id AS id, findings.episode_started AS episode, findings.cve AS name
FROM findings
WHERE findings.service_id = %(service_id_1)s AND findings.active IS true AND NOT (EXISTS (SELECT exceptions.id
FROM exceptions
WHERE exceptions.finding_id = findings.id AND exceptions.revoked_at IS NULL AND exceptions.starts_at <= %(starts_at_1)s AND exceptions.expires_at > %(expires_at_1)s)) UNION ALL SELECT %(param_2)s AS kind, policy_findings.id AS id, policy_findings.episode_started AS episode, policy_findings.finding AS name
FROM policy_findings
WHERE policy_findings.service_id = %(service_id_2)s AND policy_findings.active IS true AND NOT (EXISTS (SELECT policy_exceptions.id
FROM policy_exceptions
WHERE policy_exceptions.policy_finding_id = policy_findings.id AND policy_exceptions.revoked_at IS NULL AND policy_exceptions.starts_at <= %(starts_at_2)s AND policy_exceptions.expires_at > %(expires_at_2)s))) AS anon_1 ORDER BY anon_1.kind, anon_1.episode, anon_1.name, anon_1.id
 LIMIT %(param_3)s OFFSET %(param_4)s
```

### Statement 3

```sql
SELECT findings.id, findings.service_id, findings.cve, findings.severity, findings.first_seen, findings.episode_started, findings.last_seen, findings.active, findings.resolved_at, findings.recurrence_count
FROM findings
WHERE findings.service_id = ? AND findings.id IN (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
```

```text
(3, 0, 61, 'SEARCH findings USING INDEX ix_findings_service_id (service_id=? AND rowid=?)')
```

### Statement 4

```sql
SELECT exceptions.finding_id AS exceptions_finding_id, exceptions.id AS exceptions_id, exceptions.justification AS exceptions_justification, exceptions.approved_by AS exceptions_approved_by, exceptions.ticket AS exceptions_ticket, exceptions.starts_at AS exceptions_starts_at, exceptions.expires_at AS exceptions_expires_at, exceptions.revoked_at AS exceptions_revoked_at, exceptions.created_at AS exceptions_created_at
FROM exceptions
WHERE exceptions.finding_id IN (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) AND exceptions.revoked_at IS NULL AND exceptions.starts_at <= ? AND exceptions.expires_at > ?
```

```text
(3, 0, 116, 'SEARCH exceptions USING INDEX ix_exceptions_finding_id (finding_id=?)')
```

## Interpretation

SQLite selected the existing active index for vulnerability candidates and the service index for policy candidates; current-exception predicates use the finding foreign-key indexes. The union page needs a temporary order structure; count and ordering are evaluated before bounded finding hydration. Hydration uses the service index with row IDs, and exception hydration uses its finding index. No observation history query appears in this raw page. No new index is proposed from this small synthetic plan alone. Production cardinality, exception distribution, and real PostgreSQL plans are still needed to justify another index.
