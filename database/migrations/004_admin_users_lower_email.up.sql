-- AdminLogin looks an administrator up case-insensitively:

--   SELECT ... FROM admin_users WHERE lower(email) = lower($1)

-- admin_users.email carries a plain UNIQUE(email) constraint (001_init.up.sql),
-- which builds a btree on the raw column value. A btree on `email` cannot serve
-- an index condition on `lower(email)`, so every sign-in fell back to a
-- sequential scan of admin_users. That matters more than a single login would
-- suggest: the role/active re-check on each authenticated request reads the
-- same table, and the failure path for a bad password runs a dummy bcrypt
-- compare to equalise timing, so the login query is on the hot path and its
-- cost is paid twice.
--
-- A functional index on lower(email) is usable by the query as written and
-- keeps the case-insensitive match that the API contract promises.
--
-- UNIQUE, not plain: the query is a lookup, so it must return at most one
-- account. Two rows differing only by letter case would make AdminLogin's
-- single-row Scan return the first of them and silently authenticate as the
-- wrong administrator. The seed cannot produce that state — cmd/seed lowercases
-- both ADMIN_SEED_EMAIL and OPERATOR_SEED_EMAIL before insert, so a case-only
-- collision would already have been collapsed by the existing ON CONFLICT(email)
-- against the plain UNIQUE constraint.
--
-- IF NOT EXISTS, matching 002 and 003: the migration runner is idempotent for a
-- version it has already recorded, but a database restored from a dump can
-- already carry the index.
CREATE UNIQUE INDEX IF NOT EXISTS admin_users_lower_email_key ON admin_users (lower(email));