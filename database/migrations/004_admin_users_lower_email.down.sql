-- Exact mirror of 004_admin_users_lower_email.up.sql.
--
-- The plain UNIQUE(email) constraint from 001_init.up.sql is untouched, so the
-- table returns to its original shape.
DROP INDEX IF EXISTS admin_users_lower_email_key;