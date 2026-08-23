-- Account administration: who may create accounts, and who may not.
--
-- WHY A ROLE COLUMN EXISTS AT ALL
-- -------------------------------
-- Migration 008 made every user equal. That was fine while the only user was
-- the bootstrap administrator, and stops being fine the moment a second account
-- exists: without a role, ANY authenticated user could create another, so a
-- single compromised low-privilege session escalates to permanent access by
-- making itself a friend.
--
-- One boolean, not a role system. Two things need separating here — "can use
-- the product" and "can create accounts" — and inventing a permissions matrix
-- for a product with two verbs would be machinery nobody can audit.
--
-- WHAT THIS DELIBERATELY DOES NOT TOUCH
-- --------------------------------------
-- `core/gate.py`. An administrator gains no authority over anybody's estate:
-- the gate decides what may be done to an asset and knows nothing about users,
-- and being able to create accounts must not become being able to scan things.
-- Those stay separate, and `is_admin` appears nowhere in the authorisation path.

ALTER TABLE app_user
    ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT FALSE;

-- Whoever bootstrapped is the administrator. Backfilled rather than defaulted
-- TRUE, because a default of TRUE would silently promote every account created
-- before this migration — and on a fresh install, every account after it.
--
-- `created_by = 'bootstrap'` identifies them precisely; on an instance where
-- somebody was created by other means the fallback is the earliest account,
-- which is the one that had to exist first.
UPDATE app_user SET is_admin = TRUE
 WHERE created_by = 'bootstrap'
    OR id = (SELECT min(id) FROM app_user);

-- A password change should not silently keep every other session alive: the
-- commonest reason to change one is believing somebody else has it.
ALTER TABLE app_user
    ADD COLUMN password_changed_at TIMESTAMPTZ;

-- An account created by an administrator starts with a credential THE
-- ADMINISTRATOR HAS SEEN. It is therefore not yet the user's own account, and
-- this column is what says so: until it clears, the session can reach the
-- password-change endpoint and nothing else.
--
-- FALSE for existing rows, deliberately. The bootstrap administrator chose
-- their own password from the environment and no one else ever saw it; forcing
-- a change on upgrade would be ceremony rather than security.
ALTER TABLE app_user
    ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX app_user_admins ON app_user (org_id) WHERE is_admin;
