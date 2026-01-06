-- =====================================================
-- V2: Normalize roles into separate table and extend schema
-- =====================================================

-- Step 1: Create the roles table
CREATE TABLE roles
(
  id          UUID PRIMARY KEY                  DEFAULT gen_random_uuid(),
  name        VARCHAR(50)              NOT NULL UNIQUE,
  description VARCHAR(255),
  created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Step 2: Insert distinct roles from existing user_roles data
INSERT INTO roles (name, description)
SELECT DISTINCT role, 'Migrated from legacy schema'
FROM user_roles
ON CONFLICT (name) DO NOTHING;

-- Step 3: Ensure default roles exist
INSERT INTO roles (name, description)
VALUES ('ROLE_USER', 'Standard user with basic permissions'),
       ('ROLE_ADMIN', 'Administrator with full access'),
       ('ROLE_AUDITOR', 'Read-only access to audit logs')
ON CONFLICT (name) DO NOTHING;

-- Step 4: Create new user_roles junction table
CREATE TABLE user_roles_new
(
  user_id     UUID                     NOT NULL,
  role_id     UUID                     NOT NULL,
  assigned_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id, role_id),
  CONSTRAINT fk_user_roles_user
    FOREIGN KEY (user_id)
      REFERENCES users (id)
      ON DELETE CASCADE,
  CONSTRAINT fk_user_roles_role
    FOREIGN KEY (role_id)
      REFERENCES roles (id)
      ON DELETE CASCADE
);

-- Step 5: Migrate existing role assignments
INSERT INTO user_roles_new (user_id, role_id, assigned_at)
SELECT ur.user_id, r.id, CURRENT_TIMESTAMP
FROM user_roles ur
       JOIN roles r ON r.name = ur.role;

-- Step 6: Drop old user_roles table and rename new one
DROP TABLE user_roles;
ALTER TABLE user_roles_new
  RENAME TO user_roles;

-- Step 7: Add indexes for user_roles
CREATE INDEX idx_user_roles_user_id ON user_roles (user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles (role_id);

-- =====================================================
-- Step 8: Extend users table
-- =====================================================

ALTER TABLE users
  ADD COLUMN first_name            VARCHAR(100),
  ADD COLUMN last_name             VARCHAR(100),
  ADD COLUMN account_non_locked    BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN lock_time             TIMESTAMP WITH TIME ZONE,
  ADD COLUMN updated_at            TIMESTAMP WITH TIME ZONE,
  ADD COLUMN version               BIGINT  NOT NULL DEFAULT 0;

-- Set default values for existing rows
UPDATE users
SET first_name = COALESCE(first_name, 'Unknown'),
    last_name  = COALESCE(last_name, 'User'),
    updated_at = COALESCE(updated_at, created_at)
WHERE first_name IS NULL
   OR last_name IS NULL
   OR updated_at IS NULL;

-- Make columns NOT NULL after setting defaults
ALTER TABLE users
  ALTER COLUMN first_name SET NOT NULL,
  ALTER COLUMN last_name SET NOT NULL,
  ALTER COLUMN updated_at SET NOT NULL;

-- Update created_at to use timezone if not already
ALTER TABLE users
  ALTER COLUMN created_at TYPE TIMESTAMP WITH TIME ZONE
    USING created_at AT TIME ZONE 'UTC';

-- Add indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
CREATE INDEX IF NOT EXISTS idx_users_enabled ON users (enabled);

-- =====================================================
-- Step 9: Create refresh_tokens table
-- =====================================================

CREATE TABLE refresh_tokens
(
  id         UUID PRIMARY KEY                  DEFAULT gen_random_uuid(),
  user_id    UUID                     NOT NULL,
  token      VARCHAR(255)             NOT NULL UNIQUE,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  revoked    BOOLEAN                  NOT NULL DEFAULT false,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  revoked_at TIMESTAMP WITH TIME ZONE,
  CONSTRAINT fk_refresh_tokens_user
    FOREIGN KEY (user_id)
      REFERENCES users (id)
      ON DELETE CASCADE
);

CREATE INDEX idx_refresh_tokens_token ON refresh_tokens (token);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens (user_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens (expires_at);

-- Partial index for cleanup job (only active tokens)
CREATE INDEX idx_refresh_tokens_active
  ON refresh_tokens (expires_at)
  WHERE revoked = false;
