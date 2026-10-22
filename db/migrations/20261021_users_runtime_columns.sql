-- Additive, idempotent migration for initialized NEXUS databases.
-- Matches the users columns in db/schema.sql; existing rows keep their current values.

SET @nexus_ai_restricted_sql = IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS
   WHERE TABLE_SCHEMA = 'nexus' AND TABLE_NAME = 'users' AND COLUMN_NAME = 'ai_restricted') = 0,
  'ALTER TABLE nexus.users ADD COLUMN ai_restricted TINYINT(1) NOT NULL DEFAULT 0 AFTER pinned',
  'SELECT 1'
);
PREPARE nexus_ai_restricted_stmt FROM @nexus_ai_restricted_sql;
EXECUTE nexus_ai_restricted_stmt;
DEALLOCATE PREPARE nexus_ai_restricted_stmt;

SET @nexus_deleted_at_sql = IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS
   WHERE TABLE_SCHEMA = 'nexus' AND TABLE_NAME = 'users' AND COLUMN_NAME = 'deleted_at') = 0,
  'ALTER TABLE nexus.users ADD COLUMN deleted_at DATETIME NULL AFTER created_at',
  'SELECT 1'
);
PREPARE nexus_deleted_at_stmt FROM @nexus_deleted_at_sql;
EXECUTE nexus_deleted_at_stmt;
DEALLOCATE PREPARE nexus_deleted_at_stmt;

SET @nexus_deleted_by_sql = IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS
   WHERE TABLE_SCHEMA = 'nexus' AND TABLE_NAME = 'users' AND COLUMN_NAME = 'deleted_by') = 0,
  'ALTER TABLE nexus.users ADD COLUMN deleted_by INT UNSIGNED NULL AFTER deleted_at',
  'SELECT 1'
);
PREPARE nexus_deleted_by_stmt FROM @nexus_deleted_by_sql;
EXECUTE nexus_deleted_by_stmt;
DEALLOCATE PREPARE nexus_deleted_by_stmt;

SET @nexus_test_ai_restricted_sql = IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS
   WHERE TABLE_SCHEMA = 'nexus_test' AND TABLE_NAME = 'users' AND COLUMN_NAME = 'ai_restricted') = 0,
  'ALTER TABLE nexus_test.users ADD COLUMN ai_restricted TINYINT(1) NOT NULL DEFAULT 0 AFTER pinned',
  'SELECT 1'
);
PREPARE nexus_test_ai_restricted_stmt FROM @nexus_test_ai_restricted_sql;
EXECUTE nexus_test_ai_restricted_stmt;
DEALLOCATE PREPARE nexus_test_ai_restricted_stmt;

SET @nexus_test_deleted_at_sql = IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS
   WHERE TABLE_SCHEMA = 'nexus_test' AND TABLE_NAME = 'users' AND COLUMN_NAME = 'deleted_at') = 0,
  'ALTER TABLE nexus_test.users ADD COLUMN deleted_at DATETIME NULL AFTER created_at',
  'SELECT 1'
);
PREPARE nexus_test_deleted_at_stmt FROM @nexus_test_deleted_at_sql;
EXECUTE nexus_test_deleted_at_stmt;
DEALLOCATE PREPARE nexus_test_deleted_at_stmt;

SET @nexus_test_deleted_by_sql = IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS
   WHERE TABLE_SCHEMA = 'nexus_test' AND TABLE_NAME = 'users' AND COLUMN_NAME = 'deleted_by') = 0,
  'ALTER TABLE nexus_test.users ADD COLUMN deleted_by INT UNSIGNED NULL AFTER deleted_at',
  'SELECT 1'
);
PREPARE nexus_test_deleted_by_stmt FROM @nexus_test_deleted_by_sql;
EXECUTE nexus_test_deleted_by_stmt;
DEALLOCATE PREPARE nexus_test_deleted_by_stmt;
