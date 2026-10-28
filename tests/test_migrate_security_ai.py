import pytest

from scripts import migrate_security_ai


def test_migration_defaults_to_dry_run_without_connecting(monkeypatch, capsys):
    monkeypatch.setattr(migrate_security_ai, "migrate", lambda *_: pytest.fail("dry-run must not connect"))

    assert migrate_security_ai.main(["--database", "nexus_test"]) == 0
    assert "DRY RUN" in capsys.readouterr().out


def test_production_migration_requires_explicit_confirmation(monkeypatch):
    monkeypatch.setattr(migrate_security_ai, "migrate", lambda *_: pytest.fail("must reject before connecting"))

    with pytest.raises(SystemExit):
        migrate_security_ai.main(["--database", "nexus", "--apply"])


def test_migration_requires_explicit_database(monkeypatch):
    monkeypatch.setattr(migrate_security_ai, "migrate", lambda *_: pytest.fail("must reject before connecting"))

    with pytest.raises(SystemExit):
        migrate_security_ai.main([])


def test_migration_uses_only_rerunnable_create_and_scoped_grants():
    assert all("CREATE TABLE IF NOT EXISTS" in ddl for ddl in migrate_security_ai.DDLS)
    assert all("`{db}`." in grant for grant in migrate_security_ai.GRANTS)
    assert not any(word in " ".join(migrate_security_ai.DDLS).upper() for word in ("DROP TABLE", "TRUNCATE TABLE"))


def test_migration_adds_missing_xdr_policy_columns_without_readding_existing_columns():
    class Cursor:
        def __init__(self, columns):
            self.columns = set(columns)
            self.statements = []

        def execute(self, sql):
            self.statements.append(sql)
            if sql.startswith("ALTER TABLE"):
                self.columns.add(sql.split("ADD COLUMN `", 1)[1].split("`", 1)[0])

        def fetchall(self):
            return [(name,) for name in self.columns]

    cursor = Cursor({"assessment_id", "approval_allowed"})

    migrate_security_ai._ensure_policy_columns(cursor)

    assert cursor.columns >= {"approval_allowed", "auto_allowed"}
    assert cursor.statements == [
        "SHOW COLUMNS FROM `security_xdr_assessments`",
        "ALTER TABLE `security_xdr_assessments` ADD COLUMN `auto_allowed` TINYINT(1) NOT NULL DEFAULT 0",
    ]


def test_migration_preserves_existing_pending_r1_approval_candidates():
    class Cursor:
        def __init__(self):
            self.columns = set()
            self.statements = []

        def execute(self, sql):
            self.statements.append(sql)
            if sql.startswith("ALTER TABLE"):
                self.columns.add(sql.split("ADD COLUMN `", 1)[1].split("`", 1)[0])

        def fetchall(self):
            return [(name,) for name in self.columns]

    cursor = Cursor()

    migrate_security_ai._ensure_policy_columns(cursor)

    assert any(
        sql.startswith("UPDATE security_xdr_assessments SET approval_allowed = 1")
        and "status='PENDING'" in sql
        and "verdict='MALICIOUS'" in sql
        and "JSON_LENGTH(rule_ids)=1" in sql
        and "JSON_UNQUOTE(JSON_EXTRACT(rule_ids, '$[0]'))='R1'" in sql
        and "DAYTIME_APPROVAL" in sql
        and "WEEKEND_APPROVAL" in sql
        for sql in cursor.statements
    )
