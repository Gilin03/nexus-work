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
