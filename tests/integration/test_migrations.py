"""Exercise the real dbmate CLI against a disposable PostgreSQL database."""
import psycopg
from conftest import run_migrations


def test_baseline_apply_rollback_reapply(postgres_container):
    url = postgres_container.get_connection_url().replace(
        "postgresql+psycopg2", "postgresql"
    ) + "?sslmode=disable"

    def objects():
        with psycopg.connect(url) as conn:
            tables = conn.execute(
                "SELECT tablename FROM pg_tables WHERE schemaname = 'public' "
                "AND tablename <> 'schema_migrations' ORDER BY tablename"
            ).fetchall()
            functions = conn.execute(
                "SELECT proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = 'public' AND p.prolang = "
                "(SELECT oid FROM pg_language WHERE lanname = 'plpgsql') ORDER BY proname"
            ).fetchall()
            enums = conn.execute(
                "SELECT typname FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace "
                "WHERE n.nspname = 'public' AND typtype = 'e' ORDER BY typname"
            ).fetchall()
            triggers = conn.execute(
                "SELECT tgname FROM pg_trigger WHERE NOT tgisinternal ORDER BY tgname"
            ).fetchall()
            return tables, functions, enums, triggers

    run_migrations(url)
    before = objects()
    assert {r[0] for r in before[0]} == {
        "users", "sessions", "secrets", "secret_keys", "audit_logs",
        "secret_recipients", "secret_tracking", "secret_views",
        "email_verifications",
        "secret_versions", "user_quotas", "pending_uploads",
        "object_deletion_outbox",
        "secret_access_policies",
    }
    assert len(before[1]) == 6
    assert len(before[2]) == 3
    assert len(before[3]) == 6
    run_migrations(url)  # Already-applied migrations are a no-op.
    assert objects() == before
    try:
        run_migrations(url, "rollback")
        after_feature_rollback = objects()
        assert {r[0] for r in after_feature_rollback[0]} == {
            "users", "sessions", "secrets", "secret_keys", "audit_logs",
            "secret_recipients", "secret_tracking", "secret_views",
            "email_verifications", "secret_versions", "user_quotas",
            "pending_uploads", "object_deletion_outbox",
        }
        assert len(after_feature_rollback[1]) == 6
        assert len(after_feature_rollback[2]) == 3
        assert len(after_feature_rollback[3]) == 6

        run_migrations(url, "rollback")
        after_quota_rollback = objects()
        assert {r[0] for r in after_quota_rollback[0]} == {
            "users", "sessions", "secrets", "secret_keys", "audit_logs",
            "secret_recipients", "secret_tracking", "secret_views",
            "email_verifications", "secret_versions",
            "pending_uploads", "object_deletion_outbox",
        }
        assert len(after_quota_rollback[1]) == 6
        assert len(after_quota_rollback[2]) == 3
        assert len(after_quota_rollback[3]) == 6

        run_migrations(url, "rollback")
        after_file_rollback = objects()
        assert {r[0] for r in after_file_rollback[0]} == {
            "users", "sessions", "secrets", "secret_keys", "audit_logs",
            "secret_recipients", "secret_tracking", "secret_views",
            "email_verifications", "secret_versions",
        }
        assert len(after_file_rollback[1]) == 5
        assert len(after_file_rollback[2]) == 3
        assert len(after_file_rollback[3]) == 5

        run_migrations(url, "rollback")
        after_version_rollback = objects()
        assert {r[0] for r in after_version_rollback[0]} == {
            "users", "sessions", "secrets", "secret_keys", "audit_logs",
            "secret_recipients", "secret_tracking", "secret_views",
            "email_verifications",
        }
        assert len(after_version_rollback[1]) == 5
        assert len(after_version_rollback[2]) == 3
        assert len(after_version_rollback[3]) == 5

        run_migrations(url, "rollback")
        after_access_rollback = objects()
        assert {r[0] for r in after_access_rollback[0]} == {
            "users", "sessions", "secrets", "secret_keys", "audit_logs"
        }
        assert len(after_access_rollback[1]) == 5
        assert len(after_access_rollback[2]) == 3
        assert len(after_access_rollback[3]) == 5

        run_migrations(url, "rollback")
        assert objects() == ([], [], [], [])
        with psycopg.connect(url) as conn:
            assert conn.execute("SELECT count(*) FROM schema_migrations").fetchone()[0] == 0
    finally:
        run_migrations(url)
    assert objects() == before
    with psycopg.connect(url) as conn:
        secret_id = conn.execute(
            "INSERT INTO secrets(content) VALUES ('migration-test') RETURNING id"
        ).fetchone()[0]
        conn.execute("UPDATE secrets SET view_count = 1 WHERE id = %s", (secret_id,))
        assert conn.execute("SELECT 1 FROM secrets WHERE id = %s", (secret_id,)).fetchone() is None
        conn.rollback()
