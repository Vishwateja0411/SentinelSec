import sqlite3
import os

def migrate_db(db_path: str = "sentinelsec.db"):
    if not os.path.exists(db_path):
        print(f"Database {db_path} does not exist, skipping migration.")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    def add_col_if_missing(table: str, col: str, col_type: str):
        cursor.execute(f"PRAGMA table_info({table})")
        cols = [r[1] for r in cursor.fetchall()]
        if col not in cols:
            print(f"Adding column '{col}' to table '{table}'")
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}")

    # Assessments columns
    add_col_if_missing("assessments", "target_ip", "VARCHAR(64)")
    add_col_if_missing("assessments", "open_ports", "JSON")
    add_col_if_missing("assessments", "owasp_coverage_matrix", "JSON")
    add_col_if_missing("assessments", "executed_methods", "JSON")

    # Findings columns
    add_col_if_missing("findings", "cvss_rationale", "TEXT")
    add_col_if_missing("findings", "tool_version", "VARCHAR(64) DEFAULT '1.0.0'")
    add_col_if_missing("findings", "check_method", "VARCHAR(64) DEFAULT 'configuration_checks'")
    add_col_if_missing("findings", "target_ip", "VARCHAR(64)")
    add_col_if_missing("findings", "open_ports", "JSON")
    add_col_if_missing("findings", "source_file", "VARCHAR(1024)")
    add_col_if_missing("findings", "source_line_start", "INTEGER")
    add_col_if_missing("findings", "source_line_end", "INTEGER")
    add_col_if_missing("findings", "evidence_provenance", "VARCHAR(512)")
    add_col_if_missing("findings", "why_vulnerable", "TEXT")
    add_col_if_missing("findings", "reproduction_steps", "TEXT")
    add_col_if_missing("findings", "expected_insecure_behavior", "TEXT")
    add_col_if_missing("findings", "secure_code_example", "TEXT")
    add_col_if_missing("findings", "regression_test", "TEXT")
    add_col_if_missing("findings", "remediation_verification_status", "VARCHAR(64) DEFAULT 'unverified'")

    conn.commit()
    conn.close()
    print("Database migration successfully applied to", db_path)

if __name__ == "__main__":
    migrate_db()
