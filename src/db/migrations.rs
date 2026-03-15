use tokio_rusqlite::Connection;

const MIGRATIONS: &[(i64, &str)] = &[
    (1, include_str!("migrations/0001_initial.sql")),
    (2, include_str!("migrations/0002_indexes.sql")),
];

pub async fn run_migrations(pool: &Connection) -> Result<(), tokio_rusqlite::Error> {
    pool.call(|conn| {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY NOT NULL,
                applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now'))
            );
            "#,
        )?;
        Ok(())
    })
    .await?;

    for (version, sql) in MIGRATIONS {
        let version_value = *version;
        let migration_sql = *sql;
        let should_apply = pool
            .call(move |conn| {
                let mut stmt =
                    conn.prepare("SELECT COUNT(1) FROM schema_migrations WHERE version = ?1")?;
                let count: i64 = stmt.query_row([version_value], |row| row.get(0))?;
                Ok(count == 0)
            })
            .await?;

        if !should_apply {
            continue;
        }

        pool.call(move |conn| {
            let tx = conn.transaction()?;
            tx.execute_batch(migration_sql)?;
            tx.execute(
                "INSERT INTO schema_migrations (version) VALUES (?1)",
                [version_value],
            )?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    }

    Ok(())
}
