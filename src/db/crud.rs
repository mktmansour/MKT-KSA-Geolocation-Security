use crate::db::models::{SecurityAlert, User};
use chrono::{NaiveDateTime, Utc};
use rusqlite::params;
use tokio_rusqlite::Connection;
use uuid::Uuid;

fn parse_datetime(value: &str) -> Option<NaiveDateTime> {
    NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S").ok()
}

pub async fn init_schema(pool: &Connection) -> Result<(), tokio_rusqlite::Error> {
    crate::db::migrations::run_migrations(pool).await
}

pub async fn get_user_by_id(
    pool: &Connection,
    user_id: &Uuid,
) -> Result<Option<User>, tokio_rusqlite::Error> {
    let user_id = user_id.to_string();
    pool.call(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT id, username, email, password_hash, status, created_at, last_login_at FROM users WHERE id = ?1",
        )?;

        let mut rows = stmt.query(params![user_id])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };

        let id_str: String = row.get(0)?;
        let created_at_str: String = row.get(5)?;
        let last_login_at_str: Option<String> = row.get(6)?;

        let user = User {
            id: Uuid::parse_str(&id_str).unwrap_or_else(|_| Uuid::nil()),
            username: row.get(1)?,
            email: row.get(2)?,
            password_hash: row.get(3)?,
            status: row.get(4)?,
            created_at: parse_datetime(&created_at_str).unwrap_or_else(|| Utc::now().naive_utc()),
            last_login_at: last_login_at_str.and_then(|s| parse_datetime(&s)),
        };
        Ok(Some(user))
    })
    .await
}

pub async fn upsert_user(pool: &Connection, user: &User) -> Result<(), tokio_rusqlite::Error> {
    let user = user.clone();
    pool.call(move |conn| {
        conn.execute(
            r#"
            INSERT INTO users (id, username, email, password_hash, status, created_at, last_login_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(id) DO UPDATE SET
                username = excluded.username,
                email = excluded.email,
                password_hash = excluded.password_hash,
                status = excluded.status,
                created_at = excluded.created_at,
                last_login_at = excluded.last_login_at
            "#,
            params![
                user.id.to_string(),
                user.username,
                user.email,
                user.password_hash,
                user.status,
                user.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
                user
                    .last_login_at
                    .map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string()),
            ],
        )?;
        Ok(())
    })
    .await
}

pub async fn create_security_alert(
    pool: &Connection,
    alert: &SecurityAlert,
) -> Result<(), tokio_rusqlite::Error> {
    let alert = alert.clone();
    pool.call(move |conn| {
        conn.execute(
            r#"
            INSERT INTO security_alerts (id, user_id, alert_type, alert_data, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
            params![
                alert.id.to_string(),
                alert.user_id.to_string(),
                alert.alert_type,
                alert.alert_data.to_string(),
                alert.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            ],
        )?;
        Ok(())
    })
    .await
}

