/******************************************************************************************
            📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.

    File Name: crud.rs
    Path:     src/db/crud.rs

    دور الملف:
    يحتوي هذا الملف على دوال عمليات قاعدة البيانات الأساسية (CRUD) للمشروع.
    يعمل كطبقة وصول بيانات مخصصة ومحَصنة أمنيًا، مما يضمن أن منطق قاعدة البيانات معزول، آمن، وفعال.
    يطبق مبدأ "الأمان على مستوى الصف" (Row-Level Security) لضمان أن المستخدمين لا يمكنهم الوصول إلا إلى بياناتهم الخاصة.

    File Role:
    This file contains the core database operation (CRUD) functions for the project.
    It acts as a dedicated and security-hardened data access layer, ensuring that database logic is isolated, secure, and efficient.
    This file implements "Row-Level Security" to ensure users can only access their own data.
******************************************************************************************/

// سيتم إعادة بناء هذا الملف لاحقًا باستخدام mysql_async فقط.

use mysql_async::Pool;
use mysql_async::Row;
use uuid::Uuid;

// --- User Operations ---

/// جلب مستخدم عبر معرف UUID
/// Fetch a user by their UUID
pub async fn get_user_by_id(
    pool: &Pool,
    user_id: &Uuid,
) -> Result<Option<crate::db::models::User>, mysql_async::Error> {
    let mut conn = pool.get_conn().await?;
    let query = r#"SELECT id, username, email, password_hash, status, created_at, last_login_at FROM users WHERE id = ?"#;
    let row: Option<Row> =
        mysql_async::prelude::Queryable::exec_first(&mut conn, query, (user_id.to_string(),))
            .await?;
    let user = row.map(|row| {
        let last_login_at_str: Option<String> = row.get("last_login_at");
        let last_login_at = last_login_at_str
            .and_then(|s| chrono::NaiveDateTime::parse_from_str(&s, "%Y-%m-%d %H:%M:%S").ok());
        crate::db::models::User {
            id: Uuid::parse_str(row.get::<String, _>("id").unwrap().as_str()).unwrap(),
            username: row.get("username").unwrap(),
            email: row.get("email").unwrap(),
            password_hash: row.get("password_hash").unwrap(),
            status: row.get("status").unwrap(),
            created_at: chrono::NaiveDateTime::parse_from_str(
                &row.get::<String, _>("created_at").unwrap(),
                "%Y-%m-%d %H:%M:%S",
            )
            .unwrap(),
            last_login_at,
        }
    });
    Ok(user)
}

/// جلب مستخدم عبر اسم المستخدم
/// Fetch a user by their username
pub async fn get_user_by_username(
    pool: &Pool,
    username: &str,
) -> Result<Option<crate::db::models::User>, mysql_async::Error> {
    let mut conn = pool.get_conn().await?;
    let query = r#"SELECT id, username, email, password_hash, status, created_at, last_login_at FROM users WHERE username = ?"#;
    let row: Option<Row> =
        mysql_async::prelude::Queryable::exec_first(&mut conn, query, (username,)).await?;
    let user = row.map(|row| {
        let last_login_at_str: Option<String> = row.get("last_login_at");
        let last_login_at = last_login_at_str
            .and_then(|s| chrono::NaiveDateTime::parse_from_str(&s, "%Y-%m-%d %H:%M:%S").ok());
        crate::db::models::User {
            id: Uuid::parse_str(row.get::<String, _>("id").unwrap().as_str()).unwrap(),
            username: row.get("username").unwrap(),
            email: row.get("email").unwrap(),
            password_hash: row.get("password_hash").unwrap(),
            status: row.get("status").unwrap(),
            created_at: chrono::NaiveDateTime::parse_from_str(
                &row.get::<String, _>("created_at").unwrap(),
                "%Y-%m-%d %H:%M:%S",
            )
            .unwrap(),
            last_login_at,
        }
    });
    Ok(user)
}

/// جلب جميع المستخدمين (يمكن للمطور تعديل الاستعلام بسهولة)
/// Fetch all users (developer can easily modify the query)
pub async fn get_all_users(
    pool: &Pool,
) -> Result<Vec<crate::db::models::User>, mysql_async::Error> {
    let mut conn = pool.get_conn().await?;
    let query = r#"SELECT id, username, email, password_hash, status, created_at, last_login_at FROM users"#;
    let rows: Vec<Row> = mysql_async::prelude::Queryable::query(&mut conn, query).await?;
    let users = rows
        .into_iter()
        .map(|row| {
            let last_login_at_str: Option<String> = row.get("last_login_at");
            let last_login_at = last_login_at_str
                .and_then(|s| chrono::NaiveDateTime::parse_from_str(&s, "%Y-%m-%d %H:%M:%S").ok());
            crate::db::models::User {
                id: Uuid::parse_str(row.get::<String, _>("id").unwrap().as_str()).unwrap(),
                username: row.get("username").unwrap(),
                email: row.get("email").unwrap(),
                password_hash: row.get("password_hash").unwrap(),
                status: row.get("status").unwrap(),
                created_at: chrono::NaiveDateTime::parse_from_str(
                    &row.get::<String, _>("created_at").unwrap(),
                    "%Y-%m-%d %H:%M:%S",
                )
                .unwrap(),
                last_login_at,
            }
        })
        .collect();
    Ok(users)
}

/// دالة إضافة مستخدم جديد إلى قاعدة البيانات باستخدام mysql_async.
/// This function inserts a new user into the users table using mysql_async.
pub async fn create_user(
    pool: &Pool,
    username: &str,
    password_hash: &str,
) -> Result<Uuid, mysql_async::Error> {
    // توليد UUID جديد للمستخدم
    let user_id = Uuid::new_v4();
    let mut conn = pool.get_conn().await?;
    let query = r#"
        INSERT INTO users (id, username, password_hash, created_at)
        VALUES (?, ?, ?, NOW())
    "#;
    mysql_async::prelude::Queryable::exec_drop(
        &mut conn,
        query,
        (user_id.to_string(), username, password_hash),
    )
    .await?;
    Ok(user_id)
}

/******************************************************************************************
    دالة تحقق أمني مباشر من قاعدة البيانات
- تتحقق من حالة المستخدم (status) ووقت آخر دخول (last_login_at)
- تستخدم في أي سيناريو أمني (تسجيل دخول، صلاحيات، تدقيق)
- لا تعتمد على كاش أو بيانات مؤقتة، بل على البيانات الحية من قاعدة البيانات

Security verification function (direct DB check)
- Checks user status and last login time (last_login_at)
- Use in any security scenario (login, permissions, auditing)
- Does NOT rely on cache, always queries the live database
******************************************************************************************/

pub async fn verify_user_security(pool: &Pool, user_id: &Uuid) -> Result<bool, mysql_async::Error> {
    let user = get_user_by_id(pool, user_id).await?;
    if let Some(user) = user {
        // تحقق من حالة الحساب (مثال: يجب أن يكون Active)
        // Check account status (example: must be Active)
        if user.status == "active" {
            // تحقق من وجود وقت آخر دخول (اختياري)
            // Check if last_login_at exists (optional)
            if user.last_login_at.is_some() {
                // تحقق أمني ناجح
                // Security check passed
                return Ok(true);
            }
        }
    }
    // فشل التحقق الأمني
    // Security check failed
    Ok(false)
}

/******************************************************************************************
    دالة تحقق أمني متقدمة: المستخدم + الجهاز + الصلاحية
- تتحقق من أن المستخدم نشط، سجل الدخول، يملك الجهاز المطلوب، ويملك الصلاحية المطلوبة
- مفيدة في سيناريوهات التحقق المتقدم (تعدد الأجهزة، صلاحيات خاصة، إلخ)
- توضح للمطور كيف يبني تحقق أمني مركب حسب احتياجه

Advanced security verification: user + device + role
- Checks that user is active, has logged in, owns the device, and has the required role
- Useful for advanced scenarios (multi-device, special permissions, etc.)
- Shows developers how to build composite security checks
******************************************************************************************/

pub async fn verify_user_device_and_role(
    pool: &Pool,
    user_id: &Uuid,
    device_id: &Uuid,
    required_role: &str,
) -> Result<bool, mysql_async::Error> {
    // تحقق من المستخدم
    let user = get_user_by_id(pool, user_id).await?;
    if let Some(user) = user {
        if user.status == "active" && user.last_login_at.is_some() {
            // تحقق من الجهاز
            let mut conn = pool.get_conn().await?;
            let device_query = r#"SELECT id FROM devices WHERE id = ? AND user_id = ?"#;
            let device_row: Option<Row> = mysql_async::prelude::Queryable::exec_first(
                &mut conn,
                device_query,
                (device_id.to_string(), user_id.to_string()),
            )
            .await?;
            if device_row.is_some() {
                // تحقق من الصلاحية (مثال: جدول user_roles)
                let role_query = r#"SELECT role FROM user_roles WHERE user_id = ? AND role = ?"#;
                let role_row: Option<Row> = mysql_async::prelude::Queryable::exec_first(
                    &mut conn,
                    role_query,
                    (user_id.to_string(), required_role),
                )
                .await?;
                if role_row.is_some() {
                    // تحقق أمني مركب ناجح
                    return Ok(true);
                }
            }
        }
    }
    // فشل التحقق الأمني المركب
    Ok(false)
}

// --- يمكن إضافة عمليات CRUD أخرى للأجهزة، المواقع، الأحداث، التنبيهات لاحقًا ---
// --- More CRUD operations for devices, locations, events, alerts can be added later ---
