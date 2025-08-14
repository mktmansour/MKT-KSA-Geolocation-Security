/******************************************************************************************
        📍 منصة تحليل الأمان الجغرافي MKT KSA – تطوير منصور بن خالد
* 📄 رخصة Apache 2.0 – يسمح بالاستخدام والتعديل بشرط النسبة وعدم تقديم ضمانات.
* MKT KSA Geolocation Security – Developed by Mansour Bin Khalid (KSA 🇸🇦)
* Licensed under Apache 2.0 – https://www.apache.org/licenses/LICENSE-2.0
* © 2025 All rights reserved.

    File Name: policy.rs
    Path:      src/security/policy.rs

    File Role:
    هذا الملف هو "محرك الحكم الديناميكي" للمشروع. لم يعد مجرد مدقق
    صلاحيات، بل أصبح يتخذ قرارات أمنية بناءً على سياق كامل يشمل هوية
    المستخدم، أدواره، حالته، ودرجة ثقته. يوفر أسبابًا واضحة للرفض،
    مما يسهل عمليات التدقيق والتنبيه.
    --------------------------------------------------------------
    File Name: policy.rs
    Path:      src/security/policy.rs

    File Role:
    This file is the project's "Dynamic Judgment Engine". It is no longer a
    simple permission checker, but makes security decisions based on a full
    context including user identity, roles, status, and trust score. It provides
    clear reasons for denial, facilitating auditing and alerting processes.
******************************************************************************************/

use std::str::FromStr;
use thiserror::Error;
use uuid::Uuid;

/// Arabic: تعريف الأخطاء المخصصة لمحرك السياسات.
/// كل خطأ يمثل سببًا واضحًا لرفض الإجراء.
/// English: Defines custom errors for the policy engine.
/// Each error represents a clear reason for action denial.
#[derive(Error, Debug, PartialEq)]
pub enum PolicyError {
    /// Arabic: المستخدم محظور.
    /// English: The user is banned.
    #[error("User account is banned.")]
    UserBanned,
    /// Arabic: المستخدم موقوف.
    /// English: The user is suspended.
    #[error("User account is suspended.")]
    UserSuspended,
    /// Arabic: صلاحيات غير كافية.
    /// English: Insufficient permissions.
    #[error("Insufficient permissions to perform this action.")]
    InsufficientPermissions,
    /// Arabic: درجة الثقة أقل من المطلوب.
    /// English: Trust score is below the required threshold.
    #[error("User trust score ({0}) is below the required threshold ({1}) for this action.")]
    LowTrustScore(f32, f32),
}

/// Arabic: تعريف حالة المستخدم. هذا يسمح بتطبيق سياسات الإيقاف أو الحظر.
/// English: Defines the user's status. This allows for suspension or ban policies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserStatus {
    /// Arabic: المستخدم نشط.
    /// English: The user is active.
    Active,
    /// Arabic: المستخدم موقوف مؤقتًا.
    /// English: The user is temporarily suspended.
    Suspended,
    /// Arabic: المستخدم محظور بشكل دائم.
    /// English: The user is permanently banned.
    Banned,
}

/// Arabic: تعريف الأدوار المختلفة في النظام.
/// English: Defines the different roles within the system.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    /// Arabic: المستخدم العادي، يمتلك الصلاحيات الأساسية على بياناته فقط.
    /// English: A standard user, has basic permissions on their own data.
    User,
    /// Arabic: مستخدم موثوق، قد يحصل على صلاحيات إضافية بناءً على سجل سلوكه الجيد.
    /// English: A trusted user, may gain additional permissions based on good behavior.
    TrustedUser,
    /// Arabic: مشرف، يمتلك صلاحيات واسعة على المستخدمين والبيانات.
    /// English: A moderator, has broad permissions over users and data.
    Moderator,
    /// Arabic: المدير الأعلى للنظام، يمتلك كل الصلاحيات.
    /// English: The system administrator, possesses all permissions.
    Admin,
}

/// Arabic: تحويل السلسلة النصية (القادمة من توكن JWT) إلى Role.
/// English: Converts a string (from a JWT token) into a Role.
impl FromStr for Role {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "user" => Ok(Role::User),
            "trusted_user" => Ok(Role::TrustedUser),
            "moderator" => Ok(Role::Moderator),
            "admin" => Ok(Role::Admin),
            _ => Err(()),
        }
    }
}

/// Arabic: "سياق السياسة" - يجمع كل المعلومات اللازمة لاتخاذ قرار أمني.
/// هذا هو أساس الانتقال من نظام RBAC البسيط إلى نظام ABAC الذكي.
/// English: "Policy Context" - Gathers all necessary information to make a security decision.
/// This is the foundation for moving from simple RBAC to smart ABAC.
pub struct PolicyContext<'a> {
    /// Arabic: معرّف المستخدم الفريد.
    /// English: The unique identifier for the user.
    pub user_id: Uuid,
    /// Arabic: قائمة الأدوار الممنوحة للمستخدم.
    /// English: A slice of roles assigned to the user.
    pub roles: &'a [Role],
    /// Arabic: الحالة الحالية لحساب المستخدم.
    /// English: The current status of the user's account.
    pub status: &'a UserStatus,
    /// Arabic: درجة ثقة المستخدم (0.0 - 1.0).
    /// English: The user's trust score (0.0 - 1.0).
    pub trust_score: f32,
    // TODO: Add more context like request_ip: IpAddr, device_tier: String
}

/// Arabic: تعريف الإجراءات المختلفة التي يمكن للمستخدم القيام بها.
/// هذا يسمح بفحص الصلاحيات بشكل دقيق ومفصل.
/// English: Defines the different actions a user can perform.
/// This allows for granular and detailed permission checking.
#[derive(Debug, PartialEq)]
pub enum Action<'a> {
    /// Arabic: قراءة المستخدم لبياناته الخاصة.
    /// English: User reading their own data.
    ReadOwnData,
    /// Arabic: تحديث المستخدم لملفه الشخصي.
    /// English: User updating their own profile.
    UpdateOwnProfile,
    /// Arabic: الوصول إلى بيانات جهاز معين.
    /// English: Accessing data for a specific device.
    ReadDeviceData { device_id: Uuid },
    /// Arabic: الوصول إلى بيانات مستخدم آخر (للمشرفين).
    /// English: Accessing another user's data (for admins).
    ReadUserData { target_user_id: &'a Uuid },
    /// Arabic: إنشاء تقرير أمني.
    /// English: Generating a security report.
    GenerateSecurityReport,
    /// Arabic: إجراء حساس يتطلب درجة ثقة عالية.
    /// English: A sensitive action that requires a high trust score.
    PerformSensitiveTransaction,
}

/// Arabic: محرك السياسات الذكي.
/// يستخدم "سياق السياسة" لاتخاذ قرارات دقيقة ومدروسة.
/// English: The smart policy engine.
/// Uses the "Policy Context" to make fine-grained and informed decisions.
pub struct PolicyEngine;

impl PolicyEngine {
    /// Arabic: يتحقق مما إذا كان المستخدم (بناءً على سياقه الكامل) يمكنه تنفيذ إجراء معين.
    /// يعيد سبب الرفض الدقيق في حالة الفشل.
    /// English: Checks if a user (based on their full context) can perform a specific action.
    /// Returns the exact reason for denial on failure.
    pub fn can_execute(context: &PolicyContext, action: &Action) -> Result<(), PolicyError> {
        // --- المرحلة الأولى: التحقق من حالة الحساب ---
        // --- Stage 1: Status Check ---
        match context.status {
            UserStatus::Banned => return Err(PolicyError::UserBanned),
            UserStatus::Suspended => return Err(PolicyError::UserSuspended),
            UserStatus::Active => (), // متابعة
        }

        // --- المرحلة الثانية: تجاوز المدير ---
        // --- Stage 2: Admin Override ---
        if context.roles.contains(&Role::Admin) {
            return Ok(());
        }

        // --- المرحلة الثالثة: التحقق القائم على السياق (ABAC) ---
        // --- Stage 3: Context-Based Checks (ABAC) ---
        match action {
            Action::PerformSensitiveTransaction => {
                let required_score = 0.9;
                if context.trust_score < required_score {
                    return Err(PolicyError::LowTrustScore(
                        context.trust_score,
                        required_score,
                    ));
                }
            }
            _ => (), // لا توجد فحوصات أخرى لدرجة الثقة حاليًا
        }

        // --- المرحلة الرابعة: التحقق القائم على الأدوار (RBAC) ---
        // --- Stage 4: Role-Based Checks (RBAC) ---
        let has_permission = context.roles.iter().any(|role| match action {
            Action::ReadOwnData | Action::UpdateOwnProfile => true,
            Action::ReadDeviceData { .. } => *role >= Role::Moderator,
            Action::ReadUserData { target_user_id } => {
                &context.user_id == *target_user_id || *role >= Role::Moderator
            }
            Action::PerformSensitiveTransaction => *role >= Role::TrustedUser,
            Action::GenerateSecurityReport => *role >= Role::Moderator,
        });

        if has_permission {
            Ok(())
        } else {
            Err(PolicyError::InsufficientPermissions)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Arabic: اختبار الصلاحيات الأساسية لمختلف الأدوار.
    /// English: Tests basic permissions for different roles.
    #[test]
    fn test_permissions() {
        let active_status = UserStatus::Active;
        let user_id = Uuid::new_v4();
        let other_user_id = Uuid::new_v4();

        let user_context = PolicyContext {
            user_id,
            roles: &[Role::User],
            status: &active_status,
            trust_score: 0.7,
        };
        let trusted_user_context = PolicyContext {
            user_id,
            roles: &[Role::User, Role::TrustedUser],
            status: &active_status,
            trust_score: 0.95,
        };
        let moderator_context = PolicyContext {
            user_id,
            roles: &[Role::Moderator],
            status: &active_status,
            trust_score: 0.8,
        };
        let admin_context = PolicyContext {
            user_id,
            roles: &[Role::Admin],
            status: &active_status,
            trust_score: 1.0,
        };

        // --- صلاحيات المستخدم العادي ---
        // --- Basic user permissions ---
        assert_eq!(
            PolicyEngine::can_execute(&user_context, &Action::ReadOwnData),
            Ok(())
        );
        assert_eq!(
            PolicyEngine::can_execute(
                &user_context,
                &Action::ReadUserData {
                    target_user_id: &user_id
                }
            ),
            Ok(())
        );
        assert_eq!(
            PolicyEngine::can_execute(
                &user_context,
                &Action::ReadUserData {
                    target_user_id: &other_user_id
                }
            ),
            Err(PolicyError::InsufficientPermissions)
        );

        // --- صلاحيات المشرف ---
        // --- Moderator permissions ---
        assert_eq!(
            PolicyEngine::can_execute(
                &moderator_context,
                &Action::ReadUserData {
                    target_user_id: &other_user_id
                }
            ),
            Ok(())
        );
        assert_eq!(
            PolicyEngine::can_execute(&moderator_context, &Action::GenerateSecurityReport),
            Ok(())
        );
        assert_eq!(
            PolicyEngine::can_execute(&user_context, &Action::GenerateSecurityReport),
            Err(PolicyError::InsufficientPermissions)
        );

        // --- صلاحيات درجة الثقة ---
        // --- Trust score permissions ---
        assert_eq!(
            PolicyEngine::can_execute(&trusted_user_context, &Action::PerformSensitiveTransaction),
            Ok(())
        );
        assert_eq!(
            PolicyEngine::can_execute(&user_context, &Action::PerformSensitiveTransaction),
            Err(PolicyError::LowTrustScore(0.7, 0.9))
        );

        // --- صلاحيات المدير ---
        // --- Admin override ---
        assert_eq!(
            PolicyEngine::can_execute(&admin_context, &Action::GenerateSecurityReport),
            Ok(())
        );
        assert_eq!(
            PolicyEngine::can_execute(
                &admin_context,
                &Action::ReadUserData {
                    target_user_id: &other_user_id
                }
            ),
            Ok(())
        );
    }

    /// Arabic: اختبار رفض الإجراءات بناءً على حالة الحساب (موقوف/محظور).
    /// English: Tests action denials based on account status (suspended/banned).
    #[test]
    fn test_status_denials() {
        let user_id = Uuid::new_v4();
        let admin_roles = &[Role::Admin];

        let suspended_context = PolicyContext {
            user_id,
            roles: admin_roles,
            status: &UserStatus::Suspended,
            trust_score: 1.0,
        };
        let banned_context = PolicyContext {
            user_id,
            roles: admin_roles,
            status: &UserStatus::Banned,
            trust_score: 1.0,
        };

        // --- حتى المدير يتم حظره بناءً على حالته ---
        // --- Even an admin is blocked by status ---
        assert_eq!(
            PolicyEngine::can_execute(&suspended_context, &Action::ReadOwnData),
            Err(PolicyError::UserSuspended)
        );
        assert_eq!(
            PolicyEngine::can_execute(&banned_context, &Action::ReadOwnData),
            Err(PolicyError::UserBanned)
        );
    }

    /// Arabic: اختبار تحويل السلاسل النصية إلى أدوار.
    /// English: Tests the conversion from strings to roles.
    #[test]
    fn test_role_from_str() {
        assert_eq!(Role::from_str("user").unwrap(), Role::User);
        assert_eq!(Role::from_str("ADMIN").unwrap(), Role::Admin); // Case-insensitive
        assert!(Role::from_str("guest").is_err());
    }
}
