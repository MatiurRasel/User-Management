namespace UserManagement.Domain.Enums;

public enum UserStatus
{
    Active = 1,
    Inactive = 2,
    Suspended = 3,
    Deleted = 4,
    PendingVerification = 5
}

public enum TokenType
{
    EmailVerification = 1,
    PasswordReset = 2,
    TwoFactorAuth = 3,
    RefreshToken = 4
}

public enum AuditAction
{
    Create = 1,
    Update = 2,
    Delete = 3,
    Login = 4,
    Logout = 5,
    PasswordChange = 6,
    RoleAssigned = 7,
    RoleRemoved = 8,
    AccountLocked = 9,
    AccountUnlocked = 10
}