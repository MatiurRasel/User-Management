using UserManagement.Domain.Enums;

namespace UserManagement.Domain.Interfaces.Services;

public interface IAuditService
{
    Task LogActionAsync(string? userId, AuditAction action, string entity,
        string? entityId = null, object? oldValues = null, object? newValues = null);
    Task LogLoginAttemptAsync(string email, bool isSuccessful, string? ipAddress,
        string? userAgent, string? failureReason = null);
}