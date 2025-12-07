using System.Text.Json;
using UserManagement.Domain.Entities;
using UserManagement.Domain.Enums;
using UserManagement.Domain.Interfaces;
using UserManagement.Domain.Interfaces.Services;

namespace UserManagement.Infrastructure.Services;

public class AuditService : IAuditService
{
    private readonly IUnitOfWork _unitOfWork;

    public AuditService(IUnitOfWork unitOfWork)
    {
        _unitOfWork = unitOfWork;
    }

    public async Task LogActionAsync(string? userId, AuditAction action, string entity, string? entityId = null, object? oldValues = null, object? newValues = null)
    {
        var auditLog = new AuditLog
        {
            UserId = userId,
            Action = action.ToString(),
            Entity = entity,
            EntityId = entityId,
            OldValues = oldValues != null ? JsonSerializer.Serialize(oldValues) : null,
            NewValues = newValues != null ? JsonSerializer.Serialize(newValues) : null,
            Timestamp = DateTime.UtcNow
        };

        await _unitOfWork.AuditLogs.AddAsync(auditLog);
        await _unitOfWork.SaveChangesAsync();
    }

    public async Task LogLoginAttemptAsync(string email, bool isSuccessful, string? ipAddress,
        string? userAgent, string? failureReason = null)
    {
        var loginAttempt = new LoginAttempt
        {
            Email = email,
            IsSuccessful = isSuccessful,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            FailureReason = failureReason,
            AttemptTime = DateTime.UtcNow
        };

        await _unitOfWork.LoginAttempts.AddAsync(loginAttempt);
        await _unitOfWork.SaveChangesAsync();
    }
}
