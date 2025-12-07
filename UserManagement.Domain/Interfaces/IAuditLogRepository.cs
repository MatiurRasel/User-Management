using UserManagement.Domain.Entities;

namespace UserManagement.Domain.Interfaces;

public interface IAuditLogRepository : IRepository<AuditLog>
{
    Task<IEnumerable<AuditLog>> GetUserAuditLogsAsync(string userId, int pageNumber, int pageSize);
    Task<IEnumerable<AuditLog>> GetAuditLogsByEntityAsync(string entity, string entityId);
    Task<IEnumerable<AuditLog>> GetRecentAuditLogsAsync(int count);
}