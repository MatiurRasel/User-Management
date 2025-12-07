using UserManagement.Domain.Entities;

namespace UserManagement.Domain.Interfaces;

public interface IUserSessionRepository : IRepository<UserSession>
{
    Task<IEnumerable<UserSession>> GetActiveSessionsByUserIdAsync(string userId);
    Task<UserSession?> GetBySessionIdAsync(string sessionId);
    Task RevokeSessionAsync(string sessionId);
    Task RevokeAllUserSessionsAsync(string userId);
    Task<int> GetActiveSessionsCountAsync();
    Task CleanupInactiveSessionsAsync(TimeSpan inactivityThreshold);
}
