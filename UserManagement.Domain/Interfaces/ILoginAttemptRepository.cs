using UserManagement.Domain.Entities;

namespace UserManagement.Domain.Interfaces;

public interface ILoginAttemptRepository : IRepository<LoginAttempt>
{
    Task<int> GetFailedLoginCountAsync(string email, TimeSpan timeWindow);
    Task<IEnumerable<LoginAttempt>> GetRecentAttemptsAsync(string email, int count);
    Task<IEnumerable<LoginAttempt>> GetSuspiciousLoginAttemptsAsync(int failureThreshold);
}