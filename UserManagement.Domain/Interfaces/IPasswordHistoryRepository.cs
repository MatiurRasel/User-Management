using UserManagement.Domain.Entities;

namespace UserManagement.Domain.Interfaces;

public interface IPasswordHistoryRepository : IRepository<PasswordHistory>
{
    Task<IEnumerable<PasswordHistory>> GetUserPasswordHistoryAsync(string userId, int count);
    Task<bool> IsPasswordRecentlyUsedAsync(string userId, string passwordHash, int historyCount);
}