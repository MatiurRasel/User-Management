using Microsoft.EntityFrameworkCore;
using UserManagement.Domain.Entities;
using UserManagement.Domain.Interfaces;
using UserManagement.Infrastructure.Data;

namespace UserManagement.Infrastructure.Repositories;

public class PasswordHistoryRepository : Repository<PasswordHistory>, IPasswordHistoryRepository
{
    public PasswordHistoryRepository(ApplicationDbContext context) : base(context)
    {
    }

    public async Task<IEnumerable<PasswordHistory>> GetUserPasswordHistoryAsync(string userId, int count)
    {
        return await _dbSet
            .Where(p => p.UserId == userId)
            .OrderByDescending(p => p.CreatedAt)
            .Take(count)
            .ToListAsync();
    }

    public async Task<bool> IsPasswordRecentlyUsedAsync(string userId, string passwordHash, int historyCount)
    {
        var recentPasswords = await GetUserPasswordHistoryAsync(userId, historyCount);
        return recentPasswords.Any(p => p.PasswordHash == passwordHash);
    }
}