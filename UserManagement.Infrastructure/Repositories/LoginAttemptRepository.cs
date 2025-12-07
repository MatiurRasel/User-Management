using Microsoft.EntityFrameworkCore;
using UserManagement.Domain.Entities;
using UserManagement.Domain.Interfaces;
using UserManagement.Infrastructure.Data;

namespace UserManagement.Infrastructure.Repositories;

public class LoginAttemptRepository : Repository<LoginAttempt>, ILoginAttemptRepository
{
    public LoginAttemptRepository(ApplicationDbContext context) : base(context)
    {
    }

    public async Task<int> GetFailedLoginCountAsync(string email, TimeSpan timeWindow)
    {
        var cutoffTime = DateTime.UtcNow.Subtract(timeWindow);
        return await _dbSet
            .CountAsync(a => a.Email == email && !a.IsSuccessful && a.AttemptTime >= cutoffTime);
    }

    public async Task<IEnumerable<LoginAttempt>> GetRecentAttemptsAsync(string email, int count)
    {
        return await _dbSet
            .Where(a => a.Email == email)
            .OrderByDescending(a => a.AttemptTime)
            .Take(count)
            .ToListAsync();
    }

    public async Task<IEnumerable<LoginAttempt>> GetSuspiciousLoginAttemptsAsync(int failureThreshold)
    {
        var cutoffTime = DateTime.UtcNow.AddHours(-1);
        return await _dbSet
            .Where(a => !a.IsSuccessful && a.AttemptTime >= cutoffTime)
            .GroupBy(a => a.Email)
            .Where(g => g.Count() >= failureThreshold)
            .SelectMany(g => g)
            .ToListAsync();
    }
}