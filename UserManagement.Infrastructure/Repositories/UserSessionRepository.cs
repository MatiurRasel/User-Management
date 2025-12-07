using Microsoft.EntityFrameworkCore;
using UserManagement.Domain.Entities;
using UserManagement.Domain.Interfaces;
using UserManagement.Infrastructure.Data;

namespace UserManagement.Infrastructure.Repositories;

public class UserSessionRepository : Repository<UserSession>, IUserSessionRepository
{
    public UserSessionRepository(ApplicationDbContext context) : base(context)
    {
    }

    public async Task<IEnumerable<UserSession>> GetActiveSessionsByUserIdAsync(string userId)
    {
        return await _dbSet
            .Where(s => s.UserId == userId && s.IsActive)
            .OrderByDescending(s => s.LastActivity)
            .ToListAsync();
    }

    public async Task<UserSession?> GetBySessionIdAsync(string sessionId)
    {
        return await _dbSet
            .FirstOrDefaultAsync(s => s.SessionId == sessionId);
    }

    public async Task RevokeSessionAsync(string sessionId)
    {
        var session = await GetBySessionIdAsync(sessionId);
        if (session != null)
        {
            session.IsActive = false;
            session.LogoutTime = DateTime.UtcNow;
        }
    }

    public async Task RevokeAllUserSessionsAsync(string userId)
    {
        var sessions = await _dbSet
            .Where(s => s.UserId == userId && s.IsActive)
            .ToListAsync();

        foreach (var session in sessions)
        {
            session.IsActive = false;
            session.LogoutTime = DateTime.UtcNow;
        }
    }

    public async Task<int> GetActiveSessionsCountAsync()
    {
        return await _dbSet.CountAsync(s => s.IsActive);
    }

    public async Task CleanupInactiveSessionsAsync(TimeSpan inactivityThreshold)
    {
        var cutoffTime = DateTime.UtcNow.Subtract(inactivityThreshold);
        var inactiveSessions = await _dbSet
            .Where(s => s.IsActive && s.LastActivity < cutoffTime)
            .ToListAsync();

        foreach (var session in inactiveSessions)
        {
            session.IsActive = false;
            session.LogoutTime = DateTime.UtcNow;
        }
    }
}