using Microsoft.EntityFrameworkCore;
using UserManagement.Domain.Entities;
using UserManagement.Domain.Interfaces;
using UserManagement.Infrastructure.Data;

namespace UserManagement.Infrastructure.Repositories;

public class RefreshTokenRepository : Repository<RefreshToken>, IRefreshTokenRepository
{
    public RefreshTokenRepository(ApplicationDbContext context) : base(context)
    {
    }

    public async Task<RefreshToken?> GetByTokenAsync(string token)
    {
        return await _dbSet
            .Include(t => t.User)
            .FirstOrDefaultAsync(t => t.Token == token);
    }

    public async Task<IEnumerable<RefreshToken>> GetActiveTokensByUserIdAsync(string userId)
    {
        return await _dbSet
            .Where(t => t.UserId == userId && !t.IsRevoked && !t.IsUsed && t.ExpiresAt > DateTime.UtcNow)
            .ToListAsync();
    }

    public async Task RevokeAllUserTokensAsync(string userId)
    {
        var tokens = await _dbSet
            .Where(t => t.UserId == userId && !t.IsRevoked)
            .ToListAsync();

        foreach (var token in tokens)
        {
            token.IsRevoked = true;
        }
    }

    public async Task RemoveExpiredTokensAsync()
    {
        var expiredTokens = await _dbSet
            .Where(t => t.ExpiresAt <= DateTime.UtcNow)
            .ToListAsync();

        _dbSet.RemoveRange(expiredTokens);
    }
}
