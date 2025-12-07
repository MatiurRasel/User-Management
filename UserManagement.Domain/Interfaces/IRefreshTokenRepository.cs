using UserManagement.Domain.Entities;

namespace UserManagement.Domain.Interfaces;

public interface IRefreshTokenRepository : IRepository<RefreshToken>
{
    Task<RefreshToken?> GetByTokenAsync(string token);
    Task<IEnumerable<RefreshToken>> GetActiveTokensByUserIdAsync(string userId);
    Task RevokeAllUserTokensAsync(string userId);
    Task RemoveExpiredTokensAsync();
}
