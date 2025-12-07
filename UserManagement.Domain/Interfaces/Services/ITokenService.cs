using System.Security.Claims;

namespace UserManagement.Domain.Interfaces.Services;

public interface ITokenService
{
    Task<string> GenerateAccessTokenAsync(string userId, IList<string> roles, IList<Claim> claims);
    Task<string> GenerateRefreshTokenAsync();
    ClaimsPrincipal? GetPrincipalFromExpiredToken(string token);
    Task<bool> ValidateRefreshTokenAsync(string token);
    Task RevokeRefreshTokenAsync(string token);
}
