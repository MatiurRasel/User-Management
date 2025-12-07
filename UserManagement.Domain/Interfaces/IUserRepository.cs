using UserManagement.Domain.Entities;

namespace UserManagement.Domain.Interfaces;

public interface IUserRepository : IRepository<ApplicationUser>
{
    Task<ApplicationUser?> GetByEmailAsync(string email);
    Task<ApplicationUser?> GetByIdWithProfileAsync(string userId);
    Task<IEnumerable<ApplicationUser>> GetUsersByRoleAsync(string roleName);
    Task<bool> IsEmailUniqueAsync(string email, string? excludeUserId = null);
    Task<IEnumerable<ApplicationUser>> SearchUsersAsync(string searchTerm, int pageNumber, int pageSize);
    Task<int> GetActiveUsersCountAsync();
    Task<IEnumerable<ApplicationUser>> GetRecentUsersAsync(int count);
}
