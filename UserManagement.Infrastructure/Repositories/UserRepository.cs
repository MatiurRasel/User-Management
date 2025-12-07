using Microsoft.EntityFrameworkCore;
using UserManagement.Domain.Entities;
using UserManagement.Domain.Interfaces;
using UserManagement.Infrastructure.Data;

namespace UserManagement.Infrastructure.Repositories;

public class UserRepository : Repository<ApplicationUser>, IUserRepository
{
    public UserRepository(ApplicationDbContext context) : base(context)
    {
    }

    public async Task<ApplicationUser?> GetByEmailAsync(string email)
    {
        return await _dbSet
            .FirstOrDefaultAsync(u => u.Email == email);
    }

    public async Task<ApplicationUser?> GetByIdWithProfileAsync(string userId)
    {
        return await _dbSet
            .Include(u => u.UserProfile)
            .FirstOrDefaultAsync(u => u.Id == userId);
    }

    public async Task<IEnumerable<ApplicationUser>> GetUsersByRoleAsync(string roleName)
    {
        return await (from user in _context.Users
                      join userRole in _context.UserRoles on user.Id equals userRole.UserId
                      join role in _context.Roles on userRole.RoleId equals role.Id
                      where role.Name == roleName
                      select user).ToListAsync();
    }

    public async Task<bool> IsEmailUniqueAsync(string email, string? excludeUserId = null)
    {
        var query = _dbSet.Where(u => u.Email == email);

        if (!string.IsNullOrEmpty(excludeUserId))
        {
            query = query.Where(u => u.Id != excludeUserId);
        }

        return !await query.AnyAsync();
    }

    public async Task<IEnumerable<ApplicationUser>> SearchUsersAsync(string searchTerm, int pageNumber, int pageSize)
    {
        return await _dbSet
            .Where(u => u.FirstName.Contains(searchTerm) ||
                       u.LastName.Contains(searchTerm) ||
                       u.Email!.Contains(searchTerm))
            .OrderBy(u => u.FirstName)
            .Skip((pageNumber - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();
    }

    public async Task<int> GetActiveUsersCountAsync()
    {
        return await _dbSet.CountAsync(u => u.IsActive);
    }

    public async Task<IEnumerable<ApplicationUser>> GetRecentUsersAsync(int count)
    {
        return await _dbSet
            .OrderByDescending(u => u.CreatedAt)
            .Take(count)
            .ToListAsync();
    }
}
