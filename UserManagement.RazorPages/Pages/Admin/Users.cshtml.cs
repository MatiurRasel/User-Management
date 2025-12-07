using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using UserManagement.Domain.Entities;
using UserManagement.Domain.Interfaces;

namespace UserManagement.RazorPages.Pages.Admin;

[Authorize(Roles = "Admin")]
public class UsersModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IUnitOfWork _unitOfWork;

    public UsersModel(UserManager<ApplicationUser> userManager, IUnitOfWork unitOfWork)
    {
        _userManager = userManager;
        _unitOfWork = unitOfWork;
    }

    public List<UserViewModel> Users { get; set; } = new();
    public int PageNumber { get; set; }
    public int TotalPages { get; set; }
    public string? SearchTerm { get; set; }

    public async Task OnGetAsync(int pageNumber = 1, int pageSize = 10, string? searchTerm = null)
    {
        PageNumber = pageNumber;
        SearchTerm = searchTerm;

        IEnumerable<ApplicationUser> users;
        int totalCount;

        if (!string.IsNullOrEmpty(searchTerm))
        {
            users = await _unitOfWork.Users.SearchUsersAsync(searchTerm, pageNumber, pageSize);
            totalCount = await _unitOfWork.Users.CountAsync(u =>
                u.FirstName.Contains(searchTerm) ||
                u.LastName.Contains(searchTerm) ||
                u.Email!.Contains(searchTerm));
        }
        else
        {
            var result = await _unitOfWork.Users.GetPagedAsync(
                pageNumber,
                pageSize,
                orderBy: q => q.OrderByDescending(u => u.CreatedAt)
            );
            users = result.Items;
            totalCount = result.TotalCount;
        }

        foreach (var user in users)
        {
            var roles = await _userManager.GetRolesAsync(user);
            Users.Add(new UserViewModel
            {
                Id = user.Id,
                Email = user.Email!,
                FullName = user.FullName,
                PhoneNumber = user.PhoneNumber,
                IsActive = user.IsActive,
                EmailConfirmed = user.EmailConfirmed,
                CreatedAt = user.CreatedAt,
                LastLoginDate = user.LastLoginDate,
                Roles = string.Join(", ", roles)
            });
        }

        TotalPages = (int)Math.Ceiling(totalCount / (double)pageSize);
    }

    public async Task<IActionResult> OnPostToggleStatusAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound();
        }

        user.IsActive = !user.IsActive;
        user.ModifiedAt = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        if (!user.IsActive)
        {
            await _unitOfWork.UserSessions.RevokeAllUserSessionsAsync(userId);
            await _unitOfWork.RefreshTokens.RevokeAllUserTokensAsync(userId);
            await _unitOfWork.SaveChangesAsync();
        }

        TempData["SuccessMessage"] = $"User {(user.IsActive ? "activated" : "deactivated")} successfully.";
        return RedirectToPage();
    }

    public class UserViewModel
    {
        public string Id { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public string? PhoneNumber { get; set; }
        public bool IsActive { get; set; }
        public bool EmailConfirmed { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? LastLoginDate { get; set; }
        public string Roles { get; set; } = string.Empty;
    }
}
