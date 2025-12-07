using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using UserManagement.Domain.Entities;
using UserManagement.Domain.Interfaces;

namespace UserManagement.RazorPages.Pages.User;

[Authorize]
public class ProfileModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IUnitOfWork _unitOfWork;

    public ProfileModel(UserManager<ApplicationUser> userManager, IUnitOfWork unitOfWork)
    {
        _userManager = userManager;
        _unitOfWork = unitOfWork;
    }

    public ApplicationUser? CurrentUser { get; set; }
    public IList<string> Roles { get; set; } = new List<string>();
    public UserProfile? UserProfile { get; set; }

    public async Task<IActionResult> OnGetAsync()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        CurrentUser = await _unitOfWork.Users.GetByIdWithProfileAsync(user.Id);
        Roles = await _userManager.GetRolesAsync(user);
        UserProfile = CurrentUser?.UserProfile;

        return Page();
    }
}
