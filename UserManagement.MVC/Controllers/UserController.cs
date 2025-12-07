using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using UserManagement.Domain.Entities;
using UserManagement.Domain.Interfaces;
using UserManagement.MVC.Models;

namespace UserManagement.MVC.Controllers;

[Authorize]
public class UserController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IUnitOfWork _unitOfWork;
    public UserController(UserManager<ApplicationUser> userManager, IUnitOfWork unitOfWork)
    {
        _userManager = userManager;
        _unitOfWork = unitOfWork;
    }

    [HttpGet]
    public async Task<IActionResult> Profile()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return RedirectToAction("Login", "Account");
        }

        var userWithProfile = await _unitOfWork.Users.GetByIdWithProfileAsync(user.Id);
        var roles = await _userManager.GetRolesAsync(user);

        var model = new ProfileViewModel
        {
            Id = user.Id,
            Email = user.Email!,
            FirstName = user.FirstName,
            LastName = user.LastName,
            PhoneNumber = user.PhoneNumber,
            DateOfBirth = user.DateOfBirth,
            ProfilePicture = user.ProfilePicture,
            EmailConfirmed = user.EmailConfirmed,
            TwoFactorEnabled = user.TwoFactorEnabled,
            Roles = roles.ToList(),
            Address = userWithProfile?.UserProfile?.Address,
            City = userWithProfile?.UserProfile?.City,
            State = userWithProfile?.UserProfile?.State,
            Country = userWithProfile?.UserProfile?.Country,
            PostalCode = userWithProfile?.UserProfile?.PostalCode,
            Bio = userWithProfile?.UserProfile?.Bio,
            Website = userWithProfile?.UserProfile?.Website,
            LinkedInProfile = userWithProfile?.UserProfile?.LinkedInProfile,
            GitHubProfile = userWithProfile?.UserProfile?.GitHubProfile
        };

        return View(model);
    }

    [HttpGet]
    public async Task<IActionResult> Edit()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return RedirectToAction("Login", "Account");
        }

        var userWithProfile = await _unitOfWork.Users.GetByIdWithProfileAsync(user.Id);

        var model = new EditProfileViewModel
        {
            FirstName = user.FirstName,
            LastName = user.LastName,
            PhoneNumber = user.PhoneNumber,
            DateOfBirth = user.DateOfBirth,
            Address = userWithProfile?.UserProfile?.Address,
            City = userWithProfile?.UserProfile?.City,
            State = userWithProfile?.UserProfile?.State,
            Country = userWithProfile?.UserProfile?.Country,
            PostalCode = userWithProfile?.UserProfile?.PostalCode,
            Bio = userWithProfile?.UserProfile?.Bio,
            Website = userWithProfile?.UserProfile?.Website,
            LinkedInProfile = userWithProfile?.UserProfile?.LinkedInProfile,
            GitHubProfile = userWithProfile?.UserProfile?.GitHubProfile
        };

        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Edit(EditProfileViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return RedirectToAction("Login", "Account");
        }

        var userWithProfile = await _unitOfWork.Users.GetByIdWithProfileAsync(user.Id);

        user.FirstName = model.FirstName;
        user.LastName = model.LastName;
        user.PhoneNumber = model.PhoneNumber;
        user.DateOfBirth = model.DateOfBirth;
        user.ModifiedAt = DateTime.UtcNow;

        if (userWithProfile?.UserProfile != null)
        {
            userWithProfile.UserProfile.Address = model.Address;
            userWithProfile.UserProfile.City = model.City;
            userWithProfile.UserProfile.State = model.State;
            userWithProfile.UserProfile.Country = model.Country;
            userWithProfile.UserProfile.PostalCode = model.PostalCode;
            userWithProfile.UserProfile.Bio = model.Bio;
            userWithProfile.UserProfile.Website = model.Website;
            userWithProfile.UserProfile.LinkedInProfile = model.LinkedInProfile;
            userWithProfile.UserProfile.GitHubProfile = model.GitHubProfile;
            userWithProfile.UserProfile.LastProfileUpdate = DateTime.UtcNow;
        }

        var result = await _userManager.UpdateAsync(user);

        if (result.Succeeded)
        {
            await _unitOfWork.SaveChangesAsync();
            TempData["SuccessMessage"] = "Profile updated successfully.";
            return RedirectToAction("Profile");
        }

        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }

        return View(model);
    }

    [HttpGet]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> Index(int pageNumber = 1, int pageSize = 10, string? searchTerm = null)
    {
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

        var userViewModels = new List<UserListViewModel>();

        foreach (var user in users)
        {
            var roles = await _userManager.GetRolesAsync(user);
            userViewModels.Add(new UserListViewModel
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

        ViewBag.PageNumber = pageNumber;
        ViewBag.PageSize = pageSize;
        ViewBag.TotalCount = totalCount;
        ViewBag.TotalPages = (int)Math.Ceiling(totalCount / (double)pageSize);
        ViewBag.SearchTerm = searchTerm;

        return View(userViewModels);
    }
}
