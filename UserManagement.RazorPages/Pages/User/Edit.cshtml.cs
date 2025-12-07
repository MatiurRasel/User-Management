using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using UserManagement.Domain.Entities;
using UserManagement.Domain.Interfaces;

namespace UserManagement.RazorPages.Pages.User;

[Authorize]
public class EditModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IUnitOfWork _unitOfWork;

    public EditModel(UserManager<ApplicationUser> userManager, IUnitOfWork unitOfWork)
    {
        _userManager = userManager;
        _unitOfWork = unitOfWork;
    }

    [BindProperty]
    public InputModel Input { get; set; } = null!;

    public class InputModel
    {
        [Required]
        [StringLength(100)]
        [Display(Name = "First Name")]
        public string FirstName { get; set; } = string.Empty;

        [Required]
        [StringLength(100)]
        [Display(Name = "Last Name")]
        public string LastName { get; set; } = string.Empty;

        [Phone]
        [Display(Name = "Phone Number")]
        public string? PhoneNumber { get; set; }

        [DataType(DataType.Date)]
        [Display(Name = "Date of Birth")]
        public DateTime? DateOfBirth { get; set; }

        public string? Address { get; set; }
        public string? City { get; set; }
        public string? State { get; set; }
        public string? Country { get; set; }

        [Display(Name = "Postal Code")]
        public string? PostalCode { get; set; }

        [StringLength(2000)]
        public string? Bio { get; set; }

        [Url]
        public string? Website { get; set; }

        [Url]
        [Display(Name = "LinkedIn Profile")]
        public string? LinkedInProfile { get; set; }

        [Url]
        [Display(Name = "GitHub Profile")]
        public string? GitHubProfile { get; set; }
    }

    public async Task<IActionResult> OnGetAsync()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        var userWithProfile = await _unitOfWork.Users.GetByIdWithProfileAsync(user.Id);

        Input = new InputModel
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

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        var userWithProfile = await _unitOfWork.Users.GetByIdWithProfileAsync(user.Id);

        user.FirstName = Input.FirstName;
        user.LastName = Input.LastName;
        user.PhoneNumber = Input.PhoneNumber;
        user.DateOfBirth = Input.DateOfBirth;
        user.ModifiedAt = DateTime.UtcNow;

        if (userWithProfile?.UserProfile != null)
        {
            userWithProfile.UserProfile.Address = Input.Address;
            userWithProfile.UserProfile.City = Input.City;
            userWithProfile.UserProfile.State = Input.State;
            userWithProfile.UserProfile.Country = Input.Country;
            userWithProfile.UserProfile.PostalCode = Input.PostalCode;
            userWithProfile.UserProfile.Bio = Input.Bio;
            userWithProfile.UserProfile.Website = Input.Website;
            userWithProfile.UserProfile.LinkedInProfile = Input.LinkedInProfile;
            userWithProfile.UserProfile.GitHubProfile = Input.GitHubProfile;
            userWithProfile.UserProfile.LastProfileUpdate = DateTime.UtcNow;
        }

        var result = await _userManager.UpdateAsync(user);

        if (result.Succeeded)
        {
            await _unitOfWork.SaveChangesAsync();
            TempData["SuccessMessage"] = "Profile updated successfully.";
            return RedirectToPage("./Profile");
        }

        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }

        return Page();
    }
}
