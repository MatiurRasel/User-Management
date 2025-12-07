using System.ComponentModel.DataAnnotations;

namespace UserManagement.Application.DTOs.User;

public class UpdateUserRequestDto
{
    [Required(ErrorMessage = "First name is required")]
    [StringLength(100)]
    public string FirstName { get; set; } = string.Empty;

    [Required(ErrorMessage = "Last name is required")]
    [StringLength(100)]
    public string LastName { get; set; } = string.Empty;

    [Phone(ErrorMessage = "Invalid phone number")]
    public string? PhoneNumber { get; set; }

    public DateTime? DateOfBirth { get; set; }

    public string? Address { get; set; }
    public string? City { get; set; }
    public string? State { get; set; }
    public string? Country { get; set; }
    public string? PostalCode { get; set; }
    public string? Bio { get; set; }
    public string? Website { get; set; }
    public string? LinkedInProfile { get; set; }
    public string? GitHubProfile { get; set; }
}