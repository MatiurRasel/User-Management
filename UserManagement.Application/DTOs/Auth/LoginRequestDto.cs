using System.ComponentModel.DataAnnotations;
using UserManagement.Application.DTOs.User;

namespace UserManagement.Application.DTOs.Auth;

public class LoginRequestDto
{
    [Required(ErrorMessage = "Email or Username is required")]
    public string EmailOrUsername { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password is required")]
    [DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;

    public bool RememberMe { get; set; }
}
public class LoginResponseDto
{
    public string AccessToken { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; }
    public UserDto User { get; set; } = null!;
    public bool RequiresTwoFactor { get; set; }
}

