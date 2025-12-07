using Microsoft.AspNetCore.Identity;
using UserManagement.Application.DTOs.Auth;
using UserManagement.Application.DTOs.Common;
using UserManagement.Domain.Entities;
using UserManagement.Domain.Interfaces.Services;
using UserManagement.Domain.Interfaces;
using UserManagement.Domain.Enums;
using System.Security.Claims;

namespace UserManagement.Application.Services;

public interface IAuthService
{
    Task<ApiResponse<LoginResponseDto>> LoginAsync(LoginRequestDto request, string? ipAddress, string? userAgent);
    Task<ApiResponse<RegisterResponseDto>> RegisterAsync(RegisterRequestDto request);
    Task<ApiResponse<LoginResponseDto>> RefreshTokenAsync(RefreshTokenRequestDto request, string? ipAddress, string? userAgent);
    Task<ApiResponse<bool>> RevokeTokenAsync(string token);
    Task<ApiResponse<bool>> ForgotPasswordAsync(ForgotPasswordRequestDto request);
    Task<ApiResponse<bool>> ResetPasswordAsync(ResetPasswordRequestDto request);
    Task<ApiResponse<bool>> ChangePasswordAsync(string userId, ChangePasswordRequestDto request);
    Task<ApiResponse<bool>> ConfirmEmailAsync(string userId, string token);
    Task<ApiResponse<bool>> ResendEmailConfirmationAsync(string email);
}
public class AuthService : IAuthService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ITokenService _tokenService;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IAuditService _auditService;
    private readonly IEmailService _emailService;

    public AuthService(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        ITokenService tokenService,
        IUnitOfWork unitOfWork,
        IAuditService auditService,
        IEmailService emailService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _tokenService = tokenService;
        _unitOfWork = unitOfWork;
        _auditService = auditService;
        _emailService = emailService;
    }

    public async Task<ApiResponse<LoginResponseDto>> LoginAsync(LoginRequestDto request, string? ipAddress, string? userAgent)
    {
        try
        {
            var user = await _userManager.FindByEmailAsync(request.EmailOrUsername)
                       ?? await _userManager.FindByNameAsync(request.EmailOrUsername);

            if (user == null)
            {
                await _auditService.LogLoginAttemptAsync(request.EmailOrUsername, false, ipAddress, userAgent, "User not found");
                return ApiResponse<LoginResponseDto>.ErrorResponse("Invalid credentials");
            }

            if (!user.IsActive)
            {
                await _auditService.LogLoginAttemptAsync(user.Email!, false, ipAddress, userAgent, "Account inactive");
                return ApiResponse<LoginResponseDto>.ErrorResponse("Account is inactive");
            }

            var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);

            if (!result.Succeeded)
            {
                var failureReason = result.IsLockedOut ? "Account locked" :
                                  result.IsNotAllowed ? "Email not confirmed" :
                                  result.RequiresTwoFactor ? "2FA required" : "Invalid password";

                await _auditService.LogLoginAttemptAsync(user.Email!, false, ipAddress, userAgent, failureReason);
                return ApiResponse<LoginResponseDto>.ErrorResponse(failureReason);
            }

            // Generate tokens
            var roles = await _userManager.GetRolesAsync(user);
            var claims = await _userManager.GetClaimsAsync(user);
            var accessToken = await _tokenService.GenerateAccessTokenAsync(user.Id, roles, claims.ToList());
            var refreshToken = await _tokenService.GenerateRefreshTokenAsync();

            // Save refresh token
            var refreshTokenEntity = new RefreshToken
            {
                UserId = user.Id,
                Token = refreshToken,
                JwtId = Guid.NewGuid().ToString(),
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddDays(7),
                IpAddress = ipAddress,
                UserAgent = userAgent
            };

            await _unitOfWork.RefreshTokens.AddAsync(refreshTokenEntity);

            // Create session
            var session = new UserSession
            {
                UserId = user.Id,
                SessionId = Guid.NewGuid().ToString(),
                IpAddress = ipAddress,
                UserAgent = userAgent,
                LoginTime = DateTime.UtcNow,
                LastActivity = DateTime.UtcNow
            };

            await _unitOfWork.UserSessions.AddAsync(session);

            // Update last login
            user.LastLoginDate = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            await _unitOfWork.SaveChangesAsync();

            await _auditService.LogLoginAttemptAsync(user.Email!, true, ipAddress, userAgent);
            await _auditService.LogActionAsync(user.Id, AuditAction.Login, "User", user.Id);

            var response = new LoginResponseDto
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                ExpiresAt = DateTime.UtcNow.AddMinutes(30),
                RequiresTwoFactor = result.RequiresTwoFactor,
                User = new DTOs.User.UserDto
                {
                    Id = user.Id,
                    Email = user.Email!,
                    UserName = user.UserName!,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    FullName = user.FullName,
                    IsActive = user.IsActive,
                    EmailConfirmed = user.EmailConfirmed,
                    Roles = roles.ToList()
                }
            };

            return ApiResponse<LoginResponseDto>.SuccessResponse(response, "Login successful");
        }
        catch (Exception ex)
        {
            return ApiResponse<LoginResponseDto>.ErrorResponse($"Login failed: {ex.Message}");
        }
    }

    public async Task<ApiResponse<RegisterResponseDto>> RegisterAsync(RegisterRequestDto request)
    {
        try
        {
            if (await _userManager.FindByEmailAsync(request.Email) != null)
            {
                return ApiResponse<RegisterResponseDto>.ErrorResponse("Email already exists");
            }

            var user = new ApplicationUser
            {
                UserName = request.Email,
                Email = request.Email,
                FirstName = request.FirstName,
                LastName = request.LastName,
                PhoneNumber = request.PhoneNumber,
                DateOfBirth = request.DateOfBirth,
                EmailConfirmed = false,
                IsActive = true,
                CreatedAt = DateTime.UtcNow
            };

            var result = await _userManager.CreateAsync(user, request.Password);

            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(e => e.Description).ToList();
                return ApiResponse<RegisterResponseDto>.ErrorResponse("Registration failed", errors);
            }

            // Assign default role
            await _userManager.AddToRoleAsync(user, "User");

            // Save password history
            var passwordHistory = new PasswordHistory
            {
                UserId = user.Id,
                PasswordHash = user.PasswordHash!,
                CreatedAt = DateTime.UtcNow
            };
            await _unitOfWork.PasswordHistories.AddAsync(passwordHistory);
            await _unitOfWork.SaveChangesAsync();

            // Send email confirmation
            var emailToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            await _emailService.SendEmailVerificationAsync(user.Email, emailToken, user.FullName);

            await _auditService.LogActionAsync(user.Id, AuditAction.Create, "User", user.Id);

            var response = new RegisterResponseDto
            {
                UserId = user.Id,
                Message = "Registration successful. Please check your email to confirm your account.",
                RequiresEmailConfirmation = true
            };

            return ApiResponse<RegisterResponseDto>.SuccessResponse(response, "Registration successful");
        }
        catch (Exception ex)
        {
            return ApiResponse<RegisterResponseDto>.ErrorResponse($"Registration failed: {ex.Message}");
        }
    }

    public async Task<ApiResponse<LoginResponseDto>> RefreshTokenAsync(RefreshTokenRequestDto request, string? ipAddress, string? userAgent)
    {
        try
        {
            var principal = _tokenService.GetPrincipalFromExpiredToken(request.AccessToken);
            if (principal == null)
            {
                return ApiResponse<LoginResponseDto>.ErrorResponse("Invalid access token");
            }

            var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return ApiResponse<LoginResponseDto>.ErrorResponse("Invalid token claims");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null || !user.IsActive)
            {
                return ApiResponse<LoginResponseDto>.ErrorResponse("User not found or inactive");
            }

            var isValidToken = await _tokenService.ValidateRefreshTokenAsync(request.RefreshToken);
            if (!isValidToken)
            {
                return ApiResponse<LoginResponseDto>.ErrorResponse("Invalid or expired refresh token");
            }

            // Mark old refresh token as used
            var oldRefreshToken = await _unitOfWork.RefreshTokens.GetByTokenAsync(request.RefreshToken);
            if (oldRefreshToken != null)
            {
                oldRefreshToken.IsUsed = true;
                _unitOfWork.RefreshTokens.Update(oldRefreshToken);
            }

            // Generate new tokens
            var roles = await _userManager.GetRolesAsync(user);
            var claims = await _userManager.GetClaimsAsync(user);
            var newAccessToken = await _tokenService.GenerateAccessTokenAsync(user.Id, roles, claims.ToList());
            var newRefreshToken = await _tokenService.GenerateRefreshTokenAsync();

            // Save new refresh token
            var refreshTokenEntity = new RefreshToken
            {
                UserId = user.Id,
                Token = newRefreshToken,
                JwtId = Guid.NewGuid().ToString(),
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddDays(7),
                IpAddress = ipAddress,
                UserAgent = userAgent
            };

            await _unitOfWork.RefreshTokens.AddAsync(refreshTokenEntity);
            await _unitOfWork.SaveChangesAsync();

            var response = new LoginResponseDto
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken,
                ExpiresAt = DateTime.UtcNow.AddMinutes(30),
                User = new DTOs.User.UserDto
                {
                    Id = user.Id,
                    Email = user.Email!,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    Roles = roles.ToList()
                }
            };

            return ApiResponse<LoginResponseDto>.SuccessResponse(response, "Token refreshed successfully");
        }
        catch (Exception ex)
        {
            return ApiResponse<LoginResponseDto>.ErrorResponse($"Token refresh failed: {ex.Message}");
        }
    }

    public async Task<ApiResponse<bool>> RevokeTokenAsync(string token)
    {
        try
        {
            await _tokenService.RevokeRefreshTokenAsync(token);
            return ApiResponse<bool>.SuccessResponse(true, "Token revoked successfully");
        }
        catch (Exception ex)
        {
            return ApiResponse<bool>.ErrorResponse($"Token revocation failed: {ex.Message}");
        }
    }

    public async Task<ApiResponse<bool>> ForgotPasswordAsync(ForgotPasswordRequestDto request)
    {
        try
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                // Don't reveal that user doesn't exist
                return ApiResponse<bool>.SuccessResponse(true, "If the email exists, a password reset link has been sent");
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            await _emailService.SendPasswordResetEmailAsync(user.Email!, token, user.FullName);

            return ApiResponse<bool>.SuccessResponse(true, "Password reset email sent");
        }
        catch (Exception ex)
        {
            return ApiResponse<bool>.ErrorResponse($"Failed to send password reset email: {ex.Message}");
        }
    }

    public async Task<ApiResponse<bool>> ResetPasswordAsync(ResetPasswordRequestDto request)
    {
        try
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                return ApiResponse<bool>.ErrorResponse("Invalid request");
            }

            var result = await _userManager.ResetPasswordAsync(user, request.Token, request.NewPassword);

            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(e => e.Description).ToList();
                return ApiResponse<bool>.ErrorResponse("Password reset failed", errors);
            }

            // Save password history
            var passwordHistory = new PasswordHistory
            {
                UserId = user.Id,
                PasswordHash = user.PasswordHash!,
                CreatedAt = DateTime.UtcNow
            };
            await _unitOfWork.PasswordHistories.AddAsync(passwordHistory);
            await _unitOfWork.SaveChangesAsync();

            await _auditService.LogActionAsync(user.Id, AuditAction.PasswordChange, "User", user.Id);
            await _emailService.SendPasswordChangedNotificationAsync(user.Email!, user.FullName);

            return ApiResponse<bool>.SuccessResponse(true, "Password reset successful");
        }
        catch (Exception ex)
        {
            return ApiResponse<bool>.ErrorResponse($"Password reset failed: {ex.Message}");
        }
    }

    public async Task<ApiResponse<bool>> ChangePasswordAsync(string userId, ChangePasswordRequestDto request)
    {
        try
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return ApiResponse<bool>.ErrorResponse("User not found");
            }

            var result = await _userManager.ChangePasswordAsync(user, request.CurrentPassword, request.NewPassword);

            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(e => e.Description).ToList();
                return ApiResponse<bool>.ErrorResponse("Password change failed", errors);
            }

            // Save password history
            var passwordHistory = new PasswordHistory
            {
                UserId = user.Id,
                PasswordHash = user.PasswordHash!,
                CreatedAt = DateTime.UtcNow
            };
            await _unitOfWork.PasswordHistories.AddAsync(passwordHistory);

            // Revoke all refresh tokens for security
            await _unitOfWork.RefreshTokens.RevokeAllUserTokensAsync(userId);
            await _unitOfWork.SaveChangesAsync();

            await _auditService.LogActionAsync(user.Id, AuditAction.PasswordChange, "User", user.Id);

            return ApiResponse<bool>.SuccessResponse(true, "Password changed successfully");
        }
        catch (Exception ex)
        {
            return ApiResponse<bool>.ErrorResponse($"Password change failed: {ex.Message}");
        }
    }

    public async Task<ApiResponse<bool>> ConfirmEmailAsync(string userId, string token)
    {
        try
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return ApiResponse<bool>.ErrorResponse("Invalid confirmation link");
            }

            var result = await _userManager.ConfirmEmailAsync(user, token);

            if (!result.Succeeded)
            {
                return ApiResponse<bool>.ErrorResponse("Email confirmation failed");
            }

            await _emailService.SendWelcomeEmailAsync(user.Email!, user.FullName);
            await _auditService.LogActionAsync(user.Id, AuditAction.Update, "User", user.Id);

            return ApiResponse<bool>.SuccessResponse(true, "Email confirmed successfully");
        }
        catch (Exception ex)
        {
            return ApiResponse<bool>.ErrorResponse($"Email confirmation failed: {ex.Message}");
        }
    }

    public async Task<ApiResponse<bool>> ResendEmailConfirmationAsync(string email)
    {
        try
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null || user.EmailConfirmed)
            {
                return ApiResponse<bool>.SuccessResponse(true, "If the email exists and is not confirmed, a new confirmation email has been sent");
            }

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            await _emailService.SendEmailVerificationAsync(user.Email!, token, user.FullName);

            return ApiResponse<bool>.SuccessResponse(true, "Confirmation email sent");
        }
        catch (Exception ex)
        {
            return ApiResponse<bool>.ErrorResponse($"Failed to send confirmation email: {ex.Message}");
        }
    }
}
