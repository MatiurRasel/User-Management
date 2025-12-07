using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using UserManagement.Application.DTOs.Common;
using UserManagement.Application.DTOs.User;
using UserManagement.Domain.Entities;
using UserManagement.Domain.Interfaces;

namespace UserManagement.API.Controllers;

[Route("api/[controller]")]
[ApiController]
[Authorize]
public class UsersController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IUnitOfWork _unitOfWork;

    public UsersController(UserManager<ApplicationUser> userManager, IUnitOfWork unitOfWork)
    {
        _userManager = userManager;
        _unitOfWork = unitOfWork;
    }

    /// <summary>
    /// Get all users with pagination
    /// </summary>
    [HttpGet]
    [Authorize(Roles = "Admin,Manager")]
    [ProducesResponseType(typeof(ApiResponse<PagedResultDto<UserDto>>), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetAllUsers([FromQuery] int pageNumber = 1, [FromQuery] int pageSize = 10)
    {
        var (users, totalCount) = await _unitOfWork.Users.GetPagedAsync(
            pageNumber,
            pageSize,
            orderBy: q => q.OrderByDescending(u => u.CreatedAt)
        );

        var userDtos = new List<UserDto>();
        foreach (var user in users)
        {
            var roles = await _userManager.GetRolesAsync(user);
            userDtos.Add(new UserDto
            {
                Id = user.Id,
                Email = user.Email!,
                UserName = user.UserName!,
                FirstName = user.FirstName,
                LastName = user.LastName,
                FullName = user.FullName,
                PhoneNumber = user.PhoneNumber,
                EmailConfirmed = user.EmailConfirmed,
                IsActive = user.IsActive,
                CreatedAt = user.CreatedAt,
                LastLoginDate = user.LastLoginDate,
                Roles = roles.ToList()
            });
        }

        var result = new PagedResultDto<UserDto>
        {
            Items = userDtos,
            PageNumber = pageNumber,
            PageSize = pageSize,
            TotalCount = totalCount
        };

        return Ok(ApiResponse<PagedResultDto<UserDto>>.SuccessResponse(result));
    }

    /// <summary>
    /// Get user by ID
    /// </summary>
    [HttpGet("{id}")]
    [ProducesResponseType(typeof(ApiResponse<UserDto>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<UserDto>), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetUserById(string id)
    {
        var user = await _unitOfWork.Users.GetByIdWithProfileAsync(id);
        if (user == null)
        {
            return NotFound(ApiResponse<UserDto>.ErrorResponse("User not found"));
        }

        var roles = await _userManager.GetRolesAsync(user);

        var userDto = new UserDto
        {
            Id = user.Id,
            Email = user.Email!,
            UserName = user.UserName!,
            FirstName = user.FirstName,
            LastName = user.LastName,
            FullName = user.FullName,
            PhoneNumber = user.PhoneNumber,
            ProfilePicture = user.ProfilePicture,
            DateOfBirth = user.DateOfBirth,
            EmailConfirmed = user.EmailConfirmed,
            PhoneNumberConfirmed = user.PhoneNumberConfirmed,
            TwoFactorEnabled = user.TwoFactorEnabled,
            IsActive = user.IsActive,
            CreatedAt = user.CreatedAt,
            LastLoginDate = user.LastLoginDate,
            Roles = roles.ToList(),
            Profile = user.UserProfile != null ? new UserProfileDto
            {
                Id = user.UserProfile.Id,
                Address = user.UserProfile.Address,
                City = user.UserProfile.City,
                State = user.UserProfile.State,
                Country = user.UserProfile.Country,
                PostalCode = user.UserProfile.PostalCode,
                Bio = user.UserProfile.Bio,
                Website = user.UserProfile.Website,
                LinkedInProfile = user.UserProfile.LinkedInProfile,
                GitHubProfile = user.UserProfile.GitHubProfile
            } : null
        };

        return Ok(ApiResponse<UserDto>.SuccessResponse(userDto));
    }

    /// <summary>
    /// Create new user (Admin only)
    /// </summary>
    [HttpPost]
    [Authorize(Roles = "Admin")]
    [ProducesResponseType(typeof(ApiResponse<UserDto>), StatusCodes.Status201Created)]
    public async Task<IActionResult> CreateUser([FromBody] CreateUserRequestDto request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ApiResponse<UserDto>.ErrorResponse("Invalid request"));
        }

        var existingUser = await _userManager.FindByEmailAsync(request.Email);
        if (existingUser != null)
        {
            return BadRequest(ApiResponse<UserDto>.ErrorResponse("Email already exists"));
        }

        var user = new ApplicationUser
        {
            UserName = request.Email,
            Email = request.Email,
            FirstName = request.FirstName,
            LastName = request.LastName,
            PhoneNumber = request.PhoneNumber,
            DateOfBirth = request.DateOfBirth,
            EmailConfirmed = request.EmailConfirmed,
            IsActive = true,
            CreatedAt = DateTime.UtcNow
        };

        var result = await _userManager.CreateAsync(user, request.Password);

        if (!result.Succeeded)
        {
            var errors = result.Errors.Select(e => e.Description).ToList();
            return BadRequest(ApiResponse<UserDto>.ErrorResponse("User creation failed", errors));
        }

        if (request.Roles.Any())
        {
            await _userManager.AddToRolesAsync(user, request.Roles);
        }

        var roles = await _userManager.GetRolesAsync(user);
        var userDto = new UserDto
        {
            Id = user.Id,
            Email = user.Email,
            UserName = user.UserName!,
            FirstName = user.FirstName,
            LastName = user.LastName,
            FullName = user.FullName,
            Roles = roles.ToList()
        };

        return CreatedAtAction(nameof(GetUserById), new { id = user.Id },
            ApiResponse<UserDto>.SuccessResponse(userDto, "User created successfully"));
    }

    /// <summary>
    /// Update user
    /// </summary>
    [HttpPut("{id}")]
    [ProducesResponseType(typeof(ApiResponse<UserDto>), StatusCodes.Status200OK)]
    public async Task<IActionResult> UpdateUser(string id, [FromBody] UpdateUserRequestDto request)
    {
        var currentUserId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        var isAdmin = User.IsInRole("Admin");

        if (currentUserId != id && !isAdmin)
        {
            return Forbid();
        }

        var user = await _unitOfWork.Users.GetByIdWithProfileAsync(id);
        if (user == null)
        {
            return NotFound(ApiResponse<UserDto>.ErrorResponse("User not found"));
        }

        user.FirstName = request.FirstName;
        user.LastName = request.LastName;
        user.PhoneNumber = request.PhoneNumber;
        user.DateOfBirth = request.DateOfBirth;
        user.ModifiedAt = DateTime.UtcNow;
        user.ModifiedBy = currentUserId;

        if (user.UserProfile != null)
        {
            user.UserProfile.Address = request.Address;
            user.UserProfile.City = request.City;
            user.UserProfile.State = request.State;
            user.UserProfile.Country = request.Country;
            user.UserProfile.PostalCode = request.PostalCode;
            user.UserProfile.Bio = request.Bio;
            user.UserProfile.Website = request.Website;
            user.UserProfile.LinkedInProfile = request.LinkedInProfile;
            user.UserProfile.GitHubProfile = request.GitHubProfile;
            user.UserProfile.LastProfileUpdate = DateTime.UtcNow;
        }

        var result = await _userManager.UpdateAsync(user);
        if (!result.Succeeded)
        {
            return BadRequest(ApiResponse<UserDto>.ErrorResponse("Update failed"));
        }

        await _unitOfWork.SaveChangesAsync();

        var roles = await _userManager.GetRolesAsync(user);
        var userDto = new UserDto
        {
            Id = user.Id,
            Email = user.Email!,
            FirstName = user.FirstName,
            LastName = user.LastName,
            Roles = roles.ToList()
        };

        return Ok(ApiResponse<UserDto>.SuccessResponse(userDto, "User updated successfully"));
    }

    /// <summary>
    /// Delete user (Admin only)
    /// </summary>
    [HttpDelete("{id}")]
    [Authorize(Roles = "Admin")]
    [ProducesResponseType(typeof(ApiResponse<bool>), StatusCodes.Status200OK)]
    public async Task<IActionResult> DeleteUser(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound(ApiResponse<bool>.ErrorResponse("User not found"));
        }

        var result = await _userManager.DeleteAsync(user);
        if (!result.Succeeded)
        {
            return BadRequest(ApiResponse<bool>.ErrorResponse("Delete failed"));
        }

        return Ok(ApiResponse<bool>.SuccessResponse(true, "User deleted successfully"));
    }

    /// <summary>
    /// Activate user
    /// </summary>
    [HttpPatch("{id}/activate")]
    [Authorize(Roles = "Admin")]
    [ProducesResponseType(typeof(ApiResponse<bool>), StatusCodes.Status200OK)]
    public async Task<IActionResult> ActivateUser(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound(ApiResponse<bool>.ErrorResponse("User not found"));
        }

        user.IsActive = true;
        user.ModifiedAt = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        return Ok(ApiResponse<bool>.SuccessResponse(true, "User activated successfully"));
    }

    /// <summary>
    /// Deactivate user
    /// </summary>
    [HttpPatch("{id}/deactivate")]
    [Authorize(Roles = "Admin")]
    [ProducesResponseType(typeof(ApiResponse<bool>), StatusCodes.Status200OK)]
    public async Task<IActionResult> DeactivateUser(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound(ApiResponse<bool>.ErrorResponse("User not found"));
        }

        user.IsActive = false;
        user.ModifiedAt = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        // Revoke all active sessions
        await _unitOfWork.UserSessions.RevokeAllUserSessionsAsync(id);
        await _unitOfWork.RefreshTokens.RevokeAllUserTokensAsync(id);
        await _unitOfWork.SaveChangesAsync();

        return Ok(ApiResponse<bool>.SuccessResponse(true, "User deactivated successfully"));
    }

    /// <summary>
    /// Get user roles
    /// </summary>
    [HttpGet("{id}/roles")]
    [Authorize(Roles = "Admin")]
    [ProducesResponseType(typeof(ApiResponse<List<string>>), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetUserRoles(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound(ApiResponse<List<string>>.ErrorResponse("User not found"));
        }

        var roles = await _userManager.GetRolesAsync(user);
        return Ok(ApiResponse<List<string>>.SuccessResponse(roles.ToList()));
    }

    /// <summary>
    /// Assign role to user
    /// </summary>
    [HttpPost("{id}/roles")]
    [Authorize(Roles = "Admin")]
    [ProducesResponseType(typeof(ApiResponse<bool>), StatusCodes.Status200OK)]
    public async Task<IActionResult> AssignRole(string id, [FromBody] string roleName)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound(ApiResponse<bool>.ErrorResponse("User not found"));
        }

        var result = await _userManager.AddToRoleAsync(user, roleName);
        if (!result.Succeeded)
        {
            return BadRequest(ApiResponse<bool>.ErrorResponse("Failed to assign role"));
        }

        return Ok(ApiResponse<bool>.SuccessResponse(true, "Role assigned successfully"));
    }

    /// <summary>
    /// Remove role from user
    /// </summary>
    [HttpDelete("{id}/roles/{roleName}")]
    [Authorize(Roles = "Admin")]
    [ProducesResponseType(typeof(ApiResponse<bool>), StatusCodes.Status200OK)]
    public async Task<IActionResult> RemoveRole(string id, string roleName)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound(ApiResponse<bool>.ErrorResponse("User not found"));
        }

        var result = await _userManager.RemoveFromRoleAsync(user, roleName);
        if (!result.Succeeded)
        {
            return BadRequest(ApiResponse<bool>.ErrorResponse("Failed to remove role"));
        }

        return Ok(ApiResponse<bool>.SuccessResponse(true, "Role removed successfully"));
    }
}
