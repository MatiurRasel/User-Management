namespace UserManagement.Domain.Entities;

public class UserProfile
{
    public int Id { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string? Address { get; set; }
    public string? City { get; set; }
    public string? State { get; set; }
    public string? Country { get; set; }
    public string? PostalCode { get; set; }
    public string? Bio { get; set; }
    public string? Website { get; set; }
    public string? LinkedInProfile { get; set; }
    public string? GitHubProfile { get; set; }
    public DateTime? LastProfileUpdate { get; set; }

    public virtual ApplicationUser User { get; set; } = null!;
}