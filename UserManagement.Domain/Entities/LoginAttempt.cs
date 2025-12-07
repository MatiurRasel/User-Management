namespace UserManagement.Domain.Entities;

public class LoginAttempt
{
    public long Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public bool IsSuccessful { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public string? FailureReason { get; set; }
    public DateTime AttemptTime { get; set; } = DateTime.UtcNow;
}