namespace UserManagement.Application.DTOs.Session;

public class UserSessionDto
{
    public int Id { get; set; }
    public string SessionId { get; set; } = string.Empty;
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public DateTime LoginTime { get; set; }
    public DateTime LastActivity { get; set; }
    public bool IsActive { get; set; }
    public string DeviceInfo { get; set; } = string.Empty;
}