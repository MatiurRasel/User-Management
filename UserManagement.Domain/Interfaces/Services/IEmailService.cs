namespace UserManagement.Domain.Interfaces.Services;

public interface IEmailService
{
    Task SendEmailVerificationAsync(string email, string token, string userName);
    Task SendPasswordResetEmailAsync(string email, string token, string userName);
    Task SendTwoFactorCodeAsync(string email, string code, string userName);
    Task SendWelcomeEmailAsync(string email, string userName);
    Task SendPasswordChangedNotificationAsync(string email, string userName);
    Task SendAccountLockedNotificationAsync(string email, string userName);
}