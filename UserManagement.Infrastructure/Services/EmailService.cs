using Microsoft.Extensions.Configuration;
using System.Net.Mail;
using System.Net;
using UserManagement.Domain.Interfaces.Services;

namespace UserManagement.Infrastructure.Services;

public class EmailService : IEmailService
{
    private readonly IConfiguration _configuration;
    private readonly string _smtpServer;
    private readonly int _smtpPort;
    private readonly string _senderEmail;
    private readonly string _senderName;
    private readonly string _username;
    private readonly string _password;

    public EmailService(IConfiguration configuration)
    {
        _configuration = configuration;
        var emailSettings = configuration.GetSection("EmailSettings");
        _smtpServer = emailSettings["SmtpServer"] ?? "smtp.gmail.com";
        _smtpPort = int.Parse(emailSettings["SmtpPort"] ?? "587");
        _senderEmail = emailSettings["SenderEmail"] ?? "noreply@usermanagement.com";
        _senderName = emailSettings["SenderName"] ?? "User Management System";
        _username = emailSettings["Username"] ?? "";
        _password = emailSettings["Password"] ?? "";
    }

    public async Task SendEmailVerificationAsync(string email, string token, string userName)
    {
        var subject = "Verify Your Email Address";
        var body = $@"
            <h2>Hello {userName},</h2>
            <p>Thank you for registering! Please verify your email address by clicking the link below:</p>
            <p><a href='https://yourdomain.com/confirm-email?token={token}&email={email}'>Verify Email</a></p>
            <p>If you didn't register for this account, please ignore this email.</p>
            <br/>
            <p>Best regards,<br/>User Management Team</p>
        ";

        await SendEmailAsync(email, subject, body);
    }

    public async Task SendPasswordResetEmailAsync(string email, string token, string userName)
    {
        var subject = "Reset Your Password";
        var body = $@"
            <h2>Hello {userName},</h2>
            <p>You requested to reset your password. Click the link below to reset it:</p>
            <p><a href='https://yourdomain.com/reset-password?token={token}&email={email}'>Reset Password</a></p>
            <p>This link will expire in 24 hours.</p>
            <p>If you didn't request this, please ignore this email.</p>
            <br/>
            <p>Best regards,<br/>User Management Team</p>
        ";

        await SendEmailAsync(email, subject, body);
    }

    public async Task SendTwoFactorCodeAsync(string email, string code, string userName)
    {
        var subject = "Your Two-Factor Authentication Code";
        var body = $@"
            <h2>Hello {userName},</h2>
            <p>Your two-factor authentication code is: <strong>{code}</strong></p>
            <p>This code will expire in 5 minutes.</p>
            <p>If you didn't request this, please contact support immediately.</p>
            <br/>
            <p>Best regards,<br/>User Management Team</p>
        ";

        await SendEmailAsync(email, subject, body);
    }

    public async Task SendWelcomeEmailAsync(string email, string userName)
    {
        var subject = "Welcome to User Management System!";
        var body = $@"
            <h2>Welcome {userName}!</h2>
            <p>Your email has been verified successfully. You can now enjoy all features of our platform.</p>
            <p>If you have any questions, feel free to contact our support team.</p>
            <br/>
            <p>Best regards,<br/>User Management Team</p>
        ";

        await SendEmailAsync(email, subject, body);
    }

    public async Task SendPasswordChangedNotificationAsync(string email, string userName)
    {
        var subject = "Password Changed Successfully";
        var body = $@"
            <h2>Hello {userName},</h2>
            <p>Your password has been changed successfully.</p>
            <p>If you didn't make this change, please contact support immediately.</p>
            <br/>
            <p>Best regards,<br/>User Management Team</p>
        ";

        await SendEmailAsync(email, subject, body);
    }

    public async Task SendAccountLockedNotificationAsync(string email, string userName)
    {
        var subject = "Account Locked - Security Alert";
        var body = $@"
            <h2>Hello {userName},</h2>
            <p>Your account has been locked due to multiple failed login attempts.</p>
            <p>Your account will be automatically unlocked after 30 minutes, or you can reset your password to unlock it immediately.</p>
            <p>If you didn't attempt to log in, please contact support immediately.</p>
            <br/>
            <p>Best regards,<br/>User Management Team</p>
        ";

        await SendEmailAsync(email, subject, body);
    }

    private async Task SendEmailAsync(string toEmail, string subject, string body)
    {
        try
        {
            using var smtpClient = new SmtpClient(_smtpServer, _smtpPort)
            {
                Credentials = new NetworkCredential(_username, _password),
                EnableSsl = true
            };

            var mailMessage = new MailMessage
            {
                From = new MailAddress(_senderEmail, _senderName),
                Subject = subject,
                Body = body,
                IsBodyHtml = true
            };

            mailMessage.To.Add(toEmail);

            await smtpClient.SendMailAsync(mailMessage);
        }
        catch (Exception ex)
        {
            // Log the error (implement proper logging)
            Console.WriteLine($"Email sending failed: {ex.Message}");
            // In production, use proper logging framework like Serilog
        }
    }
}
