using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore;
using UserManagement.Domain.Entities;

namespace UserManagement.Infrastructure.Data.Configurations;

public class LoginAttemptConfiguration : IEntityTypeConfiguration<LoginAttempt>
{
    public void Configure(EntityTypeBuilder<LoginAttempt> builder)
    {
        builder.HasKey(l => l.Id);

        builder.Property(l => l.Email)
            .IsRequired()
            .HasMaxLength(256);

        builder.Property(l => l.IpAddress)
            .HasMaxLength(45);

        builder.Property(l => l.UserAgent)
            .HasMaxLength(500);

        builder.Property(l => l.FailureReason)
            .HasMaxLength(500);

        builder.HasIndex(l => l.Email);
        builder.HasIndex(l => l.AttemptTime);
        builder.HasIndex(l => new { l.Email, l.IsSuccessful });
    }
}