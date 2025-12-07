using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using UserManagement.Domain.Entities;

namespace UserManagement.Infrastructure.Data.Configurations;

public class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    public void Configure(EntityTypeBuilder<RefreshToken> builder)
    {
        builder.HasKey(t => t.Id);

        builder.Property(t => t.UserId)
            .IsRequired()
            .HasMaxLength(450);

        builder.Property(t => t.Token)
            .IsRequired()
            .HasMaxLength(500);

        builder.Property(t => t.JwtId)
            .IsRequired()
            .HasMaxLength(500);

        builder.Property(t => t.IpAddress)
            .HasMaxLength(45);

        builder.Property(t => t.UserAgent)
            .HasMaxLength(500);

        builder.Property(t => t.DeviceInfo)
            .HasMaxLength(500);

        builder.HasOne(t => t.User)
            .WithMany(u => u.RefreshTokens)
            .HasForeignKey(t => t.UserId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasIndex(t => t.Token)
            .IsUnique();

        builder.HasIndex(t => t.UserId);
        builder.HasIndex(t => t.ExpiresAt);
        builder.HasIndex(t => new { t.IsRevoked, t.IsUsed });
    }
}
