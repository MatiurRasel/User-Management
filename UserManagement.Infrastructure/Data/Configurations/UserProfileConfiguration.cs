using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using UserManagement.Domain.Entities;

namespace UserManagement.Infrastructure.Data.Configurations;

public class UserProfileConfiguration : IEntityTypeConfiguration<UserProfile>
{
    public void Configure(EntityTypeBuilder<UserProfile> builder)
    {
        builder.HasKey(p => p.Id);

        builder.Property(p => p.UserId)
            .IsRequired()
            .HasMaxLength(450);

        builder.Property(p => p.Address)
            .HasMaxLength(500);

        builder.Property(p => p.City)
            .HasMaxLength(100);

        builder.Property(p => p.State)
            .HasMaxLength(100);

        builder.Property(p => p.Country)
            .HasMaxLength(100);

        builder.Property(p => p.PostalCode)
            .HasMaxLength(20);

        builder.Property(p => p.Bio)
            .HasMaxLength(2000);

        builder.Property(p => p.Website)
            .HasMaxLength(500);

        builder.Property(p => p.LinkedInProfile)
            .HasMaxLength(500);

        builder.Property(p => p.GitHubProfile)
            .HasMaxLength(500);

        builder.HasOne(p => p.User)
            .WithOne(u => u.UserProfile)
            .HasForeignKey<UserProfile>(p => p.UserId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasIndex(p => p.UserId)
            .IsUnique();
    }
}
