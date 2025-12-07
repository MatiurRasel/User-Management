using Microsoft.EntityFrameworkCore.Storage;
using UserManagement.Domain.Interfaces;
using UserManagement.Infrastructure.Data;

namespace UserManagement.Infrastructure.Repositories;

public class UnitOfWork : IUnitOfWork
{
    private readonly ApplicationDbContext _context;
    private IDbContextTransaction? _transaction;

    public UnitOfWork(
        ApplicationDbContext context,
        IUserRepository users,
        IRefreshTokenRepository refreshTokens,
        IAuditLogRepository auditLogs,
        IPasswordHistoryRepository passwordHistories,
        IUserSessionRepository userSessions,
        ILoginAttemptRepository loginAttempts)
    {
        _context = context;
        Users = users;
        RefreshTokens = refreshTokens;
        AuditLogs = auditLogs;
        PasswordHistories = passwordHistories;
        UserSessions = userSessions;
        LoginAttempts = loginAttempts;
    }

    public IUserRepository Users { get; }
    public IRefreshTokenRepository RefreshTokens { get; }
    public IAuditLogRepository AuditLogs { get; }
    public IPasswordHistoryRepository PasswordHistories { get; }
    public IUserSessionRepository UserSessions { get; }
    public ILoginAttemptRepository LoginAttempts { get; }

    public async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        return await _context.SaveChangesAsync(cancellationToken);
    }

    public async Task BeginTransactionAsync()
    {
        _transaction = await _context.Database.BeginTransactionAsync();
    }

    public async Task CommitTransactionAsync()
    {
        try
        {
            await SaveChangesAsync();
            if (_transaction != null)
            {
                await _transaction.CommitAsync();
            }
        }
        catch
        {
            await RollbackTransactionAsync();
            throw;
        }
        finally
        {
            if (_transaction != null)
            {
                await _transaction.DisposeAsync();
                _transaction = null;
            }
        }
    }

    public async Task RollbackTransactionAsync()
    {
        if (_transaction != null)
        {
            await _transaction.RollbackAsync();
            await _transaction.DisposeAsync();
            _transaction = null;
        }
    }

    public void Dispose()
    {
        _transaction?.Dispose();
        _context.Dispose();
    }
}
