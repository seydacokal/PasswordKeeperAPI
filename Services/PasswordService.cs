using Microsoft.EntityFrameworkCore;
using PasswordKeeperAPI.Data;
using System.Security.Cryptography;
using System.Text;

namespace PasswordKeeperAPI.Services
{
    public class PasswordService : IPasswordService
    {

        //private readonly IDbContextFactory<AppDbContext> _contextFactory;

        //// Injecting the DbContextFactory
        //public PasswordService(IDbContextFactory<AppDbContext> contextFactory)
        //{
        //    _contextFactory = contextFactory;
        //}

        //public dynamic GetPasswords()
        //{
        //    try
        //    {
        //        using (var context = _contextFactory.CreateDbContext())
        //        {
        //            return context.Passwords.ToList();
        //        }

        //    }
        //    catch (Exception)
        //    {
        //        return null;
        //        throw;
        //    }
        //}

        public string EncryptPassword(string password)
        {
            using (var sha256 = SHA256.Create())
            {
                var bytes = Encoding.UTF8.GetBytes(password);
                var hashBytes = sha256.ComputeHash(bytes);
                return Convert.ToBase64String(hashBytes);
            }
        }

        public bool VerifyPassword(string password, string encryptedPassword)
        {
            var hashedPassword = EncryptPassword(password);
            return hashedPassword == encryptedPassword;
        }
    }
}

