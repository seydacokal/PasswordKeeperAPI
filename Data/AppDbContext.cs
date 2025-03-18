using Microsoft.AspNetCore.Identity.EntityFrameworkCore; // Identity için gerekli namespace
using Microsoft.EntityFrameworkCore;
using PasswordKeeperAPI.Models;

namespace PasswordKeeperAPI.Data
{
    public class AppDbContext : IdentityDbContext<ApplicationUser> // IdentityDbContext ile ApplicationUser kullanıyoruz
    {
        // DbContext'e bağlantı seçeneklerini geçiren yapılandırıcı
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }

        // Password modeline karşılık gelen DbSet
        public DbSet<Password> Passwords { get; set; }
    }
}



