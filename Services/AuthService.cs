using PasswordKeeperAPI.Models;
using PasswordKeeperAPI.DTOs;
using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;

namespace PasswordKeeperAPI.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;

        public AuthService(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        // RegisterAsync metodunu ekliyoruz
        public async Task<string> RegisterAsync(RegisterDto model)
        {
            var user = new ApplicationUser
            {
                UserName = model.Username,
                Email = model.Email
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                // Kullanıcıyı "User" rolüne atıyoruz
                await _userManager.AddToRoleAsync(user, "User");
                await _signInManager.SignInAsync(user, isPersistent: false);
                return "Kayıt başarılı";
            }

            return "Kayıt başarısız";
        }

        // LoginAsync metodu
        public async Task<string> LoginAsync(LoginModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email); // Email'i burada kullanıyoruz
            if (user != null)
            {
                var result = await _signInManager.PasswordSignInAsync(user, model.Password, false, false);

                if (result.Succeeded)
                {
                    return "Giriş başarılı";
                }
            }

            return "Giriş başarısız";
        }
    }
}


