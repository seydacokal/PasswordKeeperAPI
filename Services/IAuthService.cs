using PasswordKeeperAPI.DTOs;
using PasswordKeeperAPI.Models;

namespace PasswordKeeperAPI.Services
{
    public interface IAuthService
    {
        Task<string> LoginAsync(LoginModel model);
        Task<string> RegisterAsync(RegisterDto model); // RegisterAsync metodunu ekledik
    }
}
