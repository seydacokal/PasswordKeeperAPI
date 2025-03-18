using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using PasswordKeeperAPI.Models;
using PasswordKeeperAPI.DTOs; // Login ve Register DTO'ları
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace PasswordKeeperAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager; // ROL YÖNETİCİSİ EKLENDİ
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IConfiguration _configuration;

        public AuthController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, SignInManager<ApplicationUser> signInManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager; // ROL YÖNETİCİSİ EKLENDİ
            _signInManager = signInManager;
            _configuration = configuration;
        }

        // Register
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
        {
            if (registerDto.Password != registerDto.ConfirmPassword)
            {
                return BadRequest(new { Message = "Passwords do not match" });
            }

            var user = new ApplicationUser
            {
                UserName = registerDto.Username,
                Email = registerDto.Email,
                FullName = registerDto.FullName
            };

            var result = await _userManager.CreateAsync(user, registerDto.Password);

            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            // Kullanıcı rolü belirleme (admin veya user)
            string role = string.IsNullOrEmpty(registerDto.Role) ? "User" : registerDto.Role;

            // **admin** rolü yalnızca senin onayından sonra atanacak
            if (role == "Admin")
            {
                // Admin rolü seçen kullanıcıya sadece User rolü atanacak
                await _userManager.AddToRoleAsync(user, "User");

                // Admin onayı verilene kadar sadece User olarak kalacak
                return BadRequest(new { Message = "Admin role assignment is restricted to admin approval. You are registered as User." });
            }

            // **user** rolü için veritabanında rolün var mı kontrol et
            if (!await _roleManager.RoleExistsAsync(role))
            {
                return BadRequest(new { Message = "Invalid role selected" });
            }

            // Kullanıcıya rol ata (user rolü)
            await _userManager.AddToRoleAsync(user, role);

            return Ok(new { Message = "User registered successfully!" });
        }

        // Login
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
        {
            var user = await _userManager.FindByNameAsync(loginDto.Username);
            if (user != null && await _userManager.CheckPasswordAsync(user, loginDto.Password))
            {
                var token = await GenerateJwtToken(user);
                return Ok(new { Token = token });
            }
            return Unauthorized(new { Message = "Invalid username or password" });
        }

        // JWT Token oluşturma
        private async Task<string> GenerateJwtToken(ApplicationUser user)
        {
            var userRoles = await _userManager.GetRolesAsync(user);

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
            };

            // Kullanıcının rollerini token'a ekleyelim
            claims.AddRange(userRoles.Select(role => new Claim(ClaimTypes.Role, role)));
                
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:Issuer"],
                audience: _configuration["JWT:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(Convert.ToDouble(_configuration["JWT:ExpiresInMinutes"])),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        // Admin onayı ile kullanıcıya Admin rolü atama
        [HttpPost("approve-admin/{userId}")]
        public async Task<IActionResult> ApproveAdminRole(string userId)
        {
            // Admin kullanıcısı olduğumuzu kontrol et
            var currentUser = await _userManager.GetUserAsync(User);
            var currentRoles = await _userManager.GetRolesAsync(currentUser);

            if (!currentRoles.Contains("Admin"))
            {
                return Unauthorized(new { Message = "You do not have permission to approve admin role." });
            }

            // Onay verilecek kullanıcıyı bul
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound(new { Message = "User not found" });
            }

            // Kullanıcının zaten Admin rolü olup olmadığını kontrol et
            if (await _userManager.IsInRoleAsync(user, "Admin"))
            {
                return BadRequest(new { Message = "User is already an Admin" });
            }

            // Kullanıcıya Admin rolü ata
            var result = await _userManager.AddToRoleAsync(user, "Admin");

            if (!result.Succeeded)
            {
                return BadRequest(new { Message = "Failed to assign Admin role" });
            }

            return Ok(new { Message = "User successfully approved as Admin" });
        }
    }
}






