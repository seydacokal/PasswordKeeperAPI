using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PasswordKeeperAPI.Data;
using PasswordKeeperAPI.Models;
using PasswordKeeperAPI.Services;
using SeydaSecurity;
using Microsoft.AspNetCore.Authorization;
using System.Linq;

namespace PasswordKeeperAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class PasswordController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly IPasswordService _passwordService;

        public PasswordController(AppDbContext context, IPasswordService passwordService)
        {
            _context = context;
            _passwordService = passwordService;
        }

        // GET: api/passwords
        [HttpGet("all")]
        public async Task<ActionResult<IEnumerable<Password>>> GetPasswords()
        {
            var passwords = await _context.Passwords.ToListAsync();
            return Ok(passwords);
        }

        // GET: api/passwords/{id}
        [HttpGet("{id}")]
        public async Task<ActionResult<Password>> GetPassword(int id)
        {
            var password = await _context.Passwords.FindAsync(id);

            if (password == null)
            {
                return NotFound();
            }

            return Ok(password);
        }

        // GET: api/passwords/get-passwords/{username}
        [HttpGet("get-passwords/{username}")]
        public ActionResult<List<Password>> GetUserPasswords(string username)
        {
            List<Password> password = _context.Passwords.Where(item => item.Username == username).ToList();

            if (password == null || password.Count == 0)
            {
                return NotFound();
            }

            return Ok(password);
        }

        // POST: api/passwords
        [HttpPost]
        [Authorize(Roles = "Admin, User")]  // Şifreyi sadece admin ya da kullanıcı oluşturabilir
        public async Task<ActionResult<Password>> PostPassword(Password password)
        {
            string salt = SaltHelper.GetSalt(); // Örnek: SaltHelper'dan alınan salt

            if (string.IsNullOrEmpty(salt))
            {
                return BadRequest("Geçersiz salt.");
            }

            var encryptionService = new EncryptionService(salt);
            string encryptedPassword = encryptionService.Encrypt(password.HashedPassword);

            password.HashedPassword = encryptedPassword;

            _context.Passwords.Add(password);
            await _context.SaveChangesAsync();

            return CreatedAtAction(nameof(GetPassword), new { id = password.Id }, password);
        }

        // PUT: api/passwords/{id}
        [HttpPut("{id}")]
        [Authorize(Roles = "Admin, User")] // Yalnızca şifreyi oluşturan kişi ya da admin güncelleyebilir
        public async Task<IActionResult> PutPassword(int id, [FromBody] Password password)
        {
            if (id != password.Id)
            {
                return BadRequest("ID uyumsuzluğu.");
            }

            var dbPassword = await _context.Passwords.FindAsync(password.Id);
            if (dbPassword == null) return NotFound("Password not found.");

            var currentUser = User.Identity.Name;
            if (dbPassword.Username != currentUser && !User.IsInRole("Admin"))
            {
                return Unauthorized("Bu şifreyi güncelleyemezsiniz.");
            }

            string salt = SaltHelper.GetSalt();

            if (string.IsNullOrEmpty(salt))
            {
                return BadRequest("Geçersiz salt.");
            }

            var encryptionService = new EncryptionService(salt);
            string encryptedPassword = encryptionService.Encrypt(password.HashedPassword);

            dbPassword.HashedPassword = encryptedPassword;

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!PasswordExists(id))
                {
                    return NotFound("Password not found.");
                }
                else
                {
                    throw;
                }
            }

            return Ok();
        }

        // DELETE: api/passwords/{id}
        [HttpDelete("{id}")]
        [Authorize(Roles = "Admin, User")] // Yalnızca şifreyi oluşturan kişi ya da admin silebilir
        public async Task<IActionResult> DeletePassword(int id)
        {
            var password = await _context.Passwords.FindAsync(id);
            if (password == null)
            {
                return NotFound("Password not found.");
            }

            var currentUser = User.Identity.Name;
            if (password.Username != currentUser && !User.IsInRole("Admin"))
            {
                return Unauthorized("Bu şifreyi silemezsiniz.");
            }

            _context.Passwords.Remove(password);
            await _context.SaveChangesAsync();

            return NoContent();
        }

        private bool PasswordExists(int id)
        {
            return _context.Passwords.Any(e => e.Id == id);
        }

        // PATCH: api/passwords/update-username/{id}
        [HttpPatch("update-username/{id}")]
        [Authorize(Roles = "Admin, User")]  // Yalnızca şifreyi oluşturan kişi ya da admin güncelleyebilir
        public async Task<IActionResult> UpdateUsername(int id, [FromBody] string newUsername)
        {
            var password = await _context.Passwords.FindAsync(id);
            if (password == null) return NotFound("Password not found.");

            var currentUser = User.Identity.Name;
            if (password.Username != currentUser && !User.IsInRole("Admin"))
            {
                return Unauthorized("Bu şifreyi güncelleyemezsiniz.");
            }

            password.Username = newUsername;
            await _context.SaveChangesAsync();

            return NoContent();
        }

        // PATCH: api/passwords/update-title/{id}
        [HttpPatch("update-title/{id}")]
        //[Authorize] // Yalnızca şifreyi oluşturan kişi ya da admin güncelleyebilir
        public async Task<IActionResult> UpdateTitle(int id, [FromBody] string newTitle)
        {
            var password = await _context.Passwords.FindAsync(id);
            if (password == null) return NotFound("Password not found.");

            var currentUser = User.Identity.Name;
            if (password.Username != currentUser && !User.IsInRole("Admin"))
            {
                return Unauthorized("Bu şifreyi güncelleyemezsiniz.");
            }

            password.Title = newTitle;
            await _context.SaveChangesAsync();

            return NoContent();
        }

        // PUT: api/passwords/update-all
        [HttpPut("update-all")]
        [Authorize(Roles = "Admin")] // Admin sadece tüm şifreleri güncelleyebilir
        public async Task<IActionResult> UpdateAll([FromBody] List<Password> updatedPasswords)
        {
            foreach (var updatedPassword in updatedPasswords)
            {
                var password = await _context.Passwords.FindAsync(updatedPassword.Id);
                if (password == null) continue;

                password.Title = updatedPassword.Title;
                password.Username = updatedPassword.Username;

                string salt = SaltHelper.GetSalt();

                if (string.IsNullOrEmpty(salt))
                {
                    return BadRequest("Geçersiz salt.");
                }

                var encryptionService = new EncryptionService(salt);
                string encryptedPassword = encryptionService.Encrypt(updatedPassword.HashedPassword);

                password.HashedPassword = encryptedPassword;
            }
            await _context.SaveChangesAsync();

            return NoContent();
        }

        // DELETE: api/passwords/delete-all
        [HttpDelete("delete-all")]
        [Authorize(Roles = "Admin")]  // Admin sadece tüm şifreleri silebilir
        public async Task<IActionResult> DeleteAll()
        {
            _context.Passwords.RemoveRange(_context.Passwords);
            await _context.SaveChangesAsync();

            return NoContent();
        }
    }
}

