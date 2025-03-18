namespace PasswordKeeperAPI.DTOs
{

    public class RegisterDto
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string ConfirmPassword { get; set; }
        public string FullName { get; set; }  // FullName alanını ekledik
        public string Role { get; set; } //rol eklendi
    }
}