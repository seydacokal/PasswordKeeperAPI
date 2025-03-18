using System.ComponentModel.DataAnnotations;

namespace PasswordKeeperAPI.Models
{
    public class Password
    {
        public int Id { get; set; }  // Primary Key, otomatik artan

        [Required]
        [StringLength(100)]  // Başlık için bir uzunluk sınırı ekleyelim (isteğe bağlı)
        public string Title { get; set; } // Password Name

        [Required]
        [StringLength(100)]  // Kullanıcı adı için uzunluk sınırı
        public string Username { get; set; } // Username

        public int? UserId { get; set; } 

        [Required]
        public string HashedPassword { get; set; }  // Şifre, hashlenmiş şekilde saklanacak
    }
}

