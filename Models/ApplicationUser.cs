using Microsoft.AspNetCore.Identity;

namespace PasswordKeeperAPI.Models
{
    // IdentityUser sınıfından türeyen ApplicationUser sınıfı
    public class ApplicationUser : IdentityUser
    {
        // Buraya eklemek istediğiniz özel kullanıcı bilgilerini ekleyebilirsiniz
        public string FullName { get; set; }  // Kullanıcı adı, soyadı gibi
    }

}

