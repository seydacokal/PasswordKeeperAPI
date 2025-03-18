namespace PasswordKeeperAPI.Services
{
    public interface IPasswordService
    {
        string EncryptPassword(string password);
        bool VerifyPassword(string password, string encryptedPassword);
        //dynamic GetPasswords();
    }
}

