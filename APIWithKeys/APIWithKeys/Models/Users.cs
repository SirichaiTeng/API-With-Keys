namespace APIWithKeys.Models
{
    public class Users
    {
        public string username { get; set; } = string.Empty;
        public byte[] userpasswordHash { get; set; }
        public byte[] userpasswordSalt { get; set; }
    }
}
