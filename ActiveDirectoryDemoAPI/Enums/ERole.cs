using System.ComponentModel;

namespace ActiveDirectoryDemoAPI.Enums
{
    public enum ERole
    {
        [Description("Admin")]
        Admin = 1,
        [Description("User")]
        User = 2,
    }
        
}
