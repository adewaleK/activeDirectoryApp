using ActiveDirectoryDemoAPI.Enums;
using Microsoft.AspNetCore.Identity;

namespace ActiveDirectoryDemoAPI.Entities
{
    public class User : IdentityUser<Guid>, IAuditableEntity
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Password { get; set; }
        public string Status { get; set; } = EUserStatus.Active.ToString();
        public bool Verified { get; set; } = false;
        public bool IsActive { get; set; } = false;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
        public DateTimeOffset LastLogin { get; set; }
        public string? RefreshToken { get; set; }
        public DateTime RefreshTokenExpiryTime { get; set; }
    }
}
