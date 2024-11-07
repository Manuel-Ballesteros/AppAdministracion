using Microsoft.AspNetCore.Identity;

namespace WebApplication1.Data.Entities;
public class User : IdentityUser
{
    public string Name { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public bool IsActive { get; set; }
}

