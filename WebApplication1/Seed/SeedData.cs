using Microsoft.AspNetCore.Identity;
using WebApplication1.Constants;
using WebApplication1.Data.Entities;

namespace WebApplication1.Seed;
public class SeedData
{
    public static async Task SeedAsync(UserManager<User> userManager, RoleManager<IdentityRole> roleManager, ILoggerFactory loggerFactory)
    {
        try
        {
            if (!roleManager.Roles.Any())
            {
                await roleManager.CreateAsync(new IdentityRole(Roles.ADMIN));
                await roleManager.CreateAsync(new IdentityRole(Roles.USER));
            }

            if (!userManager.Users.Any())
            {
                var userAdmin = new User
                {
                    Name = "Alexander",
                    LastName = "Ardila",
                    IsActive = true,
                    UserName = "jorge.ardila1641@correo.policia.gov.co",
                    Email = "jorge.ardila1641@correo.policia.gov.co",
                    PhoneNumber = "3103897228"                    
                };
                await userManager.CreateAsync(userAdmin, "PasswordAlexander123*");
                await userManager.AddToRoleAsync(userAdmin, Roles.ADMIN);

                var user1 = new User
                {
                    Name = "Manuel",
                    LastName = "Ballesteros",
                    IsActive = true,
                    UserName = "mferballesteros27@gmail.com",
                    Email = "mferballesteros27@gmail.com",
                    PhoneNumber = "3225999210"                    
                };
                await userManager.CreateAsync(user1, "PasswordNaty123*");
                await userManager.AddToRoleAsync(user1, Roles.ADMIN);
            }
            
        }
        catch (Exception ex)
        {
            var logger = loggerFactory.CreateLogger<SeedData>();
            logger.LogError($"An error occurred seeding the DB. Error: {ex.Message}, inner exception: {ex.InnerException}");
        }
    }
}

