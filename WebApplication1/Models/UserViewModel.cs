using System.ComponentModel.DataAnnotations;

namespace WebApplication1.Models;
public class UserViewModel
{
    public string? Id { get; set; }

    [Required(ErrorMessage = "El {0} es obligatorio")]
    [StringLength(50, ErrorMessage = "El {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 3)]
    [RegularExpression(@"^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ\s]+$", ErrorMessage = "{0} solo puede contener letras.")]
    [DataType(DataType.Text)]
    [Display(Name = "Nombre")]
    public string? Name { get; set; }

    [Required(ErrorMessage = "El {0} es obligatorio")]
    [StringLength(50, ErrorMessage = "El {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 3)]
    [RegularExpression(@"^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ\s]+$", ErrorMessage = "{0} solo puede contener letras.")]
    [DataType(DataType.Text)]
    [Display(Name = "Apellido")]
    public string? LastName { get; set; }


    [StringLength(50, ErrorMessage = "La {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 10)]
    [EmailAddress(ErrorMessage = "El {0} no es válido")]
    [DataType(DataType.EmailAddress)]
    [Display(Name = "Correo electrónico")]
    public string? Email { get; set; }

    [StringLength(20, ErrorMessage = "El {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 7)]
    [RegularExpression(@"^[0-9\s+()]+$", ErrorMessage = "El {0} solo puede contener caracteres válidos.")]
    [DataType(DataType.PhoneNumber)]
    [Display(Name = "Teléfono")]
    public string? PhoneNumber { get; set; }

    [Display(Name = "Activo")]
    public bool IsActive { get; set; } = true;

    [Display(Name = "Roles del usuario")]
    public IEnumerable<string> Roles { get; set; } = [];    

    public DateTimeOffset? LockoutEnd { get; set; }
}

