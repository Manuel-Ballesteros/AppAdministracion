using System.ComponentModel.DataAnnotations;

namespace WebApplication1.Areas.Identity.Models;
public class ForgotPasswordViewModel
{
    [Required(ErrorMessage = "El {0} es obligatorio")]
    [StringLength(50, ErrorMessage = "La {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 10)]
    [EmailAddress(ErrorMessage = "El {0} no es válido")]
    [DataType(DataType.EmailAddress)]
    [Display(Name = "Correo electrónico")]
    public string? Email { get; set; }
}

