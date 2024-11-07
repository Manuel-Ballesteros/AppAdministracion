using System.ComponentModel.DataAnnotations;

namespace WebApplication1.Areas.Identity.Models;
public class ChangePasswordViewModel
{
    [Required(ErrorMessage = "La {0} es obligatoria")]
    [StringLength(30, ErrorMessage = "La {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 8)]
    [DataType(DataType.Password)]
    [Display(Name = "Contraseña actual")]
    public string? OldPassword { get; set; }

    [Required(ErrorMessage = "La {0} es obligatoria")]
    [StringLength(30, ErrorMessage = "La {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 8)]
    [DataType(DataType.Password)]
    [Display(Name = "Nueva Contraseña")]
    public string? NewPassword { get; set; }

    [Compare(nameof(NewPassword), ErrorMessage = "Las contraseñas no coinciden")]
    [DataType(DataType.Password)]
    [Display(Name = "Confirmar Nueva Contraseña")]
    public string? ConfirmNewPassword { get; set; }
}

