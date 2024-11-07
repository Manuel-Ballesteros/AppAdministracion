namespace WebApplication1.Areas.Identity.Models;
public class AssignRolesViewModel
{
    public string? Id { get; set; }
    public string? FullName { get; set; }
    public IList<string> UserRoles { get; set; } = []; // Roles que el usuario ya tiene asignados
    public IList<string?>? AllRoles { get; set; } = []; // Todos los roles disponibles
    public IList<string> SelectedRoles { get; set; } = [];  // Roles seleccionados en el formulario
}

