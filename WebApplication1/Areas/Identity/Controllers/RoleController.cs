using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using WebApplication1.Areas.Identity.Models;
using WebApplication1.Constants;
using WebApplication1.Controllers;
using WebApplication1.Data.Entities;
using WebApplication1.Mappings;

namespace WebApplication1.Areas.Identity.Controllers;
[Authorize(Roles = Roles.ADMIN)]
[Area("Identity")]
public class RoleController(RoleManager<IdentityRole> roleManager, UserManager<User> userManager) : Controller
{
    private readonly RoleManager<IdentityRole> _roleManager = roleManager;
    private readonly UserManager<User> _userManager = userManager;

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        try
        {
            var roleViewModels = await _roleManager.Roles
                .Select(r => new RoleViewModel { Id = r.Id, Name = r.Name })
                .ToListAsync() ?? [];

            return View(roleViewModels);
        }
        catch (Exception)
        {
            return RedirectToAction(nameof(HomeController.Error), "Home", new { message = "Ocurrió un error inesperado. Por favor, inténtalo de nuevo más tarde." });
        }
    }

    [HttpGet]
    public IActionResult Create() => View();

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(RoleViewModel viewModel)
    {
        if (!ModelState.IsValid) return View(viewModel);
        try
        {
            if (await _roleManager.RoleExistsAsync(viewModel.Name!))
            {
                ModelState.AddModelError(nameof(RoleViewModel.Name), "El rol ya existe.");
                return View(viewModel);
            }

            var result = await _roleManager.CreateAsync(new IdentityRole(viewModel.Name!));
            if (result.Succeeded)
            {
                TempData["StatusMessage"] = "Rol creado exitosamente.";
                return RedirectToAction(nameof(Index));
            }
            foreach (var error in result.Errors) ModelState.AddModelError(string.Empty, error.Description);
        }
        catch (Exception)
        {
            ModelState.AddModelError(string.Empty, "Ocurrió un error inesperado. Por favor, inténtalo de nuevo más tarde.");
        }
        return View(viewModel);
    }

    [HttpGet]
    public async Task<IActionResult> Edit(string id)
    {
        if (string.IsNullOrEmpty(id))
        {
            TempData["StatusMessage"] = "Error inesperado. Por favor, inténtalo de nuevo más tarde.";
            return RedirectToAction(nameof(Index));
        }
        try
        {
            var role = await _roleManager.FindByIdAsync(id);
            if (role is null)
            {
                TempData["StatusMessage"] = "Error al intentar encontrar el rol.";
                return RedirectToAction(nameof(Index));
            }
            var viewModel = new RoleViewModel { Id = role.Id, Name = role.Name };
            return View(viewModel);
        }
        catch (Exception)
        {
            return RedirectToAction(nameof(HomeController.Error), "Home", new { message = "Ocurrió un error inesperado. Por favor, inténtalo de nuevo más tarde." });
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Edit(RoleViewModel viewModel)
    {
        if (!ModelState.IsValid) return View(viewModel);
        if (string.IsNullOrEmpty(viewModel.Id))
        {
            ModelState.AddModelError(string.Empty, "Ocurrió un error inesperado. Por favor, inténtalo de nuevo más tarde.");
            return View(viewModel);
        }

        try
        {
            if (await _roleManager.RoleExistsAsync(viewModel.Name!))
            {
                ModelState.AddModelError(nameof(RoleViewModel.Name), "El rol ya existe.");
                return View(viewModel);
            }

            var role = await _roleManager.FindByIdAsync(viewModel.Id);
            if (role is null)
            {
                ModelState.AddModelError(string.Empty, "Ocurrió un problema al intentar encontrar el rol.");
                return View(viewModel);
            }

            if (role.Name!.Equals(Roles.ADMIN))
            {
                ModelState.AddModelError(string.Empty, $"No puede modificar el rol {Roles.ADMIN}.");
                return View(viewModel);
            }

            role.Name = viewModel.Name;
            role.NormalizedName = _roleManager.NormalizeKey(viewModel.Name);
            var result = await _roleManager.UpdateAsync(role);
            if (result.Succeeded)
            {
                TempData["StatusMessage"] = "Nombre del rol modificado exitosamente.";
                return RedirectToAction(nameof(Index));
            }
            foreach (var error in result.Errors) ModelState.AddModelError(string.Empty, error.Description);
        }
        catch (Exception)
        {
            ModelState.AddModelError(string.Empty, "Ocurrió un error inesperado. Por favor, inténtalo de nuevo más tarde.");
        }
        return View(viewModel);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Delete(string id)
    {
        if (string.IsNullOrEmpty(id))
        {
            TempData["StatusMessage"] = "Error inesperado. Por favor, inténtalo de nuevo más tarde.";
            return RedirectToAction(nameof(Index));
        }
        try
        {
            var role = await _roleManager.FindByIdAsync(id);
            if (role is null)
            {
                TempData["StatusMessage"] = "Error al intentar encontrar el rol.";
                return RedirectToAction(nameof(Index));
            }

            // Verifica si hay usuarios asignados al rol
            var usersInRole = await _userManager.GetUsersInRoleAsync(role.Name!);
            if (usersInRole.Any())
            {
                TempData["StatusMessage"] = $"Error: No se puede eliminar el rol '{role.Name}' porque hay usuarios asignados a este rol.";
                return RedirectToAction(nameof(Index));
            }

            if (role.Name!.Equals(Roles.ADMIN))
            {
                TempData["StatusMessage"] = $"Error: No puede eliminar el rol {Roles.ADMIN}.";
                return RedirectToAction(nameof(Index));
            }

            var result = await _roleManager.DeleteAsync(role);
            if (result.Succeeded)
            {
                TempData["StatusMessage"] = "Rol eliminado correctamente.";
                return RedirectToAction(nameof(Index));
            }

            TempData["StatusMessage"] = $"Error al eliminar el rol: {result.Errors.FirstOrDefault()?.Description}";
        }
        catch (Exception)
        {
            TempData["StatusMessage"] = "Error inesperado. Por favor, inténtalo de nuevo más tarde.";
        }
        return RedirectToAction(nameof(Index));
    }

    [HttpGet]
    public async Task<IActionResult> UsersInRole(string id)
    {
        if (string.IsNullOrEmpty(id))
        {
            TempData["StatusMessage"] = "Error inesperado. Por favor, inténtalo de nuevo más tarde.";
            return RedirectToAction(nameof(Index));
        }

        try
        {
            var role = await _roleManager.FindByIdAsync(id);
            if (role == null)
            {
                TempData["StatusMessage"] = "Error: Rol no encontrado.";
                return RedirectToAction(nameof(Index));
            }

            // Obtiene todos los usuarios que tienen este rol
            var usersInRole = await _userManager.GetUsersInRoleAsync(role.Name!) ?? [];
            var userViewModels = usersInRole.Select(user => user.ToViewModel()).ToList() ?? [];
            ViewBag.RoleName = role.Name;

            return View(userViewModels);
        }
        catch (Exception)
        {
            TempData["StatusMessage"] = "Error inesperado. Por favor, inténtalo de nuevo más tarde.";
            return RedirectToAction(nameof(Index));
        }
    }

}

