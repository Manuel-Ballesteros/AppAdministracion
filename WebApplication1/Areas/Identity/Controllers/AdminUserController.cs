using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using WebApplication1.Areas.Identity.Models;
using WebApplication1.Constants;
using WebApplication1.Controllers;
using WebApplication1.Data.Entities;
using WebApplication1.Mappings;
using WebApplication1.Models;

namespace WebApplication1.Areas.Identity.Controllers;
[Authorize(Roles = Roles.ADMIN)]
[Area("Identity")]
public class AdminUserController(UserManager<User> userManager, RoleManager<IdentityRole> roleManager) : Controller
{
    private readonly UserManager<User> _userManager = userManager;
    private readonly RoleManager<IdentityRole> _roleManager = roleManager;

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        try
        {
            var users = await _userManager.Users.ToListAsync();
            var userViewModels = new List<UserViewModel>();
            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);
                var viewModel = user.ToViewModel();
                viewModel.Roles = roles;
                userViewModels.Add(viewModel);
            }
            return View(userViewModels);
        }
        catch (Exception)
        {
            return RedirectToAction(nameof(HomeController.Error), "Home", new { message = "Ocurrió un error inesperado. Por favor, inténtalo de nuevo más tarde." });
        }
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
            var user = await _userManager.FindByIdAsync(id);
            if (user is null)
            {
                TempData["StatusMessage"] = "Error al intentar encontrar el usuario.";
                return RedirectToAction(nameof(Index));
            }
            var viewModel = user.ToViewModel();
            viewModel.Roles = await _userManager.GetRolesAsync(user) ?? [];
            return View(viewModel);
        }
        catch (Exception)
        {
            return RedirectToAction(nameof(HomeController.Error), "Home", new { message = "Ocurrió un error inesperado. Por favor, inténtalo de nuevo más tarde." });
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Edit(UserViewModel viewModel)
    {
        if (!ModelState.IsValid) return View(viewModel);
        if (string.IsNullOrEmpty(viewModel.Id))
        {
            ModelState.AddModelError(string.Empty, "Ocurrió un error inesperado. Por favor, inténtalo de nuevo más tarde.");
            return View(viewModel);
        }

        try
        {
            var user = await _userManager.FindByIdAsync(viewModel.Id);
            if (user is null)
            {
                ModelState.AddModelError(string.Empty, "Ocurrió un problema al intentar encontrar el usuario.");
                return View(viewModel);
            }

            user.Name = viewModel.Name!;
            user.LastName = viewModel.LastName!;
            if (user.PhoneNumber != viewModel.PhoneNumber)
            {
                var setPhoneResult = await _userManager.SetPhoneNumberAsync(user, viewModel.PhoneNumber ?? string.Empty);
                if (!setPhoneResult.Succeeded)
                {
                    var errorMessage = setPhoneResult.Errors.FirstOrDefault()?.Description ?? "Ocurrió un error al actualizar el número de teléfono.";
                    ModelState.AddModelError(nameof(UserViewModel.PhoneNumber), errorMessage);
                    return View(viewModel);
                }
            }

            var updateResult = await _userManager.UpdateAsync(user);
            if (updateResult.Succeeded)
            {
                TempData["StatusMessage"] = "Perfil editado exitosamente.";
                return RedirectToAction(nameof(Index));
            }
            foreach (var error in updateResult.Errors) ModelState.AddModelError(string.Empty, error.Description);
        }
        catch (Exception)
        {
            ModelState.AddModelError(string.Empty, "Ocurrió un error inesperado. Por favor, inténtalo de nuevo más tarde.");
        }
        return View(viewModel);
    }

    [HttpGet]
    public async Task<IActionResult> AssignRoles(string id)
    {
        if (string.IsNullOrEmpty(id))
        {
            TempData["StatusMessage"] = "Error inesperado. Por favor, inténtalo de nuevo más tarde.";
            return RedirectToAction(nameof(Index));
        }
        try
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user is null)
            {
                TempData["StatusMessage"] = "Error al intentar encontrar el usuario.";
                return RedirectToAction(nameof(Index));
            }

            var viewModel = new AssignRolesViewModel
            {
                Id = user.Id,
                FullName = $"{user.Name} {user.LastName}",
                UserRoles = await _userManager.GetRolesAsync(user) ?? [],
                AllRoles = _roleManager.Roles.Select(r => r.Name).ToList() ?? []
            };

            return View(viewModel);
        }
        catch (Exception)
        {
            return RedirectToAction(nameof(HomeController.Error), "Home", new { message = "Ocurrió un error inesperado. Por favor, inténtalo de nuevo más tarde." });
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AssignRoles(AssignRolesViewModel viewModel)
    {
        if (string.IsNullOrEmpty(viewModel.Id))
        {
            TempData["StatusMessage"] = "Error inesperado. Por favor, inténtalo de nuevo más tarde.";
            return RedirectToAction(nameof(Index));
        }
        try
        {
            var user = await _userManager.FindByIdAsync(viewModel.Id);
            if (user is null)
            {
                TempData["StatusMessage"] = "Error al intentar encontrar el usuario.";
                return RedirectToAction(nameof(Index));
            }

            var currentRoles = await _userManager.GetRolesAsync(user);
            var rolesToAdd = viewModel.SelectedRoles.Except(currentRoles).ToList();
            var rolesToRemove = currentRoles.Except(viewModel.SelectedRoles).ToList();

            var AddToRolesResult = await _userManager.AddToRolesAsync(user, rolesToAdd);
            if (!AddToRolesResult.Succeeded)
            {
                foreach (var error in AddToRolesResult.Errors) ModelState.AddModelError(string.Empty, error.Description);
                return View(viewModel);
            }
            var RemoveFromRolesResult = await _userManager.RemoveFromRolesAsync(user, rolesToRemove);
            if (!AddToRolesResult.Succeeded)
            {
                foreach (var error in AddToRolesResult.Errors) ModelState.AddModelError(string.Empty, error.Description);
                return View(viewModel);
            }

            TempData["StatusMessage"] = "Roles asignados correctamente.";
            return RedirectToAction(nameof(Index));

        }
        catch (Exception)
        {
            return RedirectToAction(nameof(HomeController.Error), "Home", new { message = "Ocurrió un error inesperado. Por favor, inténtalo de nuevo más tarde." });
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Lock(string id)
    {
        if (string.IsNullOrEmpty(id))
        {
            TempData["StatusMessage"] = "Error inesperado. Por favor, inténtalo de nuevo más tarde.";
            return RedirectToAction(nameof(Index));
        }
        try
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user is null)
            {
                TempData["StatusMessage"] = "Error al intentar encontrar el usuario.";
                return RedirectToAction(nameof(Index));
            }
            var lockoutEndDate = DateTimeOffset.UtcNow.AddMonths(1);
            var result = await _userManager.SetLockoutEndDateAsync(user, lockoutEndDate);
            if (result.Succeeded)
            {
                TempData["StatusMessage"] = $"El usuario ha sido bloqueado exitosamente hasta el {lockoutEndDate.LocalDateTime}.";
                return RedirectToAction(nameof(Index));
            }
            else
            {
                TempData["StatusMessage"] = "Error al intentar bloquear el usuario.";
                return RedirectToAction(nameof(Index));
            }
        }
        catch (Exception)
        {
            return RedirectToAction(nameof(HomeController.Error), "Home", new { message = "Ocurrió un error inesperado. Por favor, inténtalo de nuevo más tarde." });
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Unlock(string id)
    {
        if (string.IsNullOrEmpty(id))
        {
            TempData["StatusMessage"] = "Error inesperado. Por favor, inténtalo de nuevo más tarde.";
            return RedirectToAction(nameof(Index));
        }
        try
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user is null)
            {
                TempData["StatusMessage"] = "Error al intentar encontrar el usuario.";
                return RedirectToAction(nameof(Index));
            }

            var result = await _userManager.SetLockoutEndDateAsync(user, null);
            if (result.Succeeded)
            {
                // Opcional: Reiniciar el contador de accesos fallidos
                await _userManager.ResetAccessFailedCountAsync(user);
                TempData["StatusMessage"] = "El usuario ha sido habilitado exitosamente.";
                return RedirectToAction(nameof(Index));
            }
            else
            {
                TempData["StatusMessage"] = "Error al intentar habilitar el usuario.";
                return RedirectToAction(nameof(Index));
            }
        }
        catch (Exception)
        {
            return RedirectToAction(nameof(HomeController.Error), "Home", new { message = "Ocurrió un error inesperado. Por favor, inténtalo de nuevo más tarde." });
        }
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
            var user = await _userManager.FindByIdAsync(id);
            if (user is null)
            {
                TempData["StatusMessage"] = "Error al intentar encontrar el usuario.";
                return RedirectToAction(nameof(Index));
            }
            /*
             * Uso del soft delete:
                 user.IsActive = false;
                 var result = await _userManager.UpdateAsync(user);
             */

            var result = await _userManager.DeleteAsync(user);
            if (result.Succeeded)
            {
                TempData["StatusMessage"] = "El usuario ha sido eliminado exitosamente.";
                return RedirectToAction(nameof(Index));
            }
            else
            {
                TempData["StatusMessage"] = "Error al intentar eliminar el usuario.";
                return RedirectToAction(nameof(Index));
            }
        }
        catch (Exception)
        {
            return RedirectToAction(nameof(HomeController.Error), "Home", new { message = "Ocurrió un error inesperado. Por favor, inténtalo de nuevo más tarde." });
        }
    }


    [HttpGet]
    public async Task<IActionResult> RegisterUser()
    {
        var viewModel = new RegisterViewModel();
        viewModel.Roles = await GetRolesNameAsync();
        return View(viewModel);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RegisterUser(RegisterViewModel viewModel)
    {
        try
        {
            viewModel.Roles = await GetRolesNameAsync();
            if (!ModelState.IsValid) return View(viewModel);

            if (string.IsNullOrEmpty(viewModel.SelectedRole) || !await _roleManager.RoleExistsAsync(viewModel.SelectedRole))
            {
                ModelState.AddModelError(string.Empty, "El rol seleccionado no es válido.");
                return View(viewModel);
            }

            var user = viewModel.ToEntity();
            var result = await _userManager.CreateAsync(user, viewModel.Password!);

            if (!result.Succeeded)
            {
                HandleIdentityErrors(result);
                return View(viewModel);
            }

            var addRoleResult = await _userManager.AddToRoleAsync(user, viewModel.SelectedRole);
            if (!addRoleResult.Succeeded)
            {
                // Intentar eliminar el usuario creado
                var deleteResult = await _userManager.DeleteAsync(user);
                if (deleteResult.Succeeded)
                    ModelState.AddModelError(string.Empty, "No se pudo asignar el rol al usuario. El usuario no ha sido creado.");
                else
                    ModelState.AddModelError(string.Empty, "No se pudo asignar el rol al usuario y tampoco se pudo eliminar el usuario creado. Por favor, contacte al soporte técnico.");

                HandleIdentityErrors(addRoleResult);
                return View(viewModel);
            }
            TempData["StatusMessage"] = "Usuario creado exitosamente.";
            return RedirectToAction(nameof(HomeController.Index), "Home", new { area = "" });
        }
        catch (Exception)
        {
            ModelState.AddModelError(string.Empty, "Ocurrió un error inesperado. Por favor, inténtalo de nuevo más tarde.");
            return View(viewModel);
        }
    }

    private async Task<IEnumerable<SelectListItem>> GetRolesNameAsync()
    {
        try
        {
            var rolesName = await _roleManager.Roles.Select(role => role.Name).ToListAsync() ?? [];
            return rolesName.Select(r => new SelectListItem { Value = r, Text = r }).ToList();
        }
        catch (Exception)
        {
            throw;
        }
    }

    private void HandleIdentityErrors(IdentityResult result)
    {
        foreach (var error in result.Errors)
        {
            switch (error.Code)
            {
                case "DuplicateUserName":
                    ModelState.AddModelError(nameof(RegisterViewModel.Email), "El correo electrónico ya está registrado.");
                    break;
                case "DuplicateEmail":
                    ModelState.AddModelError(nameof(RegisterViewModel.Email), "El correo electrónico ya está registrado.");
                    break;
                default:
                    ModelState.AddModelError(string.Empty, error.Description);
                    break;
            }
        }
    }

}
