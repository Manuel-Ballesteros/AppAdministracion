using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WebApplication1.Areas.Identity.Models;
using WebApplication1.Controllers;
using WebApplication1.Data.Entities;
using WebApplication1.Mappings;
using WebApplication1.Models;

namespace WebApplication1.Areas.Identity.Controllers;
[Area("Identity")]
public class UserController(UserManager<User> userManager) : Controller
{
    private readonly UserManager<User> _userManager = userManager;

    [HttpGet]
    public async Task<IActionResult> EditProfile()
    {
        try
        {
            var user = await _userManager.GetUserAsync(User);
            if (user is null) return RedirectToAction(nameof(HomeController.Error), "Home", new { message = "El usuario no fue encontrado." });
            var viewmodel = user.ToViewModel();
            return View(viewmodel);
        }
        catch (Exception)
        {
            throw;
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> EditProfile(UserViewModel viewModel)
    {
        if (!ModelState.IsValid) return View(viewModel);
        try
        {
            var user = await _userManager.GetUserAsync(User);
            if (user is null) return RedirectToAction(nameof(HomeController.Error), "Home", new { message = "El usuario no fue encontrado." });
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
                return RedirectToAction(nameof(HomeController.Index), "Home", new { area = "" });
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
    public IActionResult ChangePassword() => View();

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChangePassword(ChangePasswordViewModel viewModel)
    {
        if (!ModelState.IsValid) return View(viewModel);
        try
        {
            var user = await _userManager.GetUserAsync(User);
            if (user is null) return RedirectToAction(nameof(HomeController.Error), "Home", new { message = "El usuario no fue encontrado." });

            var resultValidateOldPassword = _userManager.PasswordHasher.VerifyHashedPassword(user, user.PasswordHash!, viewModel.OldPassword!); // no es async

            if (resultValidateOldPassword == PasswordVerificationResult.Failed)
            {
                ModelState.AddModelError(nameof(ChangePasswordViewModel.OldPassword), "Contraseña incorrecta.");
                return View(viewModel);
            }
            var hashNewPassword = _userManager.PasswordHasher.HashPassword(user, viewModel.NewPassword!);
            user.PasswordHash = hashNewPassword;

            var updateResult = await _userManager.UpdateAsync(user);
            if (updateResult.Succeeded)
            {
                TempData["StatusMessage"] = "Se ha cambiado la contraseña.";
                return RedirectToAction(nameof(HomeController.Index), "Home", new { area = "" });
            }
            foreach (var error in updateResult.Errors) ModelState.AddModelError(string.Empty, error.Description);
        }
        catch (Exception)
        {
            ModelState.AddModelError(string.Empty, "Ocurrió un error inesperado. Por favor, inténtalo de nuevo más tarde.");
        }
        return View(viewModel);
    }
}

