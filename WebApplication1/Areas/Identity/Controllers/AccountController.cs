using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;
using WebApplication1.Areas.Identity.Models;
using WebApplication1.Constants;
using WebApplication1.Controllers;
using WebApplication1.Data.Entities;
using WebApplication1.Mappings;
using WebApplication1.Services.Email;

namespace WebApplication1.Areas.Identity.Controllers;
[Area("Identity")]
[AllowAnonymous]
public class AccountController(UserManager<User> userManager, SignInManager<User> signInManager, IEmailService emailService) : Controller
{
    private readonly UserManager<User> _userManager = userManager;
    private readonly SignInManager<User> _signInManager = signInManager;
    private readonly IEmailService _emailService = emailService;

    [HttpGet]
    public IActionResult Register() => View();

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(RegisterViewModel viewModel)
    {
        try
        {
            if (!ModelState.IsValid) return View(viewModel);

            var user = viewModel.ToEntity();
            var result = await _userManager.CreateAsync(user, viewModel.Password!);

            if (!result.Succeeded)
            {
                HandleIdentityErrors(result);
                return View(viewModel);
            }

            var addRoleResult = await _userManager.AddToRoleAsync(user, Roles.USER);
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

            await _signInManager.SignInAsync(user, isPersistent: false);
            return RedirectToAction(nameof(HomeController.Index), "Home", new { area = "" });
        }
        catch (Exception)
        {
            ModelState.AddModelError(string.Empty, "Ocurrió un error inesperado. Por favor, inténtalo de nuevo más tarde.");
            return View(viewModel);
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

    [HttpGet]
    public IActionResult Login(string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel viewModel, string? returnUrl = null)
    {
        if (!ModelState.IsValid) return View(viewModel);
        ViewData["ReturnUrl"] = returnUrl;
        returnUrl ??= Url.Content("~/");

        try
        {            
            var result = await _signInManager.PasswordSignInAsync(
                viewModel.Email!,
                viewModel.Password!,
                viewModel.RememberMe,
                lockoutOnFailure: true);

            if (result is null)
            {
                ModelState.AddModelError(string.Empty, "Ocurrió un error al autenticar el usuario.");
                return View(viewModel);
            }

            if (result.Succeeded) return LocalRedirect(returnUrl);
            else if (result.IsLockedOut) ModelState.AddModelError(string.Empty, "Usuario Bloqueado. Demasiados intentos fallidos.");
            else ModelState.AddModelError(string.Empty, "Acceso inválido. Verifique las credenciales de acceso.");
        }
        catch (Exception)
        {
            ModelState.AddModelError(string.Empty, "Ocurrió un error inesperado. Por favor, inténtalo de nuevo más tarde.");
        }
        return View(viewModel);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        return RedirectToAction(nameof(HomeController.Index), "Home", new { area = "" });
    }

    [HttpGet]
    public IActionResult ForgotPassword() => View();

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel viewModel)
    {
        if (!ModelState.IsValid) return View(viewModel);

        try
        {
            User? user = await _userManager.FindByEmailAsync(viewModel.Email!);

            if (user is null)
            {
                // No revelar que el usuario no existe, por eso lo reenviamos a la vista que dice que ya se le envio el correo.
                return RedirectToAction(nameof(ForgotPasswordConfirmation));
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var tokenBase64 = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
            var callbackUrl = Url.Action(nameof(ResetPassword), "Account", new { token = tokenBase64 }, protocol: HttpContext.Request.Scheme);

            var body = $@"
            Hola {user.Name},
            Recibimos una solicitud para restablecer tu contraseña. Haz clic en el siguiente enlace para continuar:
            {callbackUrl}

            Si no solicitaste este cambio, puedes ignorar este correo.
            Saludos, El equipo de WebApplication1";

            await _emailService.SendEmail(viewModel.Email!, "Restablecer la contraseña - WebApplication1", body);

            return RedirectToAction(nameof(ForgotPasswordConfirmation));
        }
        catch (Exception)
        {
            ModelState.AddModelError(string.Empty, "Ocurrió un error inesperado. Por favor, inténtalo de nuevo más tarde.");
            return View(viewModel);
        }
    }

    [HttpGet]
    public IActionResult ForgotPasswordConfirmation() => View();

    [HttpGet]
    public IActionResult ResetPassword(string token)
    {
        if (string.IsNullOrEmpty(token))
        {
            ViewBag.ErrorMessage = "Se debe proporcionar un código para restablecer la contraseña.";
            return View("AccessDenied");
        }
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResetPassword(ResetPasswordViewModel viewModel)
    {
        if (!ModelState.IsValid) return View(viewModel);
        if (string.IsNullOrEmpty(viewModel.Token))
        {
            ModelState.AddModelError(string.Empty, "El token de restablecimiento es inválido.");
            return View(viewModel);
        }

        try
        {
            var user = await _userManager.FindByEmailAsync(viewModel.Email!);

            if (user is null)
            {
                // No revelar que el usuario no existe, por eso lo reenviamos a la vista que dice que ya se reseteo la contraseña.
                return RedirectToAction(nameof(ResetPasswordConfirmation));
            }
            var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(viewModel.Token));
            var result = await _userManager.ResetPasswordAsync(user, decodedToken, viewModel.Password!);
            if (result.Succeeded) return RedirectToAction(nameof(ResetPasswordConfirmation));

            HandleIdentityErrors(result);
        }
        catch (Exception)
        {
            ModelState.AddModelError(string.Empty, "Ocurrió un error inesperado. Por favor, inténtalo de nuevo más tarde.");
        }
        return View(viewModel);
    }

    [HttpGet]
    public IActionResult ResetPasswordConfirmation() => View();

    [HttpGet]
    public IActionResult AccessDenied() => View();
}
