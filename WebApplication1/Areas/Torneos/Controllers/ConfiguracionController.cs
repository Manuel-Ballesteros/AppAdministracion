using Microsoft.AspNetCore.Mvc;

namespace WebApplication1.Areas.Torneos.Controllers;
[Area("Torneos")]
public class ConfiguracionController : Controller
{

    public IActionResult Index()
    {
        return View();
    }


}
