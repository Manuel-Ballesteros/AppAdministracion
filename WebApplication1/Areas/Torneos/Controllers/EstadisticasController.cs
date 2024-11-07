using Microsoft.AspNetCore.Mvc;

namespace WebApplication1.Areas.Torneos.Controllers;
[Area("Torneos")]
public class EstadisticasController : Controller
{
    public IActionResult Index()
    {
        return View();
    }
}
