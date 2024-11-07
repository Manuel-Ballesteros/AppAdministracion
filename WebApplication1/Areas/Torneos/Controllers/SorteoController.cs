using Microsoft.AspNetCore.Mvc;

namespace WebApplication1.Areas.Torneos.Controllers;
[Area("Torneos")]
public class SorteoController : Controller
{
    public IActionResult Index()
    {
        return View();
    }

}
