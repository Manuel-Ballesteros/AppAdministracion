using Microsoft.AspNetCore.Mvc;

namespace WebApplication1.Areas.Torneos.Controllers;
[Area("Torneos")]
public class CuerdasController : Controller
{
    public IActionResult Index()
    {
        return View();
    }    
}
