using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ClientApp.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        [AllowAnonymous]
        public IActionResult Login()
        {
            return Redirect("https://localhost:5075/Account/Login"); // AuthServer Login
        }

        [HttpPost]
        public IActionResult GetUser()
        {
            var username = User.Identity.Name;
            return Ok(username);
        }
    }
}
