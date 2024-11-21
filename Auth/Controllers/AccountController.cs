using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthServer.Controllers
{
    public class AccountController : Controller
    {
        private const string JwtKey = "SuperSecretKey@123SuperSecretKey@123SuperSecretKey@123"; // Aynı key kullanılmalı
        private const string Issuer = "https://localhost:5075"; // AuthServer URL'si
        private const string Audience = "https://localhost:5258"; // ClientApp URL'si

        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Login(string username, string password)
        {
            if (username == "admin" && password == "123456") // Örnek kontrol
            {
                var claims = new[]
                {
                    new Claim(ClaimTypes.Name, username),
                    new Claim(ClaimTypes.Role, "User")
                };

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JwtKey));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                var token = new JwtSecurityToken(
                    issuer: Issuer,
                    audience: Audience,
                    claims: claims,
                    expires: DateTime.Now.AddMinutes(30),
                    signingCredentials: creds);

                var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

                // Token'ı çerezde saklama
                Response.Cookies.Append("AuthToken", tokenString, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.None,
                    Domain = "localhost"
                });

                var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));


                return Ok("Başarılı");
            }

            ViewBag.Error = "Invalid credentials";
            return View();
        }

        [HttpPost]
        public IActionResult LogOff()
        {
            Response.Cookies.Delete("AuthToken", new CookieOptions
            {
                Domain = "localhost",
                Secure = true,
                SameSite = SameSiteMode.None
            });

            return Ok("Çıkış");
        }
        [HttpPost]
        public IActionResult GetUser()
        {
            var username = User.Identity.Name;
            return Ok(username);
        }
    }
}
