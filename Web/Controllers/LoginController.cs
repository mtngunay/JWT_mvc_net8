using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Web.Models;

namespace Web.Controllers
{
    public class LoginController : Controller
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        public LoginController(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }
        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Index(UserModel userModel)
        {
            // Basit kullanıcı doğrulaması
            if (userModel.Username == "admin" && userModel.Password == "123")
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes("BuBirGizliAnahtarBuBirGizliAnahtarBuBirGizliAnahtarBuBirGizliAnahtarBuBirGizliAnahtarBuBirGizliAnahtar");
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new Claim[]
                    {
                    new Claim(ClaimTypes.Name, userModel.Username)
                    }),
                    Expires = DateTime.UtcNow.AddHours(1),
                    Issuer = "yourdomain.com",
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                // Token'ı saklayabilirsin (örneğin, session)
                //  _httpContextAccessor.HttpContext.Session.SetString("Token", tokenHandler.WriteToken(token));



                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, userModel.Username)
                };
                var identity = new ClaimsIdentity(claims, "login");
                var principal = new ClaimsPrincipal(identity);

                // HttpContext.User'ı ayarla
                _httpContextAccessor.HttpContext.User = principal;

                // Token'ı session'a kaydet
                _httpContextAccessor.HttpContext.Session.SetString("Token", tokenHandler.WriteToken(token));



                return RedirectToAction("Index", "Home");
            }
            ModelState.AddModelError("", "Kullanıcı adı veya şifre hatalı.");
            return View(userModel);
        }
    }
}
