using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace Web.Models
{


    #region ikinci
    //public class JwtAuthorizeAttribute : ActionFilterAttribute
    //{
    //    private readonly string _secretKey;
    //    private readonly string _issuer;

    //    public JwtAuthorizeAttribute(IConfiguration configuration)
    //    {
    //        _secretKey = configuration["Jwt:Key"];
    //        _issuer = configuration["Jwt:Issuer"];
    //    }

    //    public override void OnActionExecuting(ActionExecutingContext context)
    //    {
    //        var httpContextAccessor = (IHttpContextAccessor)context.HttpContext.RequestServices.GetService(typeof(IHttpContextAccessor));
    //        var token = httpContextAccessor.HttpContext.Session.GetString("Token");

    //        if (string.IsNullOrEmpty(token))
    //        {
    //            context.Result = new UnauthorizedResult(); // Token yoksa 401 döner
    //            return;
    //        }

    //        var claimsPrincipal = ValidateToken(token);
    //        if (claimsPrincipal == null)
    //        {
    //            context.Result = new UnauthorizedResult(); // Token geçersizse 401 döner
    //            return;
    //        }

    //        context.HttpContext.User = claimsPrincipal;
    //    }

    //    private ClaimsPrincipal ValidateToken(string token)
    //    {
    //        var tokenHandler = new JwtSecurityTokenHandler();
    //        var key = Encoding.ASCII.GetBytes(_secretKey);

    //        var validationParameters = new TokenValidationParameters
    //        {
    //            ValidateIssuerSigningKey = true,
    //            IssuerSigningKey = new SymmetricSecurityKey(key),

    //            ValidateIssuer = true,
    //            ValidIssuer = _issuer,

    //            ValidateAudience = false, // Audience kontrolü yapmıyorsanız false bırakabilirsiniz
    //                                      // ValidAudience = "your_audience_here", // Eğer belirli bir audience varsa burayı ayarlayın

    //            ValidateLifetime = true,
    //            ClockSkew = TimeSpan.Zero // Token süresi dolduğunda hemen geçersiz kılın
    //        };

    //        try
    //        {
    //            var principal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);
    //            return principal;
    //        }
    //        catch
    //        {
    //            return null; // Token geçersiz
    //        }
    //    }
    //} 
    #endregion

    public class JwtAuthorizeAttribute : Attribute, IAuthorizationFilter
    {

        public void OnAuthorization(AuthorizationFilterContext context)
        {
            var httpContextAccessor = (IHttpContextAccessor)context.HttpContext.RequestServices.GetService(typeof(IHttpContextAccessor));
            var token = httpContextAccessor.HttpContext.Session.GetString("Token");

            if (string.IsNullOrEmpty(token))
            {
                context.Result = new UnauthorizedResult(); // Token yoksa 401 döner
            }
            else
            {
                // Token'ı doğrulama işlemi burada yapılabilir
                var claimsPrincipal = ValidateToken(token);
                if (claimsPrincipal == null)
                {
                    context.Result = new UnauthorizedResult(); // Token geçersizse 401 döner
                    return;
                }

                // Kullanıcı bilgilerini HttpContext'e set et
                context.HttpContext.User = claimsPrincipal;
            }
        }

        private ClaimsPrincipal ValidateToken(string token)
        {
            // Burada token'ı doğrulama ve kullanıcı bilgilerini alma işlemini yapın
            // Örneğin: JwtSecurityTokenHandler kullanarak
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("BuBirGizliAnahtarBuBirGizliAnahtarBuBirGizliAnahtarBuBirGizliAnahtarBuBirGizliAnahtarBuBirGizliAnahtar");

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),

                ValidateIssuer = true,
                ValidIssuer = "yourdomain.com", // Token'ı oluştururken kullandığınız issuer

                ValidateAudience = false, // Audience kontrolü yapmıyorsanız false bırakabilirsiniz

                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero // Token süresi dolduğunda hemen geçersiz kılın
            };

            try
            {
                var principal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);
                return principal; // Token geçerli
            }
            catch (SecurityTokenExpiredException)
            {
                Console.WriteLine("Token süresi dolmuş.");
                return null; // Token süresi dolmuş
            }
            catch (SecurityTokenInvalidSignatureException)
            {
                Console.WriteLine("Token imzası geçersiz.");
                return null; // Geçersiz imza
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Token doğrulama hatası: {ex.Message}");
                return null; // Diğer hatalar
            }
        }
    }

}
