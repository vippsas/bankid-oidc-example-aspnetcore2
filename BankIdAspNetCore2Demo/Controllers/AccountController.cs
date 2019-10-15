using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace BankIdAspNetCore2Demo.Controllers
{
    public class AccountController : Controller
    {
        private readonly ILogger _logger;

        public AccountController(ILogger<AccountController> logger) {
            _logger = logger;
        }

        //
        // GET: /Account/SignIn
        [HttpGet]
        public IActionResult SignIn()
        {
            var authProperties = new AuthenticationProperties { RedirectUri = "/" };

            // The redirect to OpenID Connect server has its own session.
            // Put session parameters into the AuthenticationProperties to be picked up by our event handler.
            string value = HttpContext.Session?.GetString("login_hint");
            if (!string.IsNullOrEmpty(value))
            {
                authProperties.Items.Add("login_hint", value);
            }
            value = HttpContext.Session?.GetString("ui_locales");
            if (!string.IsNullOrEmpty(value))
            {
                authProperties.Items.Add("ui_locales", value);
            }

            authProperties.RedirectUri = "http://localhost:44326/callback";

            HttpContext.Session.SetString("some_value", "foo");

            _logger.LogDebug($"THE SESSION ID IS {HttpContext.Session.Id}");

            var result = Challenge(authProperties, OpenIdConnectDefaults.AuthenticationScheme);
            return result;
        }

        //
        // GET: /Account/SignOut
        [HttpGet]
        public async System.Threading.Tasks.Task<IActionResult> SignOut()
        {
            await AuthenticationHttpContextExtensions.SignOutAsync(HttpContext);

            return RedirectToAction("Index", "Home");
        }


        //
        // GET: /Account/AccessDenied
        [AllowAnonymous]
        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }
    }
}