using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace BankIdDotNet2Demo.Controllers
{
    public class AccountController : Controller
    {
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
            var result = Challenge(authProperties, OpenIdConnectDefaults.AuthenticationScheme);
            return result;
        }

        //
        // GET: /Account/SignOut
        [HttpGet]
        public IActionResult SignOut()
        {
            var callbackUrl = Url.Action(nameof(SignedOut), "Account", values: null, protocol: Request.Scheme);
            return SignOut(
                new AuthenticationProperties { RedirectUri = callbackUrl },
                CookieAuthenticationDefaults.AuthenticationScheme,
                OpenIdConnectDefaults.AuthenticationScheme);
        }

        //

        // GET: /Account/SignedOut
        [HttpGet]
        public IActionResult SignedOut()
        {
            // Redirect to home page which switches views depening on user authentication.
            return RedirectToAction(nameof(HomeController.Index), "Home");
        }

        //
        // GET: /Account/AccessDenied
        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }
    }
}