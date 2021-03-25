using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;
using System.IdentityModel.Tokens.Jwt;

namespace BankIdAspNetCoreDemo.Controllers
{
    public class HomeController : Controller
    {
        public async System.Threading.Tasks.Task<IActionResult> Index()
        {
            if (User.Identity.IsAuthenticated)
            {
                ViewBag.Title1 = "(Microsoft.AspNetCore.Mvc.ClaimsPrincipal) User.Claims:";
                ViewBag.Title2 = string.Empty;
                ViewBag.Message = string.Empty;
                // If you need the access_token: string accessToken = await HttpContext.GetTokenAsync("access_token");
                string idToken = await HttpContext.GetTokenAsync("id_token");
                // Prepare for display.
                ViewBag.id_token = new JwtSecurityToken(idToken).ToString();
            }
            else
            {
                string value = HttpContext.Session.GetString("login_hint");

                if (string.IsNullOrEmpty(value))
                {
                    HttpContext.Session.SetString("login_hint", " ");
                }

                value = HttpContext.Session.GetString("ui_locales");

                if (string.IsNullOrEmpty(value))
                {
                    HttpContext.Session.SetString("ui_locales", "no");
                }

            }
            return View();
        }

        public IActionResult About()
        {
            ViewData["Message"] = "A demonstration on how to use BankID's OpenID Connect server";
            ViewData["Message2"] = "Programmed by Jens Erik Torgersen, Kantega AS.";

            return View();
        }

        public IActionResult Contact()
        {
            ViewData["Message"] = "https://confluence.bankidnorge.no/confluence/display/DEVPUB/BankID+Norway+Developer+Portal";

            return View();
        }

        [AllowAnonymous]
        [HttpGet]
        public ActionResult SetLoginHint(string login_hint)
        {
            HttpContext.Session.SetString("login_hint", login_hint ?? " ");
            return RedirectToAction("Index", "Home");
        }
        [AllowAnonymous]
        [HttpGet]
        public ActionResult SetUiLocales(string ui_locales)
        {
            HttpContext.Session.SetString("ui_locales", ui_locales ?? " ");
            return RedirectToAction("Index", "Home");
        }

        [AllowAnonymous]
        public ActionResult Error(string message)
        {

            ViewBag.Message = message;
            return View("~/Views/Shared/Error.cshtml");
        }
    }
}
