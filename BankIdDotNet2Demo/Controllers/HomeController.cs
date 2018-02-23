using BankIdDotNet2Demo.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Text;
using Microsoft.AspNetCore.Http;

namespace BankIdDotNet2Demo.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            if (User.Identity.IsAuthenticated)
            {
                ViewBag.Title1 = "User.Claims:";
                ViewBag.Title2 = string.Empty;
                ViewBag.Message = string.Empty;
            }
            else
            {
                string value = HttpContext.Session.GetString("login_hint");

                if (string.IsNullOrEmpty(value))
                {
                    HttpContext.Session.SetString("login_hint", "BID:07025302553");
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
            ViewData["Message"] = "A demonstration on how to user BankID's OpenID Connect server\n Programmed by Jens Erik Torgersen, Kantega AS.";

            return View();
        }

        public IActionResult Contact()
        {
            ViewData["Message"] = "https://confluence.bankidnorge.no/confluence/display/DEVPUB/BankID+Norway+Developer+Portal";

            return View();
        }

        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        private byte[] getByteArray(string s)
        {
            if (string.IsNullOrEmpty(s))
                return null;

            var enc = new UTF8Encoding();
            return enc.GetBytes(s.ToCharArray());
        }

        private string getString(byte[] b)
        {
            if (b == null || b.Length == 0)
                return string.Empty;


            var enc = new UTF8Encoding();
            return enc.GetString(b);
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
        [HttpGet]
        public ActionResult SetJWS(string check_jws = "false")
        {
            // Startup.useRequestParam = string.IsNullOrEmpty(check_jws) ? false : bool.Parse(check_jws);
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
