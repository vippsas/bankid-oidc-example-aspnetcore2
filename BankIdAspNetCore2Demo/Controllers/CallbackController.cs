using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace BankIdAspNetCore2Demo.Controllers
{
    public class CallbackController : Controller
    {
        private readonly ILogger _logger;

        public CallbackController(ILogger<CallbackController> logger) {
            _logger = logger;
        }

        public string Index()
        {
            if ( HttpContext.Session.IsAvailable ) {
                string value = HttpContext.Session.GetString("some_value");
                if (!string.IsNullOrEmpty(value))
                {
                    _logger.LogDebug($"THE VALUE OF FOO: {value}");
                    return $"FOUND THE SAME ID: {HttpContext.Session.Id}";
                } else {
                    return $"NEW ID?: {HttpContext.Session.Id}";
                }
            }
            return "This is my default action...";
        }
    }

}