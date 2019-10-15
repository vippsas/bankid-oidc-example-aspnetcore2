using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;

namespace BankIdAspNetCore2Demo
{
    // Nice article which explains security configuration in .NET Core 2.0: https://github.com/aspnet/Security/issues/1310
    public class Startup
    {
        public static string authority = Properties.Resources.OIDC_BaseUrl;
        public static string manifestUrl = authority + "/.well-known/openid-configuration";
        public static string scope = Properties.Resources.Scope;

        // readonly string CORSAllowSpecificOrigins = "_corsAllowBankIDOIDCOrigins";

        private readonly ILogger _logger;

        IHostingEnvironment env = null;

        public Startup(IConfiguration configuration, ILogger<Startup> logger)
        {
            Configuration = configuration;
            _logger = logger;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(sharedOptions =>
            {
                sharedOptions.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                sharedOptions.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                sharedOptions.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
                sharedOptions.DefaultSignOutScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
            .AddCookie(options =>
            {
                options.AccessDeniedPath = new PathString("/Account/AccessDenied");
                options.LoginPath = new PathString("/Account/SignIn");
                options.LogoutPath = new PathString("/Account/SignOut");
            })
            .AddOpenIdConnect(o =>
            {
                // OpenID Connect Client/Server Identification:
                o.Authority = Properties.Resources.OIDC_BaseUrl;
                o.ClientId = Properties.Resources.ClientId;
                o.ClientSecret = Properties.Resources.ClientSecret;

                o.ResponseType = OpenIdConnectResponseType.Code; // As expected by OpenID framework on ASPNET Core 2.0.
                o.RequireHttpsMetadata = true;
                o.SaveTokens = true;
                o.TokenValidationParameters.NameClaimType = "name";
                o.TokenValidationParameters.AuthenticationType = "amr";
                o.TokenValidationParameters.RequireSignedTokens = true;
                o.TokenValidationParameters.SaveSigninToken = true;
                o.GetClaimsFromUserInfoEndpoint = Boolean.Parse(Properties.Resources.CallUserInfo?.ToLower());

                // BankID Tillegsinfo hentes med userinfo. Noen må spesifikt tas vare på - ikke alle claims blir det
                // per default for å spare plass:
                o.ClaimActions.MapJsonKey("phone_number", "phone_number");
                o.ClaimActions.MapCustomJson("address", jobj =>
                {
                    var values = jobj.GetEnumerator();
                    string result = string.Empty;

                    while (values.MoveNext())
                    {
                        var item = values.Current;
                        if ("address".Equals(item.Key))
                        {
                            // Formatert adresse blir tatt vare på (ligger først i strukturen)
                            result = item.Value.First.First.ToString();
                        }
                    }
                    return result;
                });

                o.Events = new OpenIdConnectEvents()
                {
                    OnRedirectToIdentityProvider = context =>
                    {
                        switch (context.ProtocolMessage.RequestType)
                        {
                            case OpenIdConnectRequestType.Authentication:

                                // context.ProtocolMessage.SetParameter(OpenIdConnectParameterNames.ResponseMode, "query");
                                context.ProtocolMessage.SetParameter(OpenIdConnectParameterNames.Scope, Startup.scope);
                                context.ProtocolMessage.SetParameter(OpenIdConnectParameterNames.State, "foo");

                                if (context.Properties.Items.ContainsKey("ui_locales"))
                                {
                                    string lh = context.Properties.Items["ui_locales"].Trim();
                                    if (lh.Length > 1)
                                    {
                                        context.ProtocolMessage.SetParameter(OpenIdConnectParameterNames.UiLocales, lh);
                                    }
                                }

                                if (context.Properties.Items.ContainsKey("login_hint"))
                                {
                                    string lh = context.Properties.Items["login_hint"].Trim();
                                    if (lh.Length > 1)
                                    {
                                        context.ProtocolMessage.SetParameter(OpenIdConnectParameterNames.LoginHint, lh);
                                    }
                                }
                                _logger.LogInformation($"OnRedirectToIdentityProvider: {context.ProtocolMessage.State}");
                                break;

                            case OpenIdConnectRequestType.Token:
                                break;

                            case OpenIdConnectRequestType.Logout:
                                break;

                            default:
                                break;
                        }
                        return Task.FromResult(0);
                    },
                    OnAuthorizationCodeReceived = context =>
                    {
                        _logger.LogInformation($"OnAuthorizationCodeReceived: {context.ProtocolMessage.State}");
                        // Possible Token endpoint request customisation: var temp = context.TokenEndpointRequest;
                        return Task.FromResult(0);
                    },
                    OnAuthenticationFailed = context =>
                    {
                        context.HandleResponse();

                        context.Response.StatusCode = 500;
                        context.Response.ContentType = "text/plain";
                        if (this.env != null && env.IsDevelopment())
                        {
                            // Debug only, in production do not share exceptions with the remote host.
                            return context.Response.WriteAsync(context.Exception.ToString());
                        }
                        return context.Response.WriteAsync("An error occurred processing your authentication.");
                    },
                    OnUserInformationReceived = context =>
                    {
                        // Check on return from userinfo - UserInformationReceivedContext context
                        return Task.FromResult(0);
                    },
                    OnTokenResponseReceived = context =>
                    {
                        // Possibility to check token response: var temp = context.TokenEndpointResponse;
                        return Task.FromResult(0);
                    }
                };
            });

            // services.AddCors(options =>
            // {
            //     options.AddPolicy(CORSAllowSpecificOrigins,
            //     builder =>
            //     {
            //         builder.WithOrigins("https://prototype3.bankidnorge.no",
            //                             "https://prototype.bankidnorge.no",
            //                             "https://oidc-preprod.bankidapis.no",
            //                             "http://localhost:44326",
            //                             "https://localhost:8888")
            //                             .AllowAnyHeader()
            //                             .AllowAnyMethod()
            //                             .AllowCredentials();
            //     });
            // });

            services.AddMvc();

            // Add cookie sessions for passing parameters from controller to event handlers
            // Adds a default in-memory implementation of IDistributedCache.
            //services.AddMemoryCache();
            services.AddSession(options =>
            {
                options.IdleTimeout = TimeSpan.FromSeconds(60);
                options.Cookie.HttpOnly = true;
            });

            // services.Configure<ForwardedHeadersOptions>(options =>
            // {
            //     options.ForwardedHeaders =
            //         ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
            // });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            this.env = env;

            if (env.IsDevelopment())
            {
                app.UseBrowserLink();
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();
            app.UseAuthentication();
            app.UseSession();

            // app.UseCors(CORSAllowSpecificOrigins);

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
