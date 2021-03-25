using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Threading.Tasks;

namespace BankIdAspNetCoreDemo
{
    public class Startup
    {
        public static string authority = Properties.Resources.OIDC_BaseUrl;
        public static string manifestUrl = authority + "/.well-known/openid-configuration";
        public static string scope = Properties.Resources.Scope;

        IWebHostEnvironment env = null;

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
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
                o.ClaimActions.MapJsonKey("nnin", "nnin");

                o.Events = new OpenIdConnectEvents()
                {
                    OnRedirectToIdentityProvider = context =>
                    {
                        switch (context.ProtocolMessage.RequestType)
                        {
                            case OpenIdConnectRequestType.Authentication:

                                context.ProtocolMessage.SetParameter(OpenIdConnectParameterNames.Scope, Startup.scope);

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

            services.AddControllersWithViews();

            // Add cookie sessions for passing parameters from controller to event handlers
            // Adds a default in-memory implementation of IDistributedCache.
            //services.AddMemoryCache();
            services.AddSession(options =>
            {
                options.IdleTimeout = TimeSpan.FromSeconds(60);
                options.Cookie.HttpOnly = true;
            });


        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
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
            app.UseRouting();

            app.UseAuthentication();

            app.UseSession();

            app.UseEndpoints(endpoints => {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}"
                );
            });
        }
    }
}
