# BankIdAspNetCoreDemo
Shows how to authenticate a user with BankID OIDC service. New version on AspNet Core 3.1 MVC in C#

You need to contact BankID Norge to get a client_id and client_secret combination. These propeties you can register in Resources.resx.
The default: redirect_uri=https://localhost:44323/signin-oidc (Should be registered with client info in OpenID Connect server.)

For time beeing userinfo only works with XID authentication. This should be fixed by end of May 2018.
