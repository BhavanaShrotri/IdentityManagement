using IdentityManagement;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddDataProtection();

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme);

builder.Services.AddAuthorization(builder =>
{
    builder.AddPolicy("manager", pb =>
    {
        pb.RequireAuthenticatedUser()
        .AddAuthenticationSchemes(CookieAuthenticationDefaults.AuthenticationScheme)
        .RequireClaim("role", "manager");
    });
    
});

builder.Services.AddSingleton<DataBase>();
builder.Services.AddSingleton<IPasswordHasher<User>, PasswordHasher<User>>();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => "Hello World !");
app.MapGet("/protected", () => "super secret").RequireAuthorization("manager");

app.MapGet("/register", async (
    string username,
    string password,
    IPasswordHasher<User> hasher,
    DataBase db,
    HttpContext ctx) =>
{
    var user = new User() { UserName = username };
    user.PasswordHash = hasher.HashPassword(user, password);
    await db.putAsync(user);

    await ctx.SignInAsync(
        CookieAuthenticationDefaults.AuthenticationScheme,
        UserHelper.Convert(user));

    return user;
});

app.MapGet("/login", async (
    string username,
    string password,
    IPasswordHasher<User> hasher,
    DataBase db,
    HttpContext ctx) =>
{
    var user = await db.GetUserAsync(username);
    var result = hasher.VerifyHashedPassword(user, user.PasswordHash, password);

    if (result == PasswordVerificationResult.Failed)
    {
        return "Bad Credentials";
    }  
    await ctx.SignInAsync(
        CookieAuthenticationDefaults.AuthenticationScheme,
        UserHelper.Convert(user));

    return "Logged In! :)";
});



app.MapGet("/promote", async (
    string username,
    DataBase db) =>
{
    var user = await db.GetUserAsync(username);
    user.Claims.Add(new UserClaim(type : "role", value : "manager"));
    await db.putAsync(user);
    
    return "promoted  :)";
});

app.MapGet("/start-password-reset", async (
    string username,
    DataBase db,
    IDataProtectionProvider provider) =>
{
    var protector = provider.CreateProtector("PasswordReset");
    var user = await db.GetUserAsync(username);
    return protector.Protect(user.UserName);
});

app.MapGet("/end-password-reset", async (
    string username,
    string password,
    string hash ,
    DataBase db,
    IPasswordHasher<User> hasher,
    IDataProtectionProvider provider) =>
{
    var protector = provider.CreateProtector("PasswordReset");
    var hashUsername = protector.Unprotect(hash);

    if(hashUsername != username)
    {
        return "bad hash";
    }

    var user = await db.GetUserAsync(username);
    user.PasswordHash = hasher.HashPassword(user, password);
    await db.putAsync(user);

    return "Password reset";
});


app.Run();

public class UserHelper
{
    public static ClaimsPrincipal Convert(User user)
    {
        var claims = new List<Claim>()
        {
            new Claim("username", user.UserName)
        };

        claims.AddRange(user.Claims.Select(x => new Claim(x.Type, x.Value)));

        var identity = new ClaimsIdentity(claims , CookieAuthenticationDefaults.AuthenticationScheme);

        return new ClaimsPrincipal(identity);
    }
}