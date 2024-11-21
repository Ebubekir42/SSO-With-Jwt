using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Servisleri ekleme
builder.Services.AddControllersWithViews();

// JWT ayarlarý
var key = "SuperSecretKey@123SuperSecretKey@123SuperSecretKey@123"; // Üretim ortamýnda güçlü bir anahtar kullanýn
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login"; // Login endpoint
        options.LogoutPath = "/Account/LogOff"; // LogOut endpoint
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // HTTPS zorunlu
        options.Cookie.SameSite = SameSiteMode.None; // Subdomain'ler arasý paylaþým için gerekli
        options.Cookie.Domain = "localhost"; // Domain ayarý
    });

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowClientApp", policy =>
    {
        policy.WithOrigins("https://localhost:5075") // ClientApp URL'si
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials(); // Çerez paylaþýmýný etkinleþtir
    });
});

// Uygulama oluþturma
var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

// Middleware sýrasý
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseCors("AllowClientApp");
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
