using AISecutity;
using AISecutity.Data;
using AISecutity.Detection;
using AISecutity.Middleware;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddOpenApi();

// === Database (SQLite) ===
builder.Services.AddDbContext<SecurityDbContext>(options =>
    options.UseSqlite("Data Source=security.db"));

// Register AI detection services
builder.Services.AddSingleton<IAiDetectionEngine, AiDetectionEngine>();
builder.Services.AddSingleton<ActivityManager>();
builder.Services.AddScoped<BanService>();
builder.Services.AddHttpClient<MlDetectionClient>();

// Register AI blocking middleware with options
builder.Services.AddAiBlocking(options =>
{
    options.MinEventsBeforeAnalysis = 5;
    options.BlockingThreshold = 0.75;
    options.ExcludedPaths = new List<string>
    {
        "/api/detection",
        "/api/ban",
        "/api/sdk",
        "/sdk",
        "/api/fingerprint",
        "/health",
        "/swagger",
        "/openapi"
    };
});

// CORS for Angular demo site + customer websites
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowDemoSite", policy =>
    {
        policy.WithOrigins("http://localhost:4200", "http://localhost:8080")
              .AllowAnyHeader()
              .AllowAnyMethod();
    });

    // SDK endpoints allow any origin (customer websites)
    options.AddPolicy("AllowSdk", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

var app = builder.Build();

// === Auto-create database on startup ===
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<SecurityDbContext>();
    db.Database.EnsureCreated();
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseCors("AllowDemoSite");

// Serve the SDK JavaScript tracker as a static file
app.UseStaticFiles(new StaticFileOptions
{
    FileProvider = new Microsoft.Extensions.FileProviders.PhysicalFileProvider(
        Path.Combine(builder.Environment.ContentRootPath, "SDK")),
    RequestPath = "/sdk"
});

// Server-side request fingerprinting — catches bots at network level
// even if they send spoofed telemetry
app.UseRequestFingerprinting();

// Rate limiting — block IPs that exceed 60 req/min
app.UseRateLimiting();

// AI agent blocking — place before auth and controllers
app.UseAiBlocking();

app.UseHttpsRedirection();
app.UseAuthorization();
app.MapControllers();

app.Run();
