using ActiveDirectoryDemoAPI.Data;
using ActiveDirectoryDemoAPI.Extensions;
using ActiveDirectoryDemoAPI.LoginUser;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.ConfigureCors();
builder.Services.ConfigureSwagger();
builder.Services.AddEndpointsApiExplorer();
builder.Services.ConfigureLoggerService();
builder.Services.ConfigureLoginService();
builder.Services.AddSwaggerGen();
builder.Services.AddAuthentication();
builder.Services.ConfigureIdentity();
builder.Services.ConfigureJWT(builder.Configuration);
builder.Services.ConfigureSqlContext(builder.Configuration);
builder.Services.ConfigureLoginService();

var app = builder.Build();

//app.SeedRoleData().Wait();
//app.SeedUserData().Wait();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors("CorsPolicy");
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
