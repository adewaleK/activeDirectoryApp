using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using System;
using System.Text;
using ActiveDirectoryDemoAPI.Entities;
using ActiveDirectoryDemoAPI.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using ActiveDirectoryDemoAPI.Utils.Logger;
using ActiveDirectoryDemoAPI.LoginUser;
using Microsoft.OpenApi.Models;

namespace ActiveDirectoryDemoAPI.Extensions
{
    public static class ServiceExtensions
    {
        public static void ConfigureCors(this IServiceCollection serviceCollection) =>
        serviceCollection.AddCors(options =>
        {
            options.AddPolicy("CorsPolicy", builder =>
                builder.AllowAnyOrigin()
                    .AllowAnyMethod()
                    .AllowAnyHeader()
                    .WithExposedHeaders("X-Pagination"));
        });
        public static void ConfigureSwagger(this IServiceCollection services)
        {
            services.AddSwaggerGen(s =>
            {
                s.SwaggerDoc("v1", new OpenApiInfo
                {
                    Title = "AD API",
                    Version = "v1",
                    Description = "API Template",
                    TermsOfService = new Uri("https://prunedge.com/terms"),
                    Contact = new OpenApiContact
                    {
                        Name = "Daniel Ale",
                        Email = "developer@prunedge.com",
                        Url = new Uri("https://prunedge.com/danielale")
                    },
                    License = new OpenApiLicense
                    {
                        Name = "Prunedge API LICX",
                        Url = new Uri("https://prunedge.com/developer-licence")
                    }
                });
                //s.SwaggerDoc("v2", new OpenApiInfo { Title = "Prunedge Web API2", Version = "v2" });

                //var xmlFile = $"{typeof(Presentation.AssemblyReference).Assembly.GetName().Name}.xml";
                //var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
                // s.IncludeXmlComments(xmlPath);

                s.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    In = ParameterLocation.Header,
                    Description = "Add JWT with Bearer",
                    Name = "Authorization",
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = "Bearer"
                });

                s.AddSecurityRequirement(new OpenApiSecurityRequirement()
            {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "Bearer"
                        },
                        Name = "Bearer"
                    },
                    new List<string>()
                }
            });
            });
        }
        public static void ConfigureIdentity(this IServiceCollection services)
        {
            var builder = services.AddIdentity<User, Role>(opt =>
            {
                opt.Password.RequireDigit = true;
                opt.Password.RequireLowercase = true;
                opt.Password.RequireUppercase = true;
                opt.Password.RequireNonAlphanumeric = false;
                opt.Password.RequiredLength = 8;
                opt.User.RequireUniqueEmail = true;
            })
                .AddEntityFrameworkStores<AppDbContext>()
                .AddDefaultTokenProviders();
        }
        public static void ConfigureLoggerService(this IServiceCollection serviceCollection) =>
        serviceCollection.AddSingleton<ILoggerManager, LoggerManager>();
        public static void ConfigureJWT(this IServiceCollection services, IConfiguration configuration)
        {

            var jwtSettings = configuration.GetSection("JwtSettings");
            var jwtUserSecret = jwtSettings.GetSection("Secret").Value;

            services.AddAuthentication(opt =>
            {
                opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                opt.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = jwtSettings.GetSection("ValidIssuer").Value,
                    ValidAudience = jwtSettings.GetSection("ValidAudience").Value,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtUserSecret))
                };
            });
        }
        public static void ConfigureSqlContext(this IServiceCollection serviceCollection, IConfiguration configuration) =>
        serviceCollection.AddDbContext<AppDbContext>(
            opts =>
            {
                opts.UseSqlServer(configuration.GetConnectionString("DefaultConnection"));
            });
        public static void ConfigureLoginService(this IServiceCollection serviceCollection) =>
        serviceCollection.AddScoped<ILoginUserService, LoginUserService>();
    }
}
