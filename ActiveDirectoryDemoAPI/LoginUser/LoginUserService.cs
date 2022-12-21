using ActiveDirectoryDemoAPI.ConfigurationModels;
using ActiveDirectoryDemoAPI.Data;
using ActiveDirectoryDemoAPI.Dtos;
using ActiveDirectoryDemoAPI.Entities;
using ActiveDirectoryDemoAPI.Helpers;
using ActiveDirectoryDemoAPI.Utils.Logger;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace ActiveDirectoryDemoAPI.LoginUser
{
    public class LoginUserService : ILoginUserService
    {
        private readonly IConfiguration _configuration;
        private readonly UserManager<User> _userManager;
        private readonly JwtConfiguration _jwtConfiguration;
        private readonly ILoggerManager _logger;
        private readonly AppDbContext _context;
        public LoginUserService(
            IConfiguration configuration, 
            UserManager<User> userManager, 
            ILoggerManager logger,
            AppDbContext context
            )
        {
            _configuration = configuration;
            _userManager = userManager;
            _jwtConfiguration = new JwtConfiguration();
            _configuration.Bind(_jwtConfiguration.Section, _jwtConfiguration);
            _logger = logger;
            _context = context;
        }
        public async Task<SuccessResponse<AuthDto>> Login(UserLoginDto model)
        {
            var email = model.Email.Trim().ToLower();

            var user = await _userManager.FindByEmailAsync(email);
            if (user is null)
                throw new RestException(HttpStatusCode.NotFound, "Wrong Email");

            var authenticated = await ValidateUser(user, model.Password);
            if (!authenticated)
                throw new RestException(HttpStatusCode.Unauthorized, "Wrong Email or Password");

            //check if user is disabled or active or pending
            //CheckUserStatus(user);

            user.LastLogin = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            var userActivity = new UserActivity
            {
                EventType = "User Login",
                UserId = user.Id,
                ObjectClass = "USER",
                Details = "Logged in",
                ObjectId = user.Id
            };
           

            //await _repository.UserActivity.AddAsync(userActivity);
            //await _repository.SaveChangesAsync();

            var token = await CreateToken(user, true);

            //extract payload
            /*
            var jwtSettings = configuration.GetSection("JwtSettings");
            var secret = jwtSettings.GetSection("Secret").Value; ;
            var key = Encoding.ASCII.GetBytes(secret);
            var handler = new JwtSecurityTokenHandler();
            var validations = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false
            };
            var claims = handler.ValidateToken(token.AccessToken, validations, out var tokenSecure);
           
            */

            return new SuccessResponse<AuthDto>
            {
                Data = token
            };
        }
        private async Task<bool> ValidateUser(User user, string password)
        {
            var result = (user != null && await _userManager.CheckPasswordAsync(user, password));
            if (!result)
                _logger.LogWarn($"{nameof(ValidateUser)}: Authentication failed, wrong email or password");

            if (user != null && !user.Verified)
            {
                _logger.LogWarn($"{nameof(ValidateUser)}: Authentication failed, User is not verified");
                return false;
            }
            return result;
        }
        private async Task<AuthDto> CreateToken(User user, bool populateExp)
        {
            var signingCredentials = GetSigningCredentials();
            var claims = await GetClaims(user);
            var tokenOptions = GenerateTokenOptions(signingCredentials, claims);
            var refreshToken = GenerateRefreshToken();
            if (populateExp)
                user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
            await _userManager.UpdateAsync(user);
            var accessToken = new JwtSecurityTokenHandler().WriteToken(tokenOptions);
            return new AuthDto
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                ExpiresIn = user.RefreshTokenExpiryTime
            };

        }
        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }
        private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            //var jwtSettins = _configuration.GetSection("JwtSettings");
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtConfiguration.Secret)),
                ValidateLifetime = false,
                ValidAudience = _jwtConfiguration.ValidAudience,
                ValidIssuer = _jwtConfiguration.ValidIssuer
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,
                   StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;
        }
        private SigningCredentials GetSigningCredentials()
        {
            var jwtSecret = _configuration.GetSection("JwtSettings")["secret"];
            var key = Encoding.UTF8.GetBytes(jwtSecret);
            var secret = new SymmetricSecurityKey(key);
            return new SigningCredentials(secret, SecurityAlgorithms.HmacSha256);
        }
        private async Task<List<Claim>> GetClaims(User user)
        {
            var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user!.Email),
            new Claim("Email", user.Email),
            new Claim("UserId", user.Id.ToString()),
            new Claim("FirstName", user.FirstName),
            new Claim("LastName", user.LastName),
        };

        var roles = await _userManager.GetRolesAsync(user);
        var userRoles = new List<string>();
        foreach (var role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
            userRoles.Add(role);
        }
        claims.Add(new Claim("RolesStr", string.Join(",", userRoles)));

        return claims;
        }
        private JwtSecurityToken GenerateTokenOptions(SigningCredentials signingCredentials, List<Claim> claims)
        {
            //var jwtSettings = _configuration.GetSection("JwtSettings");
            var tokenOptions = new JwtSecurityToken(
                issuer: _jwtConfiguration.ValidIssuer,
                audience: _jwtConfiguration.ValidAudience,
                claims: claims,
                expires: DateTime.Now.AddDays(Convert.ToDouble(_jwtConfiguration.ExpiresIn)),
                signingCredentials: signingCredentials);
            return tokenOptions;
        }
    }
}
