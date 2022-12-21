using ActiveDirectoryDemoAPI.Dtos;
using ActiveDirectoryDemoAPI.Helpers;
using ActiveDirectoryDemoAPI.LoginUser;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace ActiveDirectoryDemoAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly ILoginUserService _loginService;
        public LoginController(ILoginUserService LoginUserService)
        {
            _loginService = LoginUserService;
        }

        /// <summary>
        /// Logs in user with email and password
        /// </summary>
        /// <param name="model"></param>
        /// <returns>Jwt Token</returns>
        [HttpPost("login")]
        //[Consumes(MediaTypeNames.Application.Json)]
        [ProducesResponseType(typeof(SuccessResponse<AuthDto>), 200)]
        public async Task<IActionResult> Authenticate([FromBody] UserLoginDto model)
        {
            var response = await _loginService.Login(model);
            return Ok(response);
        }
    }
}
