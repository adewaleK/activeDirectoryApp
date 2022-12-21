using ActiveDirectoryDemoAPI.Dtos;
using ActiveDirectoryDemoAPI.Helpers;

namespace ActiveDirectoryDemoAPI.LoginUser
{
    public interface ILoginUserService
    {
        Task<SuccessResponse<AuthDto>> Login(UserLoginDto model);
    }
}
