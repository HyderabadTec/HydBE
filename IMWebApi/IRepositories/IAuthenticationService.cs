using IMWebApi.Repositories;
using IMWebApi.Models;
using IMWebApi.Models.Authentication.SignUp;
using Microsoft.AspNetCore.Mvc;
using IMWebApi.Models.Authentication.Login;



namespace IMWebApi.Repositories.Interfaces.Authentication
{
    public interface IAuthenticationService
    {
        Task<IActionResult> Register(RegisterUser registerUser, string role);
        Task<IActionResult> Login(LoginModel loginModel);
        Task<IActionResult> LoginWithOTP(string code, string username);

    }
}
