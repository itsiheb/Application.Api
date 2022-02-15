using Application.Data.Model;
using Microsoft.AspNetCore.Mvc;
using Application.Core.Service.Itf;
using Microsoft.AspNetCore.Authorization;

// <Summary>
// this is our AuthenticateController where we will be injecting our Services and use them to handle some cases and return the api response
// </summary>

namespace Application.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        private readonly IAuthenticateService _AuthenticateService;
        private readonly ITokenService _TokenService;

        // <Summary> 
        // here we will inject our IAuthenticateService and our ITokenService to our controller so we can use it later
        // </Summary>
        public AuthenticateController(
            IAuthenticateService authenticateService,
            ITokenService tokenService)
        {
            _AuthenticateService = authenticateService;
            _TokenService = tokenService;
        }

        // <Summary> 
        // this is the method we will call our log in method from our AuthenticateService while handling the exceptions via a try catch
        // </Summary>
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            try
            {
                var response = await _AuthenticateService.Login(model);
                return StatusCode(response.Status,response);
            }
            catch (ArgumentNullException e)
            {
                Console.WriteLine(e.Message);
                return BadRequest(e.Message);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return BadRequest(e.Message);
            }
        }

        // <Summary> 
        // this is the method we will call our Register method for the simple user from our AuthenticateService while handling the exceptions via a try catch
        // </Summary>
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            try
            {
                var response = await _AuthenticateService.Register(model); 
                return Ok(response);
            }
            catch (ArgumentNullException e)
            {
                Console.WriteLine(e.Message);
                return BadRequest(e.Message);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return BadRequest(e.Message);
            }
        }

        // <Summary> 
        // this is the method we will call our Register method for the admin from our AuthenticateService while handling the exceptions via a try catch
        // </Summary>
        [HttpPost]
        [Route("register-admin")]
        public async Task<IActionResult> RegisterAdmin([FromBody] RegisterModel model)
        {
            try
            {
                var response = await _AuthenticateService.RegisterAdmin(model);
                return Ok(response);
            }
            catch (ArgumentNullException e)
            {
                Console.WriteLine(e.Message);
                return BadRequest(e.Message);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return BadRequest(e.Message);
            }
        }

        // <Summary> 
        // this is the method we will call our Register method for the super admin from our AuthenticateService while handling the exceptions via a try catch
        // </Summary>
        [HttpPost]
        [Route("register-superadmin")]
        public async Task<IActionResult> RegisterSuperAdmin([FromBody] RegisterModel model)
        {
            try
            {
                var response = await _AuthenticateService.RegisterSuperAdmin(model);
                return Ok(response);
            }
            catch (ArgumentNullException e)
            {
                Console.WriteLine(e.Message);
                return BadRequest(e.Message);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return BadRequest(e.Message);
            }
        }

        // <Summary> 
        // this is the method we will call our refresh token method from our TokenService while handling the exceptions via a try catch
        // </Summary>
        [HttpPost]
        [Route("refresh-token")]
        public async Task<IActionResult> RefreshToken(TokenModel tokenModel) 
        {
            try
            {
                var response = await _TokenService.RefreshToken(tokenModel);
                return Ok(response);
            }
            catch (ArgumentNullException e)
            {
                Console.WriteLine(e.Message);
                return BadRequest(e.Message);
            }
        }

        // <Summary> 
        // this is the method we will call our revoke method from our TokenService while handling the exceptions via a try catch
        // </Summary>
        [Authorize]
        [HttpPost]
        [Route("revoke/{username}")]
        public async Task<IActionResult> Revoke(string username)
        {
            try
            {
                var response = await _TokenService.Revoke(username);
                return Ok(response);
            }
            catch (ArgumentNullException e)
            {
                Console.WriteLine(e.Message);
                return BadRequest(e.Message);
            }
        }

        // <Summary> 
        // this is the method we will call our revoke all method from our TokenService while handling the exceptions via a try catch
        // </Summary>
        [Authorize]
        [HttpPost]
        [Route("revoke-all")]
        public async Task<IActionResult> RevokeAll()
        {
            try
            {
                var response = await _TokenService.RevokeAll();
                return Ok(response);
            }
            catch (ArgumentNullException e)
            {
                Console.WriteLine(e.Message);
                return BadRequest(e.Message);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return BadRequest(e.Message);
            }
        }
    }
}
