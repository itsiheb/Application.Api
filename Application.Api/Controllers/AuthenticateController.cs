using Application.Data.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Application.Core.Service.Itf;

namespace Application.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        private IAuthenticateService _AuthenticateService;
        private ITokenService _TokenService;
        public AuthenticateController(
            IAuthenticateService authenticateService,
            ITokenService tokenService)
        {
            _AuthenticateService = authenticateService;
            _TokenService = tokenService;
        }
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            
            return null;
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            return null;
        }

        [HttpPost]
        [Route("register-admin")]
        public async Task<IActionResult> RegisterAdmin([FromBody] RegisterModel model)
        {
            return null;
        }

        [HttpPost]
        [Route("refresh-token")]
        public async Task<IActionResult> RefreshToken(TokenModel tokenModel) 
        {
            return null;
        }

        [Authorize]
        [HttpPost]
        [Route("revoke/{username}")]
        public async Task<IActionResult> Revoke(string username)
        {
            return null;
        }

        [Authorize]
        [HttpPost]
        [Route("revoke-all")]
        public async Task<IActionResult> RevokeAll()
        {
            return null;
        }

        private JwtSecurityToken CreateToken(List<Claim> authClaims)
        {
            return null;
        }
        private ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token)
        {
            return null;
        }
        [HttpPost]
        [Route("register-superadmin")]
        public async Task<IActionResult> RegisterSuperAdmin([FromBody] RegisterModel model)
        {
            return null;
        }
    }
}
