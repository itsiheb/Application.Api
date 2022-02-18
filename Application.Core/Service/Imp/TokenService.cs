using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Application.Core.Service.Itf;
using Application.Data.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

// <Summary>
// in this TokenService class we will be implementing all the methods from our ITokenService Interface
// </summary>
namespace Application.Core.Service.Imp
{ 
    public class TokenService : ITokenService
    {
        private readonly IConfiguration _configuration;
        private readonly UserManager<ApplicationUser> _userManager;
        // <Summary>
        // this is the constructor of the TokenService where we inject the IConfiguration and the mapper userManager for later use.
        // </summary>
        public TokenService(IConfiguration configuration, UserManager<ApplicationUser> userManager)
        {
            _configuration = configuration;
            _userManager = userManager;
        }

        // <Summary> in this method will be refreshing the token of the logged in user </summary>
        public async Task<Response> RefreshToken(TokenModel tokenModel)
        {
            if (tokenModel is null)
            {
                return new Response
                {
                    Status = 402,
                    Message = "token is null "
                };
            }

            string? accessToken = tokenModel.AccessToken;
            string? refreshToken = tokenModel.RefreshToken;

            var principal = GetPrincipalFromExpiredToken(accessToken);
            if (principal == null)
            {
                return new Response
                {
                    Status = 401,
                    Message = "Invalid access token or refresh token"
                };
            }

            string username = principal.Identity.Name;
            var user = await _userManager.FindByNameAsync(username);

            if (user == null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
            {
                return new Response
                {
                    Status = 400,
                    Message = "Invalid access token or refresh token"
                };
            }

            var newAccessToken = CreateToken(principal.Claims.ToList());
            var newRefreshToken = GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            await _userManager.UpdateAsync(user);

            accessToken = new JwtSecurityTokenHandler().WriteToken(newAccessToken);
            refreshToken = newRefreshToken;

            return new Response
            {
                Status = 400,
                Message = $" accessToken {accessToken} \n"
            };
        }

        // <Summary> in this method will be generating a refreshed token with a random number generator </summary>
        public static string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        // <Summary> in this method will be revoking the token with all its claims from certain user  </summary>
        public async Task<Response> Revoke(string username)
        {
            var user = await _userManager.FindByNameAsync(username);
            if (user == null)
                return new Response
                {
                    Status = 200,
                    Message = "Invalid user name"
                };

            user.RefreshToken = null;
            await _userManager.UpdateAsync(user);

                return new Response
                {
                    Status = 200,
                    Message = "success"
                };
        }

        // <Summary> in this method will be revoking the token with all its claims from all the users this time </summary>
        public async Task<Response> RevokeAll()
        {
            var users = _userManager.Users.ToList();
            foreach (var user in users)
            {
                user.RefreshToken = null;
                await _userManager.UpdateAsync(user);
            }

            return new Response
            {
                Status = 200,
                Message = "revoked successfully"
            };
        }

        // <Summary> in this method will be revoking the token with all its claims from certain user  </summary>
        public JwtSecurityToken CreateToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            _ = int.TryParse(_configuration["JWT:TokenValidityInMinutes"], out int tokenValidityInMinutes);

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddMinutes(tokenValidityInMinutes),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );

            return token;
        }

        // <Summary> this is the method that will be used in the refresh token to identify the user that will get the refreshed token  </summary>
        public ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"])),
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal =
                tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            if (securityToken is not JwtSecurityToken jwtSecurityToken ||
                !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,
                    StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;

        }
    }
}
