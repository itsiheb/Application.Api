using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Application.Data.Model;

// <Summary>
// this is the ITokenService Interface where we can find all the methods that will be implemented later
// in the TokenService Class
// </summary>

namespace Application.Core.Service.Itf
{
    public interface ITokenService
    {
        public Task<Response> RefreshToken(TokenModel tokenModel);
        public Task<Response> Revoke(string username);
        public Task<Response> RevokeAll();
        public JwtSecurityToken CreateToken(List<Claim> authClaims);
        public ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token);
    }
}
