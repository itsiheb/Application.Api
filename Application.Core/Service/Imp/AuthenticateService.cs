using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Application.Core.Service.Itf;
using Application.Data.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
// <Summary>
// in this AuthenticateService class we will be implementing all the methods from our IAuthenticateService Interface
// </summary>
namespace Application.Core.Service.Imp
{
    public class AuthenticateService : IAuthenticateService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly ITokenService _tokenService;
        // <Summary> this is the constructor of the AuthenticateService where we will inject
        // the userManager , the roleManager , the IConfigurationfor and our own TokenService later use.
        // </summary>
        public AuthenticateService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager,
            IConfiguration configuration, ITokenService tokenService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _tokenService = tokenService;
        }

        // <Summary>
        // in this method will manage the Log In by checking the validity of the requests and then apply the token to the logged in user
        // </summary>
        public async Task<Response> Login(LoginModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var userRoles = await _userManager.GetRolesAsync(user);

                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }

                var token = _tokenService.CreateToken(authClaims);
                var refreshToken = TokenService.GenerateRefreshToken();

                _ = int.TryParse(_configuration["JWT:RefreshTokenValidityInDays"], out int refreshTokenValidityInDays);

                user.RefreshToken = refreshToken;
                user.RefreshTokenExpiryTime = DateTime.Now.AddDays(refreshTokenValidityInDays).ToUniversalTime();
                var jwtAuthToken = new JwtSecurityTokenHandler().WriteToken(token);
                await _userManager.UpdateAsync(user);
                return new Response
                {
                    Status = 200,
                    Message =
                        $"  token : {jwtAuthToken} \n RefreshToken : {refreshToken} \n Expires in : {token.ValidTo}"
                };
            }
            return new Response()
            {
                Status = 401,
                Message = "please verify your email and password"
            };
        }

        // <Summary>
        // in this method will manage the Register for the simple user by checking the validity of the requests and create the user 
        // </summary>
        public async Task<Response> Register([FromBody] RegisterModel model)
        {
            var userEmailExists = await _userManager.FindByEmailAsync(model.Email);
            if (userEmailExists != null)
                return new Response
                {
                    Status = 500,
                    Message = "this email already exists!"
                };

            ApplicationUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                PasswordHash = model.Password,
                FirstName = model.FirstName,
                LastName = model.LastName,
                PhoneNumber = model.PhoneNumber,
                Country = model.Country,
                DateOfBirth = model.DateOfBirth,
                UserName = model.UserName
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return new Response
                {
                    Status = 400,
                    Message = "verify password requirements"
                };

            await _roleManager.CreateAsync(new IdentityRole(UserRoles.User));
            await _userManager.AddToRoleAsync(user, UserRoles.User);


            return new Response
            {
                Status = 200,
                Message = "User created successfully!"
            };
        }
        // <Summary>
        // in this method will manage the Register for the admin by checking the validity of the requests and then create the user
        // </summary>
        public async Task<Response> RegisterAdmin(RegisterModel model)
        {
            var userExists = await _userManager.FindByEmailAsync(model.Email);
            if (userExists != null)
                return new Response
                {
                    Status = 500,
                    Message = "User already exists!"
                };

            ApplicationUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                PasswordHash = model.Password,
                FirstName = model.FirstName,
                LastName = model.LastName,
                PhoneNumber = model.PhoneNumber,
                Country = model.Country,
                DateOfBirth = model.DateOfBirth,
                UserName = model.UserName
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return new Response
                {
                    Status = 400,
                    Message = "the password must have one alphanumeric ,Upper and LowerCase Alphabet and a number"
                };

            await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));
            await _userManager.AddToRoleAsync(user, UserRoles.Admin);

            return new Response
            {
                Status = 200,
                Message = "User created successfully!"
            };
        }

        // <Summary>
        // in this method will manage the Register for the Super admin by checking the validity of the requests and then create the user
        // </summary>
        public async Task<Response> RegisterSuperAdmin(RegisterModel model)
        {
            var userExists = await _userManager.FindByEmailAsync(model.Email);
            if (userExists != null)
                return new Response
                {
                    Status = 400,
                    Message = "User already exists!"
                };

            ApplicationUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                PasswordHash = model.Password,
                FirstName = model.FirstName,
                LastName = model.LastName,
                PhoneNumber = model.PhoneNumber,
                Country = model.Country,
                DateOfBirth = model.DateOfBirth,
                UserName = model.UserName
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return new Response
                {
                    Status = 402,
                    Message = "the password must have one alphanumeric ,Upper and LowerCase Alphabet and a number"
                };

            await _roleManager.CreateAsync(new IdentityRole(UserRoles.SuperAdmin));
            await _userManager.AddToRoleAsync(user, UserRoles.SuperAdmin);

            return new Response
            {
                Status = 400,
                Message = "User created successfully!"
            };
        }
    }
}
