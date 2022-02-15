using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Application.Core.Service.Itf;
using Application.Data.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace Application.Core.Service.Imp
{
    public class AuthenticateService : IAuthenticateService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly ITokenService _tokenService;

        public AuthenticateService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager,
            IConfiguration configuration, ITokenService tokenService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _tokenService = tokenService;
        }

        //Login Task
        public async Task<Response> Login(LoginModel model)
        {
            var x = _roleManager;
            var user = await _userManager.FindByNameAsync(model.Username);
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
                    Status = "200",
                    Message =
                        $"  token : {jwtAuthToken} \n RefreshToken : {refreshToken} \n Expires in : {token.ValidTo}"
                };
            }

            return new Response()
            {
                Status = "401",
                Message = "UnAuthorized"
            };
        }
        public async Task<Response> Register(RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return new Response 
                    { 
                        Status = "500", 
                        Message = "User already exists!" };

            ApplicationUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return new Response
                    { 
                        Status = "500", 
                        Message = "User creation failed! Please check user details and try again." };

            await _roleManager.CreateAsync(new IdentityRole(UserRoles.User));
            await _userManager.AddToRoleAsync(user, UserRoles.User);


            return new Response 
                { 
                    Status = "200", 
                    Message = "User created successfully!" };
        }

        public async Task<Response> RegisterAdmin(RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return new Response
                {
                    Status = "500", 
                    Message = "User already exists!"
                };

            ApplicationUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return new Response 
                    { Status = "Error", 
                        Message = "User creation failed! Please check user details and try again." };

            //if (!await _roleManager.RoleExistsAsync(UserRoles.SuperAdmin))
            //    await _roleManager.CreateAsync(new IdentityRole(UserRoles.SuperAdmin));
            if (!await _roleManager.RoleExistsAsync(UserRoles.Admin))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));
            if (!await _roleManager.RoleExistsAsync(UserRoles.User))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.User));
            //if (await _roleManager.RoleExistsAsync(UserRoles.SuperAdmin))
            //{
            //    await _userManager.AddToRoleAsync(user, UserRoles.SuperAdmin);
            //}
            if (await _roleManager.RoleExistsAsync(UserRoles.Admin))
            {
                await _userManager.AddToRoleAsync(user, UserRoles.Admin);
            }
            if (await _roleManager.RoleExistsAsync(UserRoles.Admin))
            {
                await _userManager.AddToRoleAsync(user, UserRoles.User);
            }
            return new Response
            {
                Status = "200", 
                Message = "User created successfully!"
            };
        }

        public async Task<Response> RegisterSuperAdmin(RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return new Response
                {
                    Status = "Error", 
                    Message = "User already exists!"
                };

            ApplicationUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return new Response
                {
                    Status = "Error", 
                    Message = "User creation failed! Please check user details and try again."
                };

            if (!await _roleManager.RoleExistsAsync("SuperAdmin"))
                await _roleManager.CreateAsync(new IdentityRole("SuperAdmin"));
            if (!await _roleManager.RoleExistsAsync("Admin"))
                await _roleManager.CreateAsync(new IdentityRole("Admin"));
            if (!await _roleManager.RoleExistsAsync("User"))
                await _roleManager.CreateAsync(new IdentityRole("User"));
            if (await _roleManager.RoleExistsAsync("SuperAdmin"))
            {
                await _userManager.AddToRoleAsync(user, "SuperAdmin");
            }
            if (await _roleManager.RoleExistsAsync("SuperAdmin"))
            {
                await _userManager.AddToRoleAsync(user, "Admin");
            }
            if (await _roleManager.RoleExistsAsync("SuperAdmin"))
            {
                await _userManager.AddToRoleAsync(user, "User");
            }
            return new Response
            {
                Status = "Success",
                Message = "User created successfully!"
            };
        }
    }
}
