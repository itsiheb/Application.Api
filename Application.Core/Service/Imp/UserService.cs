using Application.Core.Service.Itf;
using Application.Data.Dto;
using Application.Data.Model;
using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

// <Summary>
// in this UserService class we will be implementing all the methods from our IUserService Interface
// </summary>

namespace Application.Core.Service.Imp
{
    public class UserService : IUserService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IMapper _mapper;
        // <Summary>
        // this is the constructor of the UserService where we inject the mapper and the userManager for later use.
        // </summary>
        public UserService(UserManager<ApplicationUser> userManager, IMapper mapper)
        {
            _userManager = userManager;
            _mapper = mapper;
        }
        // <Summary> on this method we will get the user via it's username provided . </summary>
        public async Task<ApplicationUserDto?> GetUserByUsername(string? username)
        {
            var user = await _userManager.FindByNameAsync(username);
            if (user != null)
                return _mapper.Map<ApplicationUserDto>(user);
            return null;
        }
        // <Summary> on this method we will get the user via it's Email provided . </summary>
        public async Task<ApplicationUserDto?> GetUserByEmail(string? email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
                return _mapper.Map<ApplicationUserDto>(user);
            return null;
        }
        // <Summary> on this method we will get the information of all the users in our database thanks to the toListAsync method. </summary>
        public async Task<IEnumerable<ApplicationUserDto>?> GetAllUsers()
        {
            if (_userManager.Users != null)
            {
                List<ApplicationUser> users = await _userManager.Users.ToListAsync();
                IEnumerable<ApplicationUserDto>? usersDto = _mapper.Map<List<ApplicationUser>, IEnumerable<ApplicationUserDto>>(users);

                return usersDto;
            }
            return null;
        }
        // <Summary> on this method we will update our user by checking the fields </summary>
        public async Task<Response> UpdateUser(ApplicationUser request)
        {
            if (request != null)
            {
                var user = await _userManager.FindByIdAsync(request.Id);
                if (user != null)
                {
                    if (request.UserName != null)
                        user.UserName = request.UserName;
                    if (request.Email != null)
                        user.Email = request.Email;
                    if (request.PhoneNumber != null)
                        user.PhoneNumber = request.PhoneNumber;
                    if (request.Address != null)
                       user.Address = request.Address;
                    if (request.Country != null)
                        user.Country = request.Country;
                    await _userManager.UpdateAsync(user);
                    return new Response
                    {
                        Status = 200,
                        Message = "User updated successfully."
                    };
                }
                else
                {
                    return new Response
                    {
                        Status = 404,
                        Message = "User not found."
                    };
                }
            }

            return new Response
            {
                Status = 400,
                Message = "Bad request."
            };
        }
        // <Summary> on this method we will delete a certain user by the provided username . </summary>
        public async Task<Response> DeleteUser(string? username)
        {
            var user = await _userManager.FindByNameAsync(username);
            if (user != null)
            {
                await _userManager.DeleteAsync(user);
                return new Response
                {
                    Status = 200,
                    Message = "User deleted successfully."
                };
            }
            return new Response
            {
                Status = 400,
                Message = "Bad request."
            };
        }
    }
}