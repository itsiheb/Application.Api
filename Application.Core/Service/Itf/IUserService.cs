using Application.Data.Dto;
using Application.Data.Model;

// <Summary>
// this is the IUserService Interface where we can find all the methods that will be implemented later in the UserService Class
// </summary>
namespace Application.Core.Service.Itf
{
    public interface IUserService
    {
        public Task<ApplicationUserDto?> GetUserByUsername(string? username);
        public Task<ApplicationUserDto?> GetUserByEmail(string? email);
        public Task<IEnumerable<ApplicationUserDto>?> GetAllUsers();
        public Task<Response> UpdateUser(ApplicationUser? request);
        public Task<Response> DeleteUser(string? username);
    }
}
