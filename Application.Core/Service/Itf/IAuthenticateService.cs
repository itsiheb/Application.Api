using Application.Data.Model;
using Microsoft.AspNetCore.Mvc;

// <Summary> this is the IAuthenticateService Interface where we can find all the methods that will be implemented later in
// the AuthenticateService Class </summary>

namespace Application.Core.Service.Itf
{
    public interface IAuthenticateService
    {

        public Task<Response> Login([FromBody] LoginModel model);
        public Task<Response> Register([FromBody] RegisterModel model);
        public Task<Response> RegisterAdmin([FromBody] RegisterModel model);
        public Task<Response> RegisterSuperAdmin([FromBody] RegisterModel model);
    }
}
