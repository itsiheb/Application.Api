using Application.Data.Model;
using Microsoft.AspNetCore.Mvc;
using System.Web.Http;

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
