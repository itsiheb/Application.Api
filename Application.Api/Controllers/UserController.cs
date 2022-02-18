using Application.Core.Service.Itf;
using Application.Data.Dto;
using Application.Data.Model;
using Microsoft.AspNetCore.Mvc;

// <Summary>
// this is our userController where we will be injecting our Services and use them to handle some cases and return the api response
// </summary>

namespace Application.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;

        // <Summary> 
        // here we will inject our UserService to our controller so we can use it later
        // </Summary>
        public UserController(IUserService userService)
        {
            _userService = userService;
        }

        // <Summary> 
        // this is the method used to get all the users being called from our UserService while handling the exceptions via a try catch
        // </Summary>

        [HttpGet]
        [Route("fetchAllUsers")]
        public async Task<ActionResult<IEnumerable<ApplicationUserDto>>?> GetAllUsers()
        {
            try
            {
                var response = await _userService.GetAllUsers();
                return Ok(response);
            }
            catch (NullReferenceException e)
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
        // this is the method used to get a certain user by his username  being called from our UserService while handling the exceptions via a try catch
        // </Summary>

        [HttpGet]
        [Route("fetchByUsername")]
        public async Task<ActionResult<ApplicationUserDto?>> GetUserByUsername(string? username)
        {
            try
            {
                var response = await _userService.GetUserByUsername(username);
                if (response == null) return NotFound("User not found.");
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
        // this is the method used to get a certain user by his email being called from our UserService while handling the exceptions via a try catch
        // </Summary>

        [HttpGet]
        [Route("fetchByEmail")]
        public async Task<ActionResult<ApplicationUserDto?>> GetUserByEmail(string? email)
        {
            try
            {
                var response = await _userService.GetUserByEmail(email);
                if (response == null) return NotFound("User not found.");
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
        // this is the method used to update the fields of a user being called from our UserService while handling the exceptions via a try catch
        // </Summary>

        [HttpPut]
        [Route("updateUser")]
        public async Task<IActionResult> PutUser(ApplicationUser? request)
        {
            try
            {
                var response = await _userService.UpdateUser(request);
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
        // this is the method used to delete a user being called from our UserService while handling the exceptions via a try catch
        // </Summary>

        [HttpDelete]
        [Route("deleteUser")]
        public async Task<IActionResult> DeleteUser(string? username)
        {
            try
            {
                var response = await _userService.DeleteUser(username);
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
