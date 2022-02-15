using AutoMapper;

namespace Application.Data.Dto
{
    public class ApplicationUserDto
    {
        public string? Username { get; set; }
        public string? Email { get; set; }
        public string? PhoneNumber { get; set; }
        public string? Address { get; set; }
        public string? FirstName { get; set; } 
        public string? LastName { get; set; } 
        public DateTime? DateOfBirth { get; set; }
        public string? Country { get; set; }
    }
}
