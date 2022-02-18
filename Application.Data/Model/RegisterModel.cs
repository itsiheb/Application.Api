using System.ComponentModel.DataAnnotations;

namespace Application.Data.Model
{
    public class RegisterModel
    {
        [Required(ErrorMessage = "User Name is required")]
        public string? UserName { get; set; }

        [EmailAddress]
        [Required(ErrorMessage = "Email is required")]
        public string? Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string? Password { get; set; }
        [Required(ErrorMessage = "First Name is required")]
        public string? FirstName { get; set; } 

        [Required(ErrorMessage = "Las Name is required")]
        public string? LastName { get; set; } 

        [Required(ErrorMessage = "Phone Number is required")]
        public string? PhoneNumber { get; set; } 
        [Required(ErrorMessage = "Country is required")]
        public string? Country { get; set; } 
        [Required(ErrorMessage = "Birth Date is required")]
        public DateTime? DateOfBirth { get; set; }

    }
}
