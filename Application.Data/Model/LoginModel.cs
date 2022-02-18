﻿using System.ComponentModel.DataAnnotations;

namespace Application.Data.Model
{
    public class LoginModel
    {
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress]
        public string? Email { get; set; } 

        [Required(ErrorMessage = "Password is required")]
        public string? Password { get; set; }
    }
}
