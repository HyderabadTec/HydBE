using System.ComponentModel.DataAnnotations;

namespace IMWebApi.Models.Authentication.SignUp
{
    public class RegisterUser
    {
        [Required(ErrorMessage = "User Name is required")]
        public string? Username { get; set; }

        //[EmailAddress]
        [Required(ErrorMessage = "Email is required")]
        public string? EmailAddress { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string? Password { get; set; }

        [Required(ErrorMessage = "PhoneNumber is required")]
        public string? Mobileno { get; set; }

        //[Required(ErrorMessage = "First Name is required")]
        //public string? FirstName { get; set; }

        //[Required(ErrorMessage = "Last Name is required")]
        //public string? LastName { get; set; }
    }
}
