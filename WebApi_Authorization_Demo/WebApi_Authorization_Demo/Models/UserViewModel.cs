using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebApi_Authorization_Demo.Models
{
    public class UserViewModel
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string RefreshToken { get; set; }
    }
}