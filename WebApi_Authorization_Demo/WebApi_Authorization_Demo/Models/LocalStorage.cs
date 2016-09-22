using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebApi_Authorization_Demo.Models
{
    public static class LocalStorage
    {
        public static IList<User> Users { get; set; }
        static LocalStorage()
        {
            Users = new List<User>();
        }
    }

    public class User
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public DateTime IssuedUtc { get; set; }
        public DateTime ExpiresUtc { get; set; }
        public string RefreshTicket { get; set; }
    }
}