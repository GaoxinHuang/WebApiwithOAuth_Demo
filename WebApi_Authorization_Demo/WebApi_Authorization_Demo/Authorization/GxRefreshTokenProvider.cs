using Microsoft.Owin.Security.Infrastructure;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using WebApi_Authorization_Demo.Models;

namespace WebApi_Authorization_Demo.Authorization
{
    public class GxRefreshTokenProvider : AuthenticationTokenProvider
    {
        //private static ConcurrentDictionary<string, string> _refreshTokens = new ConcurrentDictionary<string, string>();
        public async override Task CreateAsync(AuthenticationTokenCreateContext context)
        {
            
            string username = context.OwinContext.Get<string>("as:username");
            string password = context.OwinContext.Get<string>("as:password");
            string tokenValue = Guid.NewGuid().ToString("n");//全球唯一标识符,xxx-xx-xx-xx, n就是把"-"去掉
            var user = LocalStorage.Users.Where(u => u.Username.Equals(username, StringComparison.OrdinalIgnoreCase) && u.Password == password).FirstOrDefault();
            if (user == null)
            {
                return;
            }
            user.RefreshToken = tokenValue;
            user.IssuedUtc = DateTime.UtcNow;
            user.ExpiresUtc = DateTime.UtcNow.AddDays(60);
            context.Ticket.Properties.IssuedUtc = user.IssuedUtc;
            context.Ticket.Properties.ExpiresUtc = user.ExpiresUtc;
            user.RefreshTicket = context.SerializeTicket();
            context.SetToken(tokenValue);
            //await CreateAsync(context); //不能加,不然就报错
        }

        public async override Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {
            var user = LocalStorage.Users.Where(u => u.RefreshToken == context.Token).FirstOrDefault();
            if (user != null)
            {
                context.DeserializeTicket(user.RefreshTicket);
            }
            //await ReceiveAsync(context);//不能加,不然就报错
        }
    }
}