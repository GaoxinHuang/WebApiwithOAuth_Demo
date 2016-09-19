using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Threading.Tasks;
using WebApi_Authorization_Demo.Models;
using System.Security.Claims;
using Microsoft.Owin.Security;

namespace WebApi_Authorization_Demo.Authorization
{
    public class GxAuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        public async override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            string clientId = String.Empty;
            string clientSecret = String.Empty;

            if (!context.TryGetBasicCredentials(out clientId, out clientSecret))
            {
                return;
            }

            if (!LocalStorage.Users.Any(u => u.Username.Equals(clientId, StringComparison.OrdinalIgnoreCase)) || clientSecret != "Godfrey")
            {
                return;
            }
            string username = context.Parameters.Get("username");
            string password = context.Parameters.Get("password");
            context.OwinContext.Set<string>("as:username", username);
            context.OwinContext.Set<string>("as:password", password);
            context.Validated(clientId);
            await base.ValidateClientAuthentication(context);
        }

        public async override Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            //string username = context.UserName; 
            //string password = context.Password;
            string username = context.OwinContext.Get<string>("as:username");
            string password = context.OwinContext.Get<string>("as:password"); 
            //验证账号密码,可以不要,因为在create里有写
            if (!LocalStorage.Users.Any(u => u.Username.Equals(username, StringComparison.OrdinalIgnoreCase) && u.Password == password))
            {
                return;
            }
            var oAuthIdentity = new ClaimsIdentity(context.Options.AuthenticationType);
            
            oAuthIdentity.AddClaim(new Claim(ClaimTypes.Name, username));
            var props = new AuthenticationProperties(new Dictionary<string, string>
                {
                    { "as:client_id", context.ClientId }
                });
            var ticket = new AuthenticationTicket(oAuthIdentity, props);
            context.Validated(ticket);
            await base.GrantResourceOwnerCredentials(context);
        }

        public async override Task GrantRefreshToken(OAuthGrantRefreshTokenContext context)
        {
            var originalClient = context.Ticket.Properties.Dictionary["as:client_id"];
            var currentClient = context.ClientId;

            if (originalClient != currentClient)
            {
                context.Rejected();
                return;
            }
            var newId = new ClaimsIdentity(context.Ticket.Identity);
            var newClaim = newId.Claims.Where(c => c.Value == context.ClientId).FirstOrDefault();

            if (newClaim != null)
            {
                newId.RemoveClaim(newClaim);
            }
            newId.AddClaim(new Claim("newClaim", "refreshToken"));
            newId.AddClaim(new Claim(ClaimTypes.Name, context.ClientId));
            var newTicket = new AuthenticationTicket(newId, context.Ticket.Properties);
            context.Validated(newTicket);
            await base.GrantRefreshToken(context);
        }

        //All Information display
        //public override Task TokenEndpoint(OAuthTokenEndpointContext context)
        //{
        //    foreach (KeyValuePair<string, string> property in context.Properties.Dictionary)
        //    {
        //        context.AdditionalResponseParameters.Add(property.Key, property.Value);
        //    }
        //    return Task.FromResult<object>(null);
        //}

        /// <summary>
        /// grant_type=client_credentials 
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override Task GrantClientCredentials(OAuthGrantClientCredentialsContext context)
        {
            #region Old Token

            var oAuthIdentity = new ClaimsIdentity(context.Options.AuthenticationType);
            oAuthIdentity.AddClaim(new Claim(ClaimTypes.Name, context.ClientId));
            var props = new AuthenticationProperties(new Dictionary<string, string>
                {
                    { "as:client_id", context.ClientId }
                });
            var ticket = new AuthenticationTicket(oAuthIdentity, props);
            context.Validated(ticket);

            return base.GrantClientCredentials(context);
            #endregion
        }
    }
}