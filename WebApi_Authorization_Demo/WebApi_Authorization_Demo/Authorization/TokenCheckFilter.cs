using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Formatting;
using System.Web;
using System.Web.Http;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;
using WebApi_Authorization_Demo.Models;

namespace WebApi_Authorization_Demo.Authorization
{
    public class TokenCheckFilter : ActionFilterAttribute
    {
        public override void OnActionExecuting(HttpActionContext actionContext)
        {
            base.OnActionExecuting(actionContext);
            if (actionContext.ActionDescriptor.GetCustomAttributes<AllowAnonymousAttribute>().Any())
            {
                return;
            }
            var hearderAuthorization = actionContext.Request.Headers.Authorization;
            if (hearderAuthorization == null || !hearderAuthorization.Scheme.Equals("Bearer", StringComparison.OrdinalIgnoreCase))
            {
                actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized);
                return;
            }

            string clientCode = hearderAuthorization.Parameter;
            Dictionary<string, object> parameter = actionContext.ActionArguments;
            if (parameter.Count==0)
            {
                return;
            }
            object username;
            if (parameter.TryGetValue("username", out username))
            {
                if (LocalStorage.Users.Any(u => u.AccessToken.Equals(clientCode, StringComparison.Ordinal) && u.Username.Equals(Convert.ToString(username), StringComparison.OrdinalIgnoreCase)))
                {
                    return;
                }
                else
                {
                    actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.OK, new { success = false, data = new { error = "Your account login another place" } });
                    return;
                }
            }
            username = parameter["model"];
            if (username!=null)
            {
                JObject model = JObject.FromObject(username); //用Json Object 代替转化所有的View
                string getUsername = (string)model.SelectToken("Username");
                if (LocalStorage.Users.Any(u => u.AccessToken.Equals(clientCode, StringComparison.Ordinal) && u.Username.Equals(getUsername, StringComparison.OrdinalIgnoreCase)))
                {
                    return;
                }
                else
                {
                    actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.OK, new { success = false, data = new { error = "Your account login another place" } });
                    return;
                }
            }

        }
    }
    public class TestFilter : AuthorizeAttribute
    {
        public override void OnAuthorization(HttpActionContext actionContext)
        {
            base.OnAuthorization(actionContext);
        }
    }
}