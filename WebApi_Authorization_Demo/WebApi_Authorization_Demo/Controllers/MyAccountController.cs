using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Cors;
using System.Web.Http.Results;
using WebApi_Authorization_Demo.Models;

namespace WebApi_Authorization_Demo.Controllers
{
    [EnableCors(origins: "http://oauthoriztion.azurewebsites.net", headers: "*", methods: "*")]
    public class MyAccountController : ApiController
    {

        [HttpPost]

        public async Task<IHttpActionResult> Register(UserViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return Ok(new { success = false, data = new { error = "incorrect input" } });
            }
            try
            {
                var hearderAuthorization = Request.Headers.Authorization;
                if (!hearderAuthorization.Scheme.Equals("Basic", StringComparison.OrdinalIgnoreCase))
                {
                    return Ok(new { success = false, data = new { error = "invalid_client" } });
                }
                if (LocalStorage.Users.Any(u => u.Username.Equals(model.Username, StringComparison.OrdinalIgnoreCase)))
                {
                    return Ok(new { success = false, data = new { error = "the username exists" } });
                }
                User newUser = new User
                {
                    Username = model.Username,
                    Password = model.Password
                };
                LocalStorage.Users.Add(newUser);

                string clientCode = hearderAuthorization.Parameter;
                JObject resultData = await SetToken(newUser, clientCode, "password");
                if ((Boolean)resultData.SelectToken("success"))
                {
                    return Ok(resultData);
                }
                else
                {
                    LocalStorage.Users.Remove(newUser);
                    return Ok(resultData);
                }
            }catch(Exception e)
            {
                return Ok(new { message=e.Message,error=e.InnerException });
            }
        }
        [HttpPost]
        public async Task<IHttpActionResult> Login(UserViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return Ok(new { success = false, data = new { error = "incorrect input" } });
            }

            var hearderAuthorization = Request.Headers.Authorization;
            if (!hearderAuthorization.Scheme.Equals("Basic", StringComparison.OrdinalIgnoreCase))
            {
                return Ok(new { success = false, data = new { error = "invalid_client" } });
            }
            User user = LocalStorage.Users.Where(u => u.Username.Equals(model.Username, StringComparison.OrdinalIgnoreCase) && u.Password == model.Password).FirstOrDefault();
            if (user == null)
            {
                return Ok(new { success = false, data = new { error = "incorrect username or password" } });
            }
            string clientCode = hearderAuthorization.Parameter;
            JObject resultData = await SetToken(user, clientCode, "password");
            if ((Boolean)resultData.SelectToken("success"))
            {
                return Ok(resultData);
            }
            else
            {
                return Ok(resultData);
            }
        }

        [HttpPost]
        public async Task<IHttpActionResult> RefreshToken(UserViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return Ok(new { success = false, data = new { error = "incorrect input" } });
            }

            var hearderAuthorization = Request.Headers.Authorization;
            if (!hearderAuthorization.Scheme.Equals("Basic", StringComparison.OrdinalIgnoreCase))
            {
                return Ok(new { success = false, data = new { error = "invalid_client" } });
            }
            User user = LocalStorage.Users.Where(u => u.Username.Equals(model.Username, StringComparison.OrdinalIgnoreCase) && u.Password == model.Password && u.RefreshToken == model.RefreshToken).FirstOrDefault();
            if (user == null)
            {
                return Ok(new { success = false, data = new { error = "incorrect username or password or refresh token" } });
            }
            string clientCode = hearderAuthorization.Parameter;
            JObject resultData = await SetToken(user, clientCode, "refresh_token");
            if ((Boolean)resultData.SelectToken("success"))
            {
                return Ok(resultData);
            }
            else
            {
                return Ok(resultData);
            }
        }


        private async Task<JObject> SetToken(User user, string clientCode, string grantType)
        {
            using (HttpClient httpClient = new HttpClient())
            {
                httpClient.BaseAddress = new Uri("http://localhost:10995");
                httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
                    "Basic", clientCode);
                //httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
                //"Basic", Convert.ToBase64String(Encoding.ASCII.GetBytes(clientCode)));

                var requestParams = new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>("grant_type", grantType),
                    new KeyValuePair<string, string>("username", user.Username),
                    new KeyValuePair<string,string>("password",user.Password),
                    new KeyValuePair<string,string>("refresh_token",user.RefreshToken==null?String.Empty:user.RefreshToken)
                 };
                var result = await httpClient.PostAsync("/token", new FormUrlEncodedContent(requestParams));
                var responseValue = await result.Content.ReadAsStringAsync();
                var responseData = JObject.Parse(responseValue);
                if (result.StatusCode == HttpStatusCode.OK)
                {
                    user.AccessToken = (string)responseData.SelectToken("access_token");
                    return JObject.FromObject(new { success = true, data = responseData });
                }
                else
                {
                    return JObject.FromObject(new { success = false, data = responseData });

                }
            }
        }
    }
}
