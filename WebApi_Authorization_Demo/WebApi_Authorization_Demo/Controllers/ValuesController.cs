using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Cors;
using WebApi_Authorization_Demo.Authorization;
using WebApi_Authorization_Demo.Models;

namespace WebApi_Authorization_Demo.Controllers
{
    [EnableCors(origins: "http://oauthoriztion.azurewebsites.net", headers: "*", methods: "*")]
    [RoutePrefix("api/values")]
    public class ValuesController : ApiController
    {
        // GET api/values
        [Authorize]
        public string Get()
        {
            return User.Identity.Name;
        }

        [HttpPost]
        [TokenCheckFilter]
        public string Post(UserViewModel model)
        {
            return "value";
        }

    }
}
