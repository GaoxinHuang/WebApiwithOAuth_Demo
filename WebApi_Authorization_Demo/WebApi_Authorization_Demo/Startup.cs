using System;
using System.Threading.Tasks;
using Microsoft.Owin;
using Owin;
using Microsoft.Owin.Security.OAuth;
using WebApi_Authorization_Demo.Authorization;
using System.Web.Http;

[assembly: OwinStartup(typeof(WebApi_Authorization_Demo.Startup))]

namespace WebApi_Authorization_Demo
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            // For more information on how to configure your application, visit http://go.microsoft.com/fwlink/?LinkID=316888
            OAuthAuthorizationServerOptions OAuthOptions = new OAuthAuthorizationServerOptions
            {
                TokenEndpointPath = new PathString("/token"),
                Provider = new GxAuthorizationServerProvider(), //这个就是方法token提供者的class, 
                AccessTokenExpireTimeSpan = TimeSpan.FromDays(14),  //设置token过期
                AllowInsecureHttp = true,
                RefreshTokenProvider = new GxRefreshTokenProvider()
                //RefreshTokenProvider = IocContainer.Resolver.Resolve<CNBlogsRefreshTokenProvider>()
            };
            app.UseOAuthBearerTokens(OAuthOptions);
        }
    }
}
