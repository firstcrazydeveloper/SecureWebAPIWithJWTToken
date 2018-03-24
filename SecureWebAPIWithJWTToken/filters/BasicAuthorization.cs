using JWTAuthentication.Module.interfaces;
using JWTAuthentication.Module.providers;
using System;
using System.Net;
using System.Net.Http;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;

namespace SecureWebAPIWithJWTToken.filters
{
    public class BasicAuthorization : AuthorizationFilterAttribute
    {
        public IJWTTokenManager tokenManager;

        public BasicAuthorization()
        {
            tokenManager = new JWTTokenManager();
        }

        public override void OnAuthorization(HttpActionContext filterContext)
        {

            string userName = string.Empty;
            var request = filterContext.Request;
            var authorization = request.Headers.Authorization;


            try
            {
                var token = authorization.Parameter; // filterContext.Request.Headers.SingleOrDefault(x => x.Key == _authorizedToken);
                if (!string.IsNullOrEmpty(token))
                {
                    if (!tokenManager.ValidateToken(token, out userName))
                    {
                        filterContext.Response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
                        return;
                    }
                }
                else
                {
                    filterContext.Response = new HttpResponseMessage(HttpStatusCode.Forbidden);
                    return;
                }
            }
            catch (Exception)
            {
                filterContext.Response = new HttpResponseMessage(HttpStatusCode.Forbidden);
                return;
            }

            base.OnAuthorization(filterContext);
        }
    }
}