using SecureWebAPIWithJWTToken.filters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;

namespace SecureWebAPIWithJWTToken.Controllers
{
    [JWTTokenAuthentication]
    public class BaseSecureController : ApiController
    {
    }
}
