using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JWTAuthentication.Module.interfaces
{
    public interface IJWTTokenManager
    {
        string GenerateToken(string username, string[] roles, int expireMinutes = 20);
        bool ValidateToken(string token, out string username);
    }
}
