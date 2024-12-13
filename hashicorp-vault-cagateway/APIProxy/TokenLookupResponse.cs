// Copyright {year} Keyfactor 
//  Licensed under the Apache License, Version 2.0 (the "License")\

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Keyfactor.Extensions.CAPlugin.HashicorpVault.APIProxy
{
    public class TokenLookupResponse
    {
        public List<string> IdentityPolicies { get; set; }
        public List<string> Policies { get; set; }
        public string DisplayName { get; set; }
    }
}
