// Copyright {year} Keyfactor 
//  Licensed under the Apache License, Version 2.0 (the "License")\

using Newtonsoft.Json;
using System;

namespace Keyfactor.Extensions.CAPlugin.HashicorpVault.APIProxy
{
    public class RevokeResponse
    {
        [JsonProperty("revocation_time_rfc3339")]
        public DateTime RevocationTime { get; set; }

        [JsonProperty("state")]
        public string State { get; set; }

    }
}
