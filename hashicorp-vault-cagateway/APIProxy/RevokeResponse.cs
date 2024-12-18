// Copyright {year} Keyfactor 
//  Licensed under the Apache License, Version 2.0 (the "License")\

using System;
using System.Text.Json.Serialization;

namespace Keyfactor.Extensions.CAPlugin.HashicorpVault.APIProxy
{
    public class RevokeResponse
    {
        [JsonPropertyName("revocation_time_rfc3339")]
        public DateTime RevocationTime { get; set; }

        [JsonPropertyName("state")]
        public string State { get; set; }

    }
}
