// Copyright {year} Keyfactor 
//  Licensed under the Apache License, Version 2.0 (the "License")\

using System.Text.Json.Serialization;

namespace Keyfactor.Extensions.CAPlugin.HashicorpVault.APIProxy
{
    public class SealStatusResponse
    {
        [JsonPropertyName("sealed")]
        public bool Sealed { get; set; }

        [JsonPropertyName("initialized")]
        public bool Initialized { get; set; }

        [JsonPropertyName("version")]
        public string VaultVersion { get; set; }
    }
}
