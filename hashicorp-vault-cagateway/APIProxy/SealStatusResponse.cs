// Copyright {year} Keyfactor 
//  Licensed under the Apache License, Version 2.0 (the "License")\

using Newtonsoft.Json;

namespace Keyfactor.Extensions.CAPlugin.HashicorpVault.APIProxy
{
    public class SealStatusResponse
    {
        [JsonProperty("sealed")]
        public bool Sealed { get; set; }

        [JsonProperty("initialized")]
        public bool Initialized { get; set; }

        [JsonProperty("version")]
        public string VaultVersion { get; set; }
    }
}
