// Copyright {year} Keyfactor 
//  Licensed under the Apache License, Version 2.0 (the "License")\

using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Keyfactor.Extensions.CAPlugin.HashicorpVault.APIProxy
{
    public class ErrorResponse
    {
        [JsonPropertyName("errors")]
        public List<string> Errors { get; set; }
    }
}
