// Copyright {year} Keyfactor 
//  Licensed under the Apache License, Version 2.0 (the "License")\

using System;

namespace Keyfactor.Extensions.CAPlugin.HashicorpVault.APIProxy
{
    internal class MetadataResponse
    {
        public string IssuerId { get; set; }
        public DateTime Expiration { get; set; }
        public string CertMetadata { get; set; }
        public string Role { get; set; }
        public string SerialNumber { get; set; }
    }
}
