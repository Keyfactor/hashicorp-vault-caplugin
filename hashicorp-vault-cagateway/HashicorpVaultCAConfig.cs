// Copyright 2022 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using Newtonsoft.Json;

namespace Keyfactor.Extensions.CAPlugin.HashicorpVault
{
    public class HashicorpVaultCAConfig
    {
        [JsonProperty("Host")]
        public string Host { get; set; }

        [JsonProperty("MountPoint")]
        public string MountPoint { get; set; }

        [JsonProperty("Token")]
        public string Token { get; set; }

        [JsonProperty("Namespace")]
        public string Namespace { get; set; }

        [JsonProperty("ClientCertificate")]
        public AuthCert ClientCertificate { get; set; }

        [JsonProperty("Enabled")]
        public bool Enabled { get; set; }
    }

    public class AuthCert
    {
        public string StoreName { get; set; }
        public string StoreLocation { get; set; }
        public string Thumbprint { get; set; }
        public string CertificatePath { get; set; }
        public string CertificatePassword { get; set; }
    }
}