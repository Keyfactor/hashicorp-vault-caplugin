using Newtonsoft.Json;

namespace Keyfactor.Extensions.CAPlugin.HashicorpVault
{
    public class HashicorpVaultCATemplateConfig
    {
        [JsonProperty("RoleName")]
        public string RoleName { get; set; }
        
        [JsonProperty("Token")]
        public string Token { get; set; }

        [JsonProperty("Namespace")]
        public string Namespace { get; set; }

        [JsonProperty("ClientCertificate")]
        public AuthCert ClientCertificate { get; set; }
    }
}
