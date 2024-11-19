using Newtonsoft.Json;

namespace Keyfactor.Extensions.CAPlugin.HashicorpVault
{
    public class HashicorpVaultCATemplateConfig
    {
        [JsonProperty(Constants.TemplateConfig.ROLENAME)]
        public string RoleName { get; set; }

        [JsonProperty(Constants.TemplateConfig.TOKEN)]
        public string Token { get; set; }

        [JsonProperty(Constants.TemplateConfig.NAMESPACE)]
        public string Namespace { get; set; }

        [JsonProperty(Constants.TemplateConfig.MOUNTPOINT)]
        public string MountPoint { get; set; }

        [JsonProperty(Constants.TemplateConfig.CLIENTCERT)]
        public AuthCert ClientCertificate { get; set; }
    }
}
