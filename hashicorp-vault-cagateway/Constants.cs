namespace Keyfactor.Extensions.CAPlugin.HashicorpVault
{
    public static class Constants
    {
        //Define any constants needed here (mostly field names for config parameters)
        public static class CAConfig
        {
            public const string HOST = "Host";
            public const string MOUNTPOINT = "MountPoint";
            public const string TOKEN = "Token";
            public const string CLIENTCERT = "ClientCertificate";
            public const string NAMESPACE = "Namespace";
            public const string ENABLED = "Enabled";
        }

        public static class TemplateConfig
        {
            public const string ROLENAME = "RoleName";
            public const string ISSUER = "Issuer";
            public const string TOKEN = "Token";
            public const string CLIENTCERT = "ClientCertificate";
            public const string NAMESPACE = "Namespace";
            public const string MOUNTPOINT = "MountPoint";
        }
    }
}