// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

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
            public const string NAMESPACE = "Namespace";
            public const string MOUNTPOINT = "MountPoint";
            public const string TOKEN = "Token";
        }
    }
}