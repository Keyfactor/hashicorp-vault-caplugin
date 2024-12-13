// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Keyfactor.Extensions.CAPlugin.HashicorpVault.APIProxy
{
    public class WrappedResponse<T>
    {
        [JsonProperty("lease_id")]
        public string LeaseId { get; set; }

        [JsonProperty("renewable")]
        public bool Renewable { get; set; }

        [JsonProperty("lease_duration")]
        public int LeaseDuration { get; set; }

        [JsonProperty("auth")]
        public string Auth { get; set; }

        [JsonProperty("warnings")]
        public List<string> Warnings { get; set; }

        [JsonProperty("mount_point")]
        public string MountPoint { get; set; }

        [JsonProperty("mount_running_plugin_version")]
        public string PluginVersion { get; set; }

        [JsonProperty("data")]
        public T Data { get; set; }

    }
}
