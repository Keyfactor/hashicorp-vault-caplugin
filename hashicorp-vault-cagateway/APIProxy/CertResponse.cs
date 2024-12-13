﻿// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using Newtonsoft.Json;
using System;

namespace Keyfactor.Extensions.CAPlugin.HashicorpVault.APIProxy
{
    public class CertResponse
    {
        [JsonProperty("certificate")]
        public string Certificate { get; set; }

        [JsonProperty("revocation_time_rfc3339")]
        public DateTime? RevocationTime { get; set; }

        [JsonProperty("issuer_id")]
        public string IssuerId { get; set; }
    }
}
