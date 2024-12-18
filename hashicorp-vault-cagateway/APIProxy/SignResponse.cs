// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Keyfactor.Extensions.CAPlugin.HashicorpVault.APIProxy
{
    public class SignResponse
    {
        [JsonPropertyName("expiration")]
        public int Expiration { get; set; }

        [JsonPropertyName("certificate")]
        public string Certificate { get; set; }

        [JsonPropertyName("issuing_ca")]
        public string IssuingCA { get; set; }

        [JsonPropertyName("ca_chain")]
        public List<string> CAChain { get; set; }

        [JsonPropertyName("serial_number")]
        public string SerialNumber { get; set; }
    }
}
