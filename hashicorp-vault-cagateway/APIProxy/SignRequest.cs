// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.


using System.Text.Json.Serialization;

namespace Keyfactor.Extensions.CAPlugin.HashicorpVault.APIProxy
{
    public class SignRequest
    {
        /// <summary>
        /// The PEM encoded CSR
        /// </summary>
        [JsonPropertyName("csr")]
        public string CSR { get; set; }

        /// <summary>
        /// Specifies the requested CN for the certificate. If the CN is allowed by role policy, it will be issued. 
        /// If more than one common_name is desired, specify the alternative names in the alt_names list.
        /// </summary>
        [JsonPropertyName("common_name"), ]
        public string CommonName { get; set; }

        /// <summary>
        /// Specifies the requested Subject Alternative Names, in a comma-delimited list. 
        /// These can be host names or email addresses; they will be parsed into their respective fields. 
        /// If any requested names do not match role policy, the entire request will be denied.
        /// </summary>
        [JsonPropertyName("alt_names")]
        public string AltNames { get; set; }

        /// <summary>
        /// Specifies custom OID/UTF8-string SANs. These must match values specified on the role in allowed_other_sans 
        /// (see role creation for allowed_other_sans globbing rules). 
        /// The format is the same as OpenSSL: <oid>;<type>:<value> where the only current valid type is UTF8. 
        /// This can be a comma-delimited list or a JSON string slice.
        /// </summary>
        [JsonPropertyName("other_sans")]
        public string OtherSans { get; set; }

        /// <summary>
        /// Specifies the requested IP Subject Alternative Names, in a comma-delimited list. 
        /// Only valid if the role allows IP SANs (which is the default).
        /// </summary>
        [JsonPropertyName("ip_sans")]
        public string IpSans { get; set; }

        /// <summary>
        /// Specifies the requested URI Subject Alternative Names, in a comma-delimited list. 
        /// If any requested URIs do not match role policy, the entire request will be denied.
        /// </summary>
        [JsonPropertyName("uri_sans")]
        public string UriSans { get; set; }

        /// <summary>
        /// Specifies the requested Time To Live. Cannot be greater than the role's max_ttl value. 
        /// If not provided, the role's ttl value will be used. Note that the role values default to system values if not explicitly set. 
        /// See not_after as an alternative for setting an absolute end date (rather than a relative one).
        /// </summary>
        [JsonPropertyName("ttl")]
        public string TTL { get; set; }

        /// <summary>
        /// Specifies the format for returned data. Can be pem, der, or pem_bundle. If der, the output is base64 encoded. 
        /// If pem_bundle, the certificate field will contain the certificate and, if the issuing CA is not a Vault-derived self-signed root, 
        /// it will be concatenated with the certificate.
        /// </summary>
        [JsonPropertyName("format")]
        public string Format { get; set; }

        /// <summary>
        /// If true, the given common_name will not be included in DNS or Email Subject Alternate Names (as appropriate). 
        /// Useful if the CN is not a hostname or email address, but is instead some human-readable identifier.
        /// </summary>
        [JsonPropertyName("exclude_cn_from_sans")]
        public bool ExcludeCnFromSans { get; set; }

        /// <summary>
        /// Set the Not After field of the certificate with specified date value. 
        /// The value format should be given in UTC format YYYY-MM-ddTHH:MM:SSZ. 
        /// Supports the Y10K end date for IEEE 802.1AR-2018 standard devices, 9999-12-31T23:59:59Z.
        /// </summary>
        [JsonPropertyName("not_after")]
        public string NotAfter { get; set; }

        /// <summary>
        /// If true, the returned ca_chain field will not include any self-signed CA certificates. 
        /// Useful if end-users already have the root CA in their trust store.
        /// </summary>
        [JsonPropertyName("remove_roots_from_chain")]
        public bool RemoveRootsFromChain { get; set; }

        /// <summary>
        /// Specifies the comma-separated list of requested User ID (OID 0.9.2342.19200300.100.1.1) 
        /// Subject values to be placed on the signed certificate. This field is validated against allowed_user_ids on the role.
        /// </summary>
        [JsonPropertyName("user_ids")]
        public string UserIds { get; set; }

        /// <summary>
        /// **Vault Enterprise edition only**
        /// A base 64 encoded value or an empty string to associate with the certificate's serial number. 
        /// The role's no_store_metadata must be set to false, otherwise an error is returned when specified
        /// </summary>
        [JsonPropertyName("cert_metadata")]
        public string CertMetadata { get; set; }
    }
}
