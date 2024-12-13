// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using Keyfactor.Extensions.CAPlugin.HashicorpVault.APIProxy;
using Keyfactor.Extensions.CAPlugin.HashicorpVault.Client;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Org.BouncyCastle.Asn1.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata.Ecma335;
using System.Threading.Tasks;

namespace Keyfactor.Extensions.CAPlugin.HashicorpVault
{
    public class HashicorpVaultClient
    {
        private VaultHttp _vaultHttp { get; set; }
        private static readonly ILogger logger = LogHandler.GetClassLogger<HashicorpVaultClient>();

        //private string _hostUrl { get; set; }
        //private string _nameSpace { get; set; }
        //private string _mountPoint { get; set; }
        //private string _token { get; set; }
        // private AuthCert _certAuthInfo { get; set; }
        // private bool _useCertAuth { get; set; }

        public HashicorpVaultClient(HashicorpVaultCAConfig caConfig, HashicorpVaultCATemplateConfig templateConfig = null)
        {
            logger.MethodEntry();

            SetClientValuesFromConfigs(caConfig, templateConfig);

            logger.MethodExit();
        }

        public async Task<SignResponse> SignCSR(string csr, string subject, Dictionary<string, string[]> san, string roleName)
        {
            logger.MethodEntry();

            var dnsNames = new List<string>();

            if (san.ContainsKey("Dns"))
            {
                dnsNames = new List<string>(san["Dns"]);
                logger.LogTrace($"the SAN contains DNS name{(dnsNames.Count > 1 ? 's' : string.Empty)}: {string.Join(",", dnsNames)}");
            }
            else
            {
                logger.LogTrace("the provided SANs contain no DNS names");
            }

            X509Name subjectParsed = null;
            string commonName = null, organization = null, orgUnit = null;
            try
            {
                logger.LogTrace($"parsing the subject:  {subject}");
                subjectParsed = new X509Name(subject);
                commonName = subjectParsed.GetValueList(X509Name.CN).Cast<string>().LastOrDefault();
                logger.LogTrace($"CN: {commonName}");
                organization = subjectParsed.GetValueList(X509Name.O).Cast<string>().LastOrDefault();
                logger.LogTrace($"Organization: {organization}");
                orgUnit = subjectParsed.GetValueList(X509Name.OU).Cast<string>().LastOrDefault();
                logger.LogTrace($"OU: {orgUnit}");
            }
            catch (Exception ex)
            {
                logger.LogTrace("couldn't parse all values from subject; it's ok.. they may not be present.");
                logger.LogWarning(LogHandler.FlattenException(ex));
            }

            if (commonName == null)
            {
                logger.LogTrace("no CN present; will use first DNS name (if present)");
                if (dnsNames.Count > 0)
                {
                    commonName = dnsNames[0];
                }
                else
                {
                    throw new Exception("No Common Name or DNS SAN provided, unable to enroll");
                }
            }

            var reqOptions = new SignRequest()
            {
                CommonName = commonName,
                AltNames = string.Join(",", san),
                Format = "pem_bundle",
                CSR = csr
            };

            var response = new WrappedResponse<SignResponse>();

            try
            {
                logger.LogTrace($"sending request to vault..");
                response = await _vaultHttp.PostAsync<WrappedResponse<SignResponse>>($"/sign/{roleName}", reqOptions);

                logger.LogTrace($"got a response from vault..");
                if (response.Warnings.Count > 0) { logger.LogWarning($"the response contained warnings: {string.Join(",", response.Warnings)}"); }
                logger.LogTrace($"serialized response: {JsonConvert.SerializeObject(response)}");
                return response.Data;
            }
            catch (Exception ex)
            {
                logger.LogError($"There was an error when submitting the request to Vault: {LogHandler.FlattenException(ex)}");
                logger.LogTrace($"request: {JsonConvert.SerializeObject(reqOptions)}");
                logger.LogTrace($"response: {JsonConvert.SerializeObject(response)}");
                logger.LogTrace($"http client configuration: {_vaultHttp.Configuration}");
                throw;
            }
            finally
            {
                logger.MethodExit();
            }
        }

        public async Task<CertResponse> GetCertificate(string certSerial)
        {
            logger.MethodEntry();

            try
            {
                logger.LogTrace($"requesting the certificate with serial number: {certSerial}");
                var response = await _vaultHttp.GetAsync<CertResponse>($"cert/{certSerial}");
                logger.LogTrace($"successfully received a response for certificate with serial number: {certSerial}");
                return response;
            }
            catch (Exception ex)
            {
                logger.LogError($"an error occurred attempting to retrieve certificate: {LogHandler.FlattenException(ex)}");
                throw;
            }
            finally
            {
                logger.MethodExit();
            }
        }

        public async Task RevokeCertificate(string serial)
        {
            logger.MethodEntry();
            try
            {
                logger.LogTrace($"making request to revoke cert with serial: {serial}");
                var response = await _vaultHttp.PostAsync<RevokeResponse>("revoke");
                logger.LogTrace($"successfully revoked cert with serial {serial}, revocation time:  {response.RevocationTime}");

            }
            catch (Exception ex)
            {
                logger.LogError($"an error occurred when attempting to revoke the certificate: {ex.Message}");
                throw;
            }
            finally { logger.MethodExit(); }
        }

        public async Task<bool> PingServer()
        {
            logger.MethodEntry();
            logger.LogTrace($"performing a system health check request to Vault");
            try
            {
                var res = await _vaultHttp.HealthCheckAsync();
                logger.LogTrace($"-- Vault health check response --");
                logger.LogTrace($"Vault version : {res.VaultVersion}");
                logger.LogTrace($"sealed? : {res.Sealed}");
                logger.LogTrace($"initialized? : {res.Initialized}");                
                return true;
            }
            catch (Exception ex)
            {
                logger.LogError($"Vault healthcheck failed with error: {ex.Message}");
                throw;
            }
            finally
            {
                logger.MethodExit();
            }
        }

        //public async Task GetDefaultIssuer()
        //{
        //    logger.MethodEntry();
        //    logger.LogTrace("Requesting the default issuer via an authenticated endpoint");
        //    try
        //    {
        //        var res = await _vaultClient.V1.Secrets.PKI.ReadDefaultIssuerCertificateChainAsync(CertificateFormat.json, _mountPoint);
        //        logger.LogTrace($"successfully retrieved the default issuer cert chain: {res.Data.CertificateContent}");
        //    }
        //    catch (Exception ex)
        //    {
        //        logger.LogError($"The attempt to read the default issuer certificate failed: {ex.Message}");
        //        throw;
        //    }
        //    finally { logger.MethodExit(); }
        //}

        /// <summary>
        /// Retreives all serial numbers for issued certificates 
        /// </summary>
        /// <returns>a list of the certificate serial number strings</returns>
        public async Task<List<string>> GetAllCertSerialNumbers()
        {
            logger.MethodEntry();
            var keys = new List<string>();
            try
            {
                var res = await _vaultHttp.GetAsync<WrappedResponse<KeyedList>>("certs/?list=true");
                return res.Data.Entries;
            }
            catch (Exception ex)
            {
                logger.LogError($"there was an error retreiving the certificate keys: {ex.Message}");
                throw;
            }
            finally { logger.MethodExit(); }
            return keys;
        }

        private async Task<List<string>> GetRevokedSerialNumbers()
        {
            logger.MethodEntry();
            var keys = new List<string>();
            try
            {
                var res = await _vaultHttp.GetAsync<KeyedList>("certs/revoked");
                keys = res.Entries;
            }
            catch (Exception ex)
            {
                logger.LogError($"there was an error retreiving the revoked certificate keys: {ex.Message}");
                throw;
            }
            finally { logger.MethodExit(); }
            return keys;
        }

        public async Task<List<string>> GetRoleNames()
        {
            logger.MethodEntry();
            var roleNames = new List<string>();
            try
            {
                // TODO: using a local fork of VaultSharp that adds methods for interacting with PKI Roles
                // replace with official package when available.
                // there is an outstanding Github issue (https://github.com/rajanadar/VaultSharp/issues/373)

                //var roles = await _vaultClient.V1.Secrets.PKI.ListRolesAsync(_mountPoint);
                roleNames = await _vaultHttp.GetAsync<List<string>>("roles");
            }
            catch (Exception ex)
            {
                logger.LogError($"There was a problem retreiving the PKI role names: {LogHandler.FlattenException(ex)}");
                throw;
            }
            finally { logger.MethodExit(); }
            return roleNames;
        }

        private void SetClientValuesFromConfigs(HashicorpVaultCAConfig caConfig, HashicorpVaultCATemplateConfig templateConfig)
        {
            logger.MethodEntry();

            var hostUrl = caConfig.Host; // host url and authentication details come from the CA config

            var token = caConfig.Token;
            var nameSpace = string.IsNullOrEmpty(templateConfig?.Namespace) ? caConfig.Namespace : templateConfig.Namespace; // Namespace comes from templateconfig if available, otherwise defaults to caConfig; can be null
            var mountPoint = string.IsNullOrEmpty(templateConfig?.MountPoint) ? caConfig.MountPoint : templateConfig.MountPoint; // Mountpoint comes from templateconfig if available, otherwise defaults to caConfig; if null, uses "pki" (Vault Default)
            mountPoint = mountPoint ?? "pki"; // using the vault default PKI secrets engine mount point if not present in config

            logger.LogTrace($"set value for Host url: {hostUrl}");
            logger.LogTrace($"set value for authentication token: {token ?? "(not defined)"}");
            logger.LogTrace($"set value for Namespace: {nameSpace ?? "(not defined)"}");
            logger.LogTrace($"set value for Mountpoint: {mountPoint}");

            // _certAuthInfo = caConfig?.ClientCertificate;
            // logger.LogTrace($"set value for Certificate authentication; thumbprint: {_certAuthInfo?.Thumbprint ?? "(missing) - using token authentication"}");

            //if (_token == null && _certAuthInfo == null)
            //{
            //    throw new MissingFieldException("Either an authentication token or certificate to use for authentication into Vault must be provided.");
            //}

            _vaultHttp = new VaultHttp(hostUrl, mountPoint, token, nameSpace);

            logger.MethodExit();
        }
    }
}