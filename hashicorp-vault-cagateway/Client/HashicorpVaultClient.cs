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
using Org.BouncyCastle.Asn1.X509;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Keyfactor.Extensions.CAPlugin.HashicorpVault
{
    /// <summary>
    /// This is our client for interacting with the Hashicorp Vault API.
    /// It wraps our vault http client with the ability to translate objects
    /// to and from what is needed for Vault API requests.
    /// </summary>
    public class HashicorpVaultClient
    {
        private HashicorpVaultCAConfig _caConfig { get; set; }
        private HashicorpVaultCATemplateConfig _templateConfig { get; set; }
        private readonly ILogger logger;        

        public HashicorpVaultClient(HashicorpVaultCAConfig caConfig, HashicorpVaultCATemplateConfig templateConfig = null)
        {
            logger = LogHandler.GetClassLogger<HashicorpVaultClient>();
            logger.MethodEntry();
            _caConfig = caConfig;
            _templateConfig = templateConfig;
            logger.MethodExit();
        }

        public async Task<SignResponse> SignCSR(string csr, string subject, Dictionary<string, string[]> san, string roleName)
        {
            logger.MethodEntry();

            var dnsNames = new List<string>();
            SignRequest request = null;
            WrappedResponse<SignResponse> response = null;
            X509Name subjectParsed = null;
            string commonName = null, organization = null, orgUnit = null;

            logger.LogTrace($"SAN values: ");
            foreach (var key in san.Keys) {
                logger.LogTrace($"{key}: {string.Join(",", san[key])}");            
            }

            if (san.ContainsKey("dnsname"))
            {
                dnsNames = new List<string>(san["dnsname"]);
                logger.LogTrace($"the SAN contains DNS name{(dnsNames.Count > 1 ? 's' : string.Empty)}: {string.Join(",", dnsNames)}");
            }
            else
            {
                logger.LogTrace("the provided SANs contain no DNS names");
            }

            try
            {
                logger.LogTrace($"parsing the subject: {subject}");
                subjectParsed = new X509Name(subject);
                commonName = subjectParsed.GetValueList(X509Name.CN).Cast<string>().LastOrDefault();
                logger.LogTrace($"CN: {commonName}");
                organization = subjectParsed.GetValueList(X509Name.O).Cast<string>().LastOrDefault();
                logger.LogTrace($"Org: {organization}");
                orgUnit = subjectParsed.GetValueList(X509Name.OU).Cast<string>().LastOrDefault();
                logger.LogTrace($"OU: {orgUnit}");
            }
            catch (Exception ex)
            {
                logger.LogTrace("couldn't parse all values from subject; it's ok.. they may not be present.");
                logger.LogWarning(LogHandler.FlattenException(ex));
            }

            try
            {
                if (commonName == null)
                {
                    logger.LogTrace("no CN present; will use first DNS name (if present)");
                    if (dnsNames.Count > 0)
                    {
                        commonName = dnsNames[0];
                    }
                    else
                    {
                        throw new Exception("no Common Name or DNS SAN provided, unable to enroll");
                    }
                }

                request = new SignRequest()
                {
                    CommonName = commonName,
                    AltNames = dnsNames.Count > 0 ? string.Join(",", dnsNames) : null,
                    Format = "pem_bundle",
                    CSR = csr
                };
                var _vaultHttp = ConfigureNewVaultClient();

                logger.LogTrace($"sending request to vault..");
                logger.LogTrace($"serialized request: {JsonSerializer.Serialize(request)}");
                response = await _vaultHttp.PostAsync<WrappedResponse<SignResponse>>($"sign/{roleName}", request);
                logger.LogTrace($"got a response from vault..");

                if (response.Warnings?.Count > 0) { logger.LogTrace($"the response contained warnings: {string.Join(", ", response.Warnings)}"); }
                
                logger.LogTrace($"serialized SignResponse: {JsonSerializer.Serialize(response.Data)}");        
               
                return response.Data;
            }
            catch (Exception ex)
            {
                logger.LogError($"There was an error when submitting the request to Vault: {LogHandler.FlattenException(ex)}");
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
            logger.LogTrace($"requesting the certificate with serial number: {certSerial}");

            try
            {
                var _vaultHttp = ConfigureNewVaultClient();
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

        public async Task<RevokeResponse> RevokeCertificate(string serial)
        {
            logger.MethodEntry();
            logger.LogTrace($"making request to revoke cert with serial: {serial}");
            try
            {
                var _vaultHttp = ConfigureNewVaultClient();
                var response = await _vaultHttp.PostAsync<RevokeResponse>("revoke", new RevokeRequest(serial));
                logger.LogTrace($"successfully revoked cert with serial {serial}, revocation time:  {response.RevocationTime}");
                return response;
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
                var _vaultHttp = ConfigureNewVaultClient();
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

        /// <summary>
        /// Retreives all serial numbers for issued certificates 
        /// </summary>
        /// <returns>a list of the certificate serial number strings</returns>
        public async Task GetAllCertSerialNumbers(BlockingCollection<string> serialNumberCollection, CancellationToken token)
        {
            if (token.IsCancellationRequested) {
                logger.LogWarning($"cancelation was requested.  Stopping task");
                serialNumberCollection.CompleteAdding();
                return;
            }
            logger.MethodEntry();
            try
            {
                var _vaultHttp = ConfigureNewVaultClient();                
                var res = await _vaultHttp.GetAsync<WrappedResponse<KeyedList>>("certs/?list=true");
                var serials = res.Data?.Entries;
                if (serials == null || serials.Count == 0) {
                    return;
                }
                logger.LogTrace($"got {res.Data?.Entries?.Count} serial numbers from {_caConfig.Host} namespace: {_caConfig.Namespace}, mount-point: {_caConfig.MountPoint}");
                foreach (var serial in serials) {
                    if (!serialNumberCollection.TryAdd(serial, 50, token)) {
                        logger.LogWarning($"unable to add serial number {serial} to the collection");
                    }
                }
                serialNumberCollection.CompleteAdding();
            }
            catch (Exception ex)
            {
                logger.LogError($"there was an error retreiving the certificate keys from {_caConfig.Host} using namespace: {_templateConfig.Namespace ?? _caConfig.Namespace} and mount-point: {_caConfig.MountPoint}.  Error: {ex.Message}");
                throw;
            }
            finally { logger.MethodExit(); }
        }

        private async Task<List<string>> GetRevokedSerialNumbers()
        {
            logger.MethodEntry();
            var keys = new List<string>();
            try
            {
                var _vaultHttp = ConfigureNewVaultClient();
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

        public async Task<List<string>> GetRoleNamesAsync()
        {
            logger.MethodEntry();
            var roleNames = new List<string>();
            try
            {
                var _vaultHttp = ConfigureNewVaultClient();
                logger.LogTrace("getting the role names as a wrapped keyed-list response..");
                var response = await _vaultHttp.GetAsync<WrappedResponse<KeyedList>>("roles/?list=true");
                logger.LogTrace($"received {response.Data?.Entries?.Count} role names (or product IDs)");
                return response.Data?.Entries;
            }
            catch (Exception ex)
            {
                logger.LogError($"There was a problem retreiving the PKI role names: {LogHandler.FlattenException(ex)}");
                throw;
            }
            finally { logger.MethodExit(); }            
        }

        private VaultHttp ConfigureNewVaultClient()
        {
            logger.MethodEntry();
            try
            {
                var hostUrl = _caConfig.Host; // host url and authentication details come from the CA config
                logger.LogTrace($"set value for Host url: {hostUrl}");

                var token = _caConfig.Token;
                logger.LogTrace($"set value for authentication token: {token ?? "(not defined)"}");

                var nameSpace = string.IsNullOrEmpty(_templateConfig?.Namespace) ? _caConfig.Namespace : _templateConfig.Namespace; // Namespace comes from templateconfig if available, otherwise defaults to caConfig; can be null
                logger.LogTrace($"set value for Namespace: {nameSpace ?? "(not defined)"}");

                var mountPoint = string.IsNullOrEmpty(_templateConfig?.MountPoint) ? _caConfig.MountPoint : _templateConfig.MountPoint; // Mountpoint comes from templateconfig if available, otherwise defaults to caConfig; if null, uses "pki" (Vault Default)
                mountPoint = mountPoint ?? "pki"; // using the vault default PKI secrets engine mount point if not present in config
                logger.LogTrace($"set value for Mountpoint: {mountPoint}");


                // _certAuthInfo = caConfig?.ClientCertificate;
                // logger.LogTrace($"set value for Certificate authentication; thumbprint: {_certAuthInfo?.Thumbprint ?? "(missing) - using token authentication"}");

                //if (_token == null && _certAuthInfo == null)
                //{
                //    throw new MissingFieldException("Either an authentication token or certificate to use for authentication into Vault must be provided.");
                //}

                return new VaultHttp(hostUrl, mountPoint, token, nameSpace);
            }
            catch (Exception ex)
            {
                logger.LogError($"error when creating new vault client: {LogHandler.FlattenException(ex)}");
                throw;
            }
            finally {
                logger.MethodExit();
            }
        }
    }
}