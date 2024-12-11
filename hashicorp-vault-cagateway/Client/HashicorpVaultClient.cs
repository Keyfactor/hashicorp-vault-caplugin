// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using VaultSharp;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.Cert;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.Commons;
using VaultSharp.V1.SecretsEngines.PKI;

namespace Keyfactor.Extensions.CAPlugin.HashicorpVault
{
    public class HashicorpVaultClient
    {
        private VaultClient _vaultClient { get; set; }
        private static readonly ILogger logger = LogHandler.GetClassLogger<HashicorpVaultClient>();

        private string _hostUrl { get; set; }
        private string _nameSpace { get; set; }
        private string _mountPoint { get; set; }
        private string _token { get; set; }
        private AuthCert _certAuthInfo { get; set; }
        private bool _useCertAuth { get; set; }


        public HashicorpVaultClient(HashicorpVaultCAConfig caConfig, HashicorpVaultCATemplateConfig templateConfig = null)
        {
            logger.MethodEntry();
            X509Certificate2 clientCert = null;
            IAuthMethodInfo authMethod = null;

            // set global values 
            SetClientValuesFromConfigs(caConfig, templateConfig);

            _mountPoint = _mountPoint ?? "pki"; // default to "pki" (vault default) if not specified.

            if (!string.IsNullOrEmpty(_token))
            {
                logger.LogTrace("Token is present in caConfig and will be used for authentication to Vault");
                authMethod = new TokenAuthMethodInfo(_token);
            }
            else
            {
                // the token is undefined; so we will use certificate authentication.
                // the certificate location is either a filepath or operating system certificate store

                logger.LogTrace("No Token is present in the config.  Checking for certificate info for authentication");

                if (!string.IsNullOrEmpty(_certAuthInfo.Thumbprint))
                {
                    // the thumbprint is defined; so we are going to retreive it from the operating system certificate store.

                    logger.LogTrace("Thumbprint is present in config.  Retreiving cert for authentication from store");

                    string thumbprint = _certAuthInfo.Thumbprint;

                    if (!Enum.TryParse(_certAuthInfo.StoreName, out StoreName sn) || !Enum.TryParse(_certAuthInfo.StoreLocation, out StoreLocation sl))
                    {
                        // either store name or store location are missing; we cannot proceed to retreive the certificate
                        logger.LogError($"Both store name and store location values are needed to retreive the cert from the store.  Values from configuration - StoreName: {_certAuthInfo.StoreName}, StoreLocation: {_certAuthInfo.StoreLocation}");
                        throw new MissingFieldException("Unable to find client authentication certificate.  Make sure both the certificate store name and store location are defined.");
                    }

                    X509Certificate2Collection foundCerts;
                    using (X509Store currentStore = new X509Store(sn, sl))
                    {
                        logger.LogTrace($"Search for client auth certificates with Thumbprint {thumbprint} in the {sn}{sl} certificate store");
                        // opening the cert store
                        currentStore.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                        // searching by thumbprint
                        foundCerts = currentStore.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, true);
                        logger.LogTrace($"Found {foundCerts.Count} certificates in the {currentStore.Name} store");
                        currentStore.Close();
                    }

                    if (foundCerts.Count > 1)
                        // rather than use the first one; if there are multiple with the same thumbprint, we throw an exception rather than risk improper credentials.
                        throw new Exception($"Multiple certificates with Thumprint {thumbprint} found in the {sn}{sl} certificate store");

                    if (foundCerts.Count < 1)
                        throw new Exception($"No certificate found in the {sn}{sl} store with thumbprint: {thumbprint}.");

                    clientCert = foundCerts[0];
                }
                else if (!string.IsNullOrEmpty(_certAuthInfo.CertificatePath))
                {
                    // the file path is defined.  we will try to load the cert from the PFX file located there.
                    logger.LogTrace($"CertificatePath is present in caConfig.  Will attempt to read cert from {_certAuthInfo.CertificatePath}");

                    try
                    {
                        X509Certificate2 cert = new X509Certificate2(_certAuthInfo.CertificatePath, _certAuthInfo.CertificatePassword);
                        clientCert = cert;
                    }
                    catch (Exception ex)
                    {
                        throw new Exception($"Unable to open the client certificate file at {_certAuthInfo.CertificatePath} with the given password. Error: {ex.Message}");
                    }
                }
                if (clientCert != null)
                {
                    // we've got the certificate setting our authentication 
                    authMethod = new CertAuthMethodInfo(clientCert);
                }
            }

            if (authMethod == null) throw new MissingFieldException($"Neither token or certificate data are present in the configuration.  Unable to configure Vault Authentication.");

            logger.LogTrace($"creating our VaultClient for the Vault instance at {caConfig.Host}, using Authentication Method: {authMethod.AuthMethodType}");
            _vaultClient = new VaultClient(new VaultClientSettings(caConfig.Host, authMethod) { Namespace = _nameSpace });

            logger.MethodExit();
        }


        public async Task<Secret<SignedCertificateData>> SignCSR(string csr, string subject, Dictionary<string, string[]> san, string roleName)
        {
            logger.MethodEntry();
            
            var reqOptions = new SignCertificatesRequestOptions();

            List<string> dnsNames = new List<string>();
            if (san.ContainsKey("Dns"))
            {
                dnsNames = new List<string>(san["Dns"]);
            }

            // Parse subject
            X509Name subjectParsed = null;
            string commonName = null, organization = null, orgUnit = null;
            try
            {
                subjectParsed = new X509Name(subject);
                commonName = subjectParsed.GetValueList(X509Name.CN).Cast<string>().LastOrDefault();
                organization = subjectParsed.GetValueList(X509Name.O).Cast<string>().LastOrDefault();
                orgUnit = subjectParsed.GetValueList(X509Name.OU).Cast<string>().LastOrDefault();
            }
            catch (Exception) { }

            if (commonName == null)
            {
                if (dnsNames.Count > 0)
                {
                    commonName = dnsNames[0];
                }
                else
                {
                    throw new Exception("No Common Name or DNS SAN provided, unable to enroll");
                }
            }

            reqOptions.CommonName = commonName;
            reqOptions.SubjectAlternativeNames = string.Join(",", dnsNames);
            //reqOptions.IPSubjectAlternativeNames            
            try
            {
                var response = await _vaultClient.V1.Secrets.PKI.SignCertificateAsync(roleName, reqOptions, pkiBackendMountPoint: _mountPoint);
                return response;
            }
            catch (Exception ex)
            {
                logger.LogError($"There was an error when submitting the request to Vault: {ex.Message}");
                logger.LogTrace($"provided parameters -- vaultUri: {_vaultClient.Settings.VaultServerUriWithPort}, mountPoint: {_mountPoint}, roleName: {roleName}, commonName: {reqOptions.CommonName}, SANs: {reqOptions.SubjectAlternativeNames}");
                throw;
            }
            finally
            {
                logger.MethodExit();
            }
        }

        public async Task<Secret<RawCertificateData>> GetCertificate(string certSerial)
        {
            logger.MethodEntry();

            try
            {
                logger.LogTrace($"requesting the certificate with serial number: {certSerial}");
                var cert = await _vaultClient.V1.Secrets.PKI.ReadCertificateAsync(certSerial, _mountPoint);
                logger.LogTrace($"successfully received a response for certificate with serial number: {certSerial}");
                return cert;
            }
            catch (Exception ex)
            {
                logger.LogError($"an error occurred attempting to retrieve certificate: {ex.Message}");
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
                var response = await _vaultClient.V1.Secrets.PKI.RevokeCertificateAsync(serial, _mountPoint);
                logger.LogTrace($"successfully revoked cert with serial {serial}, revocation time:  {response.Data.RevocationTime}");

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
                var res = await _vaultClient.V1.System.GetHealthStatusAsync();
                logger.LogTrace($"-- Vault health check response --");
                logger.LogTrace($"Vault version : {res.Version}");
                logger.LogTrace($"enterprise instance : {res.Enterprise}");
                logger.LogTrace($"initialized : {res.Initialized}");
                logger.LogTrace($"sealed : {res.Sealed}");
                logger.LogTrace($"server time UTC: {res.ServerTimeUtcUnixTimestamp}");
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

        public async Task GetDefaultIssuer()
        {
            logger.MethodEntry();
            logger.LogTrace("Requesting the default issuer via an authenticated endpoint");
            try
            {
                var res = await _vaultClient.V1.Secrets.PKI.ReadDefaultIssuerCertificateChainAsync(CertificateFormat.json, _mountPoint);
                logger.LogTrace($"successfully retrieved the default issuer cert chain: {res.Data.CertificateContent}");
            }
            catch (Exception ex)
            {
                logger.LogError($"The attempt to read the default issuer certificate failed: {ex.Message}");
                throw;
            }
            finally { logger.MethodExit(); }
        }

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
                var res = await _vaultClient.V1.Secrets.PKI.ListCertificatesAsync(_mountPoint);
                keys = res.Data.Keys;
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
                var res = await _vaultClient.V1.Secrets.PKI.ListRevokedCertificatesAsync(_mountPoint);
                keys = res.Data.Keys;
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

                var roles = await _vaultClient.V1.Secrets.PKI.ListRolesAsync(_mountPoint);
                roleNames = roles?.Data.Keys;
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

            _hostUrl = caConfig.Host; // host url, token and/or authentication certificate details come from the CA config
            logger.LogTrace($"set value for Host url: {_hostUrl}");

            _certAuthInfo = caConfig?.ClientCertificate;
            logger.LogTrace($"set value for Certificate authentication; thumbprint: {_certAuthInfo?.Thumbprint ?? "(missing) - using token authentication"}");

            _token = caConfig.Token ?? null;
            logger.LogTrace($"set value for authenetication token: {_token ?? "(missing) - using certificate authentication"}");

            // the namespace and mount point are read from the templateConfig unless missing

            _nameSpace = templateConfig?.Namespace ?? caConfig.Namespace;
            logger.LogTrace($"set value for Namespace: {_nameSpace}");

            _mountPoint = templateConfig?.MountPoint ?? caConfig.MountPoint;
            logger.LogTrace($"set value for Mountpoint: {_mountPoint ?? "(missing) - will default to 'pki'"}");

            if (_token == null && _certAuthInfo == null)
            {
                throw new MissingFieldException("Either an authentication token or certificate to use for authentication into Vault must be provided.");
            }

            logger.MethodExit();
        }
    }
}