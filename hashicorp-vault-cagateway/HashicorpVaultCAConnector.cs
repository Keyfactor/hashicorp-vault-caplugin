// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.HashicorpVault.APIProxy;
using Keyfactor.Logging;
using Keyfactor.PKI.Enums.EJBCA;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Keyfactor.Extensions.CAPlugin.HashicorpVault
{
    public class HashicorpVaultCAConnector : IAnyCAPlugin
    {
        private readonly ILogger logger;
        private HashicorpVaultCAConfig _caConfig { get; set; }
        private HashicorpVaultClient _client { get; set; }
        private ICertificateDataReader _certificateDataReader;

        public HashicorpVaultCAConnector()
        {
            logger = LogHandler.GetClassLogger<HashicorpVaultCAConnector>();

            JsonSerializerOptions options = new()
            {
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault
            };
        }

        /// <summary>
        /// Initialize the <see cref="HashicorpVaultCAConnector"/>
        /// </summary>
        /// <param name="configProvider">The config provider contains information required to connect to the CA.</param>
        public void Initialize(IAnyCAPluginConfigProvider configProvider, ICertificateDataReader certificateDataReader)
        {
            logger.MethodEntry(LogLevel.Trace);
            string rawConfig = JsonSerializer.Serialize(configProvider.CAConnectionData);
            logger.LogTrace($"serialized config: {rawConfig}");
            _caConfig = JsonSerializer.Deserialize<HashicorpVaultCAConfig>(rawConfig);
            logger.MethodExit(LogLevel.Trace);
            _client = new HashicorpVaultClient(_caConfig);
        }

        /// <summary>
        /// Enrolls for a certificate through the API.
        /// </summary>
        /// <param name="certificateDataReader">Reads certificate data from the database.</param>
        /// <param name="csr">The certificate request CSR in PEM format.</param>
        /// <param name="subject">The subject of the certificate request.</param>
        /// <param name="san">Any SANs added to the request.</param>
        /// <param name="productInfo">Information about the CA product type.</param>
        /// <param name="requestFormat">The format of the request.</param>
        /// <param name="enrollmentType">The type of the enrollment, i.e. new, renew, or reissue.</param>
        /// <returns></returns>
        public async Task<EnrollmentResult> Enroll(string csr, string subject, Dictionary<string, string[]> san, EnrollmentProductInfo productInfo, RequestFormat requestFormat, EnrollmentType enrollmentType)
        {
            logger.MethodEntry(LogLevel.Trace);
            logger.LogInformation($"Begin {enrollmentType} enrollment for {subject}");

            try
            {
                logger.LogTrace("getting product info");
                var serializedProductInfo = JsonSerializer.Serialize(productInfo.ProductParameters);
                logger.LogTrace($"got product info: {serializedProductInfo}");
                var templateConfig = JsonSerializer.Deserialize<HashicorpVaultCATemplateConfig>(serializedProductInfo);
                templateConfig.RoleName = productInfo.ProductID; // product ID corresponds to RoleName

                // create the client
                logger.LogTrace("instantiating the client..");
                _client = new HashicorpVaultClient(_caConfig, templateConfig);

                logger.LogDebug("Parse subject for Common Name");
                string commonName = ParseSubject(subject, "CN=");
                logger.LogTrace($"Common Name: {commonName}");

                var vaultRole = templateConfig.RoleName;
                logger.LogTrace($"using vault role name {templateConfig.RoleName}");

                logger.LogTrace($"Sending request with these values:");
                logger.LogTrace($"csr: {csr}");
                logger.LogTrace($"common_name: {commonName}");
                logger.LogTrace($"sans:");
                foreach (var entry in san)
                {
                    logger.LogTrace($"{entry.Key} : {string.Join(", ", entry.Value)}");
                }

                logger.LogTrace($"role: {vaultRole}");

                var res = await _client.SignCSR(csr, subject, san, vaultRole);
                logger.LogTrace($"back to calling method, cert content: {res.Certificate}");

                return new EnrollmentResult()
                {
                    CARequestID = GetTrackingIdFromSerial(res.SerialNumber),
                    Status = (int)EndEntityStatus.NEW,
                    StatusMessage = $"Successfully enrolled certificate {subject}",
                    Certificate = res.Certificate,
                };
            }
            catch (Exception ex)
            {
                logger.LogError($"Error when performing enrollment: {LogHandler.FlattenException(ex)}");
                throw;
            }
            finally
            {
                logger.MethodExit();
            }
        }

        /// <summary>
        /// Returns a single certificate record by its serial number.
        /// </summary>
        /// <param name="caRequestID">The CA request ID for the certificate.</param>
        /// <returns></returns>
		public async Task<AnyCAPluginCertificate> GetSingleRecord(string caRequestID)
        {
            logger.MethodEntry();

            logger.LogTrace($"converting caRequestId {caRequestID} into a Vault style certificate serial number");
            var formattedSerial = GetSerialFromTrackingId(caRequestID);
            logger.LogTrace($"converted serial number: {formattedSerial}");

            try
            {
                var cert = await _client.GetCertificate(formattedSerial);
                var revoked = cert.RevocationTime != null;
                var result = new AnyCAPluginCertificate
                {
                    CARequestID = caRequestID,
                    Certificate = cert.Certificate,
                    Status = revoked ? (int)EndEntityStatus.REVOKED : (int)EndEntityStatus.GENERATED,
                    RevocationDate = cert.RevocationTime
                    // ProductID = vaultRole // this is not avialable after issuance                                       
                };

                return result;
            }
            catch (Exception ex)
            {
                logger.LogError($"There was an error retrieving the certificate: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Attempts to reach the CA over the network.
        /// </summary>
        public async Task Ping()
        {
            logger.MethodEntry();
            logger.LogTrace("Attempting ping of Vault endpoint");
            try
            {
                var result = await _client.PingServer();
            }
            catch (Exception ex)
            {
                logger.LogError($"Ping attempt failed with error: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Revokes a certificate by its serial number.
        /// </summary>
        /// <param name="caRequestID">The CA request ID.</param>
        /// <param name="hexSerialNumber">The hex-encoded serial number.</param>
        /// <param name="revocationReason">The revocation reason.</param>
        /// <returns></returns>
        public async Task<int> Revoke(string caRequestID, string hexSerialNumber, uint revocationReason)
        {
            logger.MethodEntry();
            try
            {
                var serial = GetSerialFromTrackingId(caRequestID);
                await _client.RevokeCertificate(serial);
                return (int)EndEntityStatus.REVOKED;
            }
            catch (Exception ex)
            {
                logger.LogError($"revocation failed with error: {ex.Message}");
                throw;
            }
            finally
            {
                logger.MethodExit();
            }
        }

        /// <summary>
        /// Synchronizes the gateway with the external CA
        /// </summary>
        /// <param name="certificateDataReader">Provides information about the gateway's certificate database.</param>
        /// <param name="blockingBuffer">Buffer into which certificates are places from the CA.</param>
        /// <param name="certificateAuthoritySyncInfo">Information about the last CA sync.</param>
        /// <param name="cancelToken">The cancellation token.</param>
        public async Task Synchronize(BlockingCollection<AnyCAPluginCertificate> blockingBuffer, DateTime? lastSync, bool fullSync, CancellationToken cancelToken)
        {
            // !! Any certificates issued outside of this CA Gateway will not necessarily be associated with the role name / (product ID) that was used to generate it
            // !! since that value is not available after the initial generation.

            logger.MethodEntry();
            var certSerials = new List<string>();
            var count = 0;
            try
            {
                logger.LogTrace("getting all certificate serial numbers from vault");
                certSerials = await _client.GetAllCertSerialNumbers();
            }
            catch (Exception ex)
            {
                logger.LogError($"failed to retreive serial numbers: {LogHandler.FlattenException(ex)}");
                throw;
            }

            logger.LogTrace($"got {certSerials.Count()} serial numbers. Begin checking status for each...");

            foreach (var certSerial in certSerials)
            {
                CertResponse certFromVault = null;
                var dbStatus = -1;
                try
                {
                    logger.LogTrace("Getting cert details from vault");
                    certFromVault = await _client.GetCertificate(certSerial);
                }
                catch (Exception ex)
                {
                    logger.LogError($"Failed to retreive details for certificate with serial number {certSerial} from Vault:  {LogHandler.FlattenException(ex)}");
                    throw;
                }
                logger.LogTrace($"converting {certSerial} to database trackingId");
                var trackingId = GetTrackingIdFromSerial(certSerial);
                logger.LogTrace($"attempting to retreive status of cert with tracking id {trackingId} from the database");

                try
                {
                    dbStatus = await _certificateDataReader.GetStatusByRequestID(trackingId);
                }
                catch
                {
                    logger.LogTrace($"tracking id {trackingId} was not found in the database.  it will be added.");
                } // not found; keeps dbStatus == -1

                if (dbStatus == -1 || fullSync) // it's missing and needs added, or a full sync is requested
                {
                    logger.LogTrace($"adding cert with serial {certSerial} to the database.  fullsync is {fullSync}");

                    var newCert = new AnyCAPluginCertificate
                    {
                        CARequestID = trackingId,
                        Certificate = certFromVault.Certificate,
                        Status = certFromVault.RevocationTime != null ? (int)EndEntityStatus.REVOKED : (int)EndEntityStatus.GENERATED,
                        RevocationDate = certFromVault.RevocationTime ?? null,
                    };

                    try
                    {
                        blockingBuffer.Add(newCert);
                    }
                    catch (Exception ex)
                    {
                        logger.LogError($"Failed to add the cert to the database: {LogHandler.FlattenException(ex)}");
                        throw;
                    }
                }
                else // the cert exists in the database; just update the status if necessary
                {
                    var revoked = certFromVault.RevocationTime != null;

                    if (revoked && dbStatus != (int)EndEntityStatus.REVOKED)
                    {
                        // need to update the db status to reflect that it has been revoked.
                        var newCert = new AnyCAPluginCertificate
                        {
                            CARequestID = trackingId,
                            Certificate = certFromVault.Certificate,
                            Status = (int)EndEntityStatus.REVOKED,
                            RevocationDate = certFromVault.RevocationTime
                            // ProductID is not available via the API after the initial issuance.  we do not want to overwrite                            
                        };
                    }
                }
                count++;
            }
            logger.LogTrace($"Completed sync of {count} certificates");
            logger.MethodExit();
        }

        /// <summary>
        /// Validates that the CA connection info is correct.
        /// </summary>
        /// <param name="connectionInfo">The information used to connect to the CA.</param>
        public async Task ValidateCAConnectionInfo(Dictionary<string, object> connectionInfo)
        {
            logger.MethodEntry();

            if (!(bool)connectionInfo[Constants.CAConfig.ENABLED])
            {
                logger.LogWarning($"The CA is currently in the Disabled state. It must be Enabled to perform operations. Skipping validation...");
                logger.MethodExit(LogLevel.Trace);
                return;
            }
            List<string> errors = new List<string>();

            // make sure required fields are defined..
            if (string.IsNullOrEmpty(connectionInfo[Constants.CAConfig.HOST] as string))
            {
                errors.Add($"The '{Constants.CAConfig.HOST}' is required.");
            }

            if (string.IsNullOrEmpty(connectionInfo[Constants.CAConfig.MOUNTPOINT] as string))
            {
                errors.Add($"The '{Constants.CAConfig.MOUNTPOINT}' is required.");
            }

            // make sure an authentication mechanism is defined (either certificate or token)
            var token = connectionInfo[Constants.CAConfig.TOKEN] as string;
            var cert = connectionInfo[Constants.CAConfig.CLIENTCERT] as string;

            if (string.IsNullOrEmpty(token) && string.IsNullOrEmpty(cert))
            {
                errors.Add("Either an authentication token or client certificate must be defined for authentication into Vault.");
            }
            if (!string.IsNullOrEmpty(token) && !string.IsNullOrEmpty(cert))
            {
                logger.LogWarning("Both an authentication token and client certificate are defined.  Using the token for authentication.");
            }

            // if any errors, throw
            if (errors.Any())
            {
                throw new AnyCAValidationException(string.Join("\n", errors));
            }

            // test the connection
            HashicorpVaultCAConfig config = null;
            try
            {
                var serializedConfig = JsonSerializer.Serialize(connectionInfo);

                logger.LogTrace($"deserializing the configuration values into the HashicorpVaultCAConfig object: {serializedConfig}");

                config = JsonSerializer.Deserialize<HashicorpVaultCAConfig>(JsonSerializer.Serialize(connectionInfo));
            }
            catch (Exception ex)
            {
                logger.LogError($"There was an error deserializing the configuration values.  {ex.Message}");
            }

            logger.LogTrace("initializing the Vault client with the configuration parameters.");
            _client = new HashicorpVaultClient(config);

            try
            {
                logger.LogTrace("making an authenticated request to the Vault server to verify credentials (listing role names)..");
                var roleNames = await _client.GetRoleNamesAsync();
                logger.LogTrace($"success: received response containing {roleNames.Count()} role names");
            }
            catch (Exception ex)
            {
                logger.LogError($"Authenticated request failed.  {ex.Message}");
                throw;
            }
            finally { logger.MethodExit(); }
        }

        /// <summary>
        /// Validates that the product information for the CA is correct
        /// </summary>
        /// <param name="productInfo">The product information.</param>
        /// <param name="connectionInfo">The CA connection information.</param>
        public Task ValidateProductInfo(EnrollmentProductInfo productInfo, Dictionary<string, object> connectionInfo)
        {
            logger.MethodEntry();
            List<string> errors = new List<string>();

            HashicorpVaultCATemplateConfig templateConfig = null;
            HashicorpVaultCAConfig caConfig = null;
            // deserialize the values
            try
            {
                templateConfig = JsonSerializer.Deserialize<HashicorpVaultCATemplateConfig>(JsonSerializer.Serialize(productInfo));
                caConfig = JsonSerializer.Deserialize<HashicorpVaultCAConfig>(JsonSerializer.Serialize(connectionInfo));
                logger.LogTrace("successfully deserialized the product and CA config values.");
            }
            catch (Exception ex)
            {
                logger.LogError($"failed to deserialize configuration values.  Please make sure the format is correct.");
                logger.LogError(LogHandler.FlattenException(ex));
                throw;
            }

            if (string.IsNullOrEmpty(productInfo.ProductParameters[Constants.TemplateConfig.ROLENAME] as string))
            {
                errors.Add($"The '{Constants.TemplateConfig.ROLENAME}' is required.");
            }

            // if any errors, throw
            if (errors.Any())
            {
                throw new AnyCAValidationException(string.Join("\n", errors));
            }

            return Task.CompletedTask;
        }

        /// <summary>
        /// Gets annotations for the CA connector properties.
        /// </summary>
        /// <returns></returns>
        public Dictionary<string, PropertyConfigInfo> GetCAConnectorAnnotations()
        {
            return new Dictionary<string, PropertyConfigInfo>()
            {
                [Constants.CAConfig.HOST] = new PropertyConfigInfo()
                {
                    Comments = "The hostname URI of the Hashicorp Vault server relative to this gateway host",
                    Hidden = false,
                    DefaultValue = "https://<my-vault-instance>:<port>",
                    Type = "String"
                },
                [Constants.CAConfig.NAMESPACE] = new PropertyConfigInfo()
                {
                    Comments = "Default namespace to use in the path to the Vault PKI secrets engine (Vault Enterprise only).  This will only be used if there is no value for Namespace in the Template Parameters.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.CAConfig.MOUNTPOINT] = new PropertyConfigInfo()
                {
                    Comments = "The mount point of the PKI secrets engine.",
                    Hidden = false,
                    DefaultValue = "pki",
                    Type = "String"
                },
                [Constants.CAConfig.TOKEN] = new PropertyConfigInfo()
                {
                    Comments = "The default authentication token to use when authenticating into Vault if no value is set in the Template configuration.  If present, this will be used instead of Client Cert for authenticating into Vault.",
                    Hidden = true,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.CAConfig.CLIENTCERT] = new PropertyConfigInfo()
                {
                    Comments = "The client certificate information used to authenticate with Vault (if configured to use certificate authentication). This can be either a Windows cert store name and location (e.g. 'My' and 'LocalMachine' for the Local Computer personal cert store) and thumbprint, or a PFX file and password.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "ClientCertificate"
                },
                [Constants.CAConfig.ENABLED] = new PropertyConfigInfo()
                {
                    Comments = "Flag to Enable or Disable gateway functionality. Disabling is primarily used to allow creation of the CA prior to configuration information being available.",
                    Hidden = false,
                    DefaultValue = true,
                    Type = "Boolean"
                }
            };
        }

        /// <summary>
        /// Gets annotations for the template mapping parameters
        /// </summary>
        /// <returns></returns>
        public Dictionary<string, PropertyConfigInfo> GetTemplateParameterAnnotations()
        {
            return new Dictionary<string, PropertyConfigInfo>()
            {
                [Constants.TemplateConfig.ROLENAME] = new PropertyConfigInfo()
                {
                    Comments = "REQUIRED: Vault PKI Role Name corresponding to this template.",
                    Hidden = false,
                    DefaultValue = "PKI Secrets Engine Role Name",
                    Type = "String"
                },
                [Constants.TemplateConfig.NAMESPACE] = new PropertyConfigInfo()
                {
                    Comments = "OPTIONAL: The namespace of the path to the PKI engine (Vault Enterprise); use only if different than the Namespace set in the Connector configuration",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                }
            };
        }

        /// <summary>
        /// The product id's typically correspond to certificate types (TLS, Client Auth, etc.)
        /// In the case of Hashicorp Vault, there aren't built-in product ID's.  We are using the PKI Role name.
        /// </summary>
        /// <returns></returns>
        public List<string> GetProductIds()
        {
            logger.MethodEntry();
            // Initialize should have been called in order to populate the caConfig and create the client.
            try
            {
                var roleNames = _client.GetRoleNamesAsync().Result;
                logger.LogTrace("got role names from vault: ");
                foreach (var name in roleNames)
                {
                    logger.LogTrace(name);
                }
                return roleNames;
            }
            catch (Exception ex)
            {
                logger.LogError($"Error retreiving role names: {ex.Message}");
                throw;
            }
            finally { logger.MethodExit(); }
        }

        #region Helper Methods

        private static string ParseSubject(string subject, string rdn)
        {
            string escapedSubject = subject.Replace("\\,", "|");
            string rdnString = escapedSubject.Split(',').ToList().Where(x => x.Contains(rdn)).FirstOrDefault();

            if (!string.IsNullOrEmpty(rdnString))
            {
                return rdnString.Replace(rdn, "").Replace("|", ",").Trim();
            }
            else
            {
                throw new Exception($"The request is missing a {rdn} value");
            }
        }
        private static string GetSerialFromTrackingId(string trackingId)
        {
            // to convert to a vault certificate serial number, we need to split into 2 characters and rejoin with ":" between each.            
            var serialParts = trackingId.Chunk(2).ToList();
            return String.Join(":", serialParts);
        }
        private static string GetTrackingIdFromSerial(string serialNumber)
        {
            // vault certificate serial numbers are formatted like this: 17:67:16:b0:b9:45:58:c0:3a:29:e3:cb:d6:98:33:7a:a6:3b:66:c1
            // we simply remove the ":"'s to convert to tracking ID
            return serialNumber.Replace(":", "");
        }

        #endregion Helper Methods
    }
}