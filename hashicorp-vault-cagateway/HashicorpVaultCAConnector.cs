using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Logging;
using Keyfactor.PKI.Enums.EJBCA;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace Keyfactor.Extensions.CAPlugin.HashicorpVault
{
    public class HashicorpVaultCAConnector : IAnyCAPlugin
    {
        private readonly ILogger logger;
        private HashicorpVaultCAConfig Config { get; set; }
        private HashicorpVaultClient _client { get; set; }
        private ICertificateDataReader _certificateDataReader;

        public HashicorpVaultCAConnector()
        {
            logger = Logging.LogHandler.GetClassLogger<HashicorpVaultCAConnector>();
        }

        /// <summary>
        /// Initialize the <see cref="HashicorpVaultCAConnector"/>
        /// </summary>
        /// <param name="configProvider">The config provider contains information required to connect to the CA.</param>
        public void Initialize(IAnyCAPluginConfigProvider configProvider, ICertificateDataReader certificateDataReader)
        {
            logger.MethodEntry(LogLevel.Trace);
            string rawConfig = JsonConvert.SerializeObject(configProvider.CAConnectionData);
            logger.LogTrace($"serialized config: {rawConfig}");
            Config = JsonConvert.DeserializeObject<HashicorpVaultCAConfig>(rawConfig);
            _client = new HashicorpVaultClient(Config);
            logger.MethodExit(LogLevel.Trace);
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
                logger.LogDebug("Parse subject for Common Name");
                string commonName = ParseSubject(subject, "CN=");
                logger.LogTrace($"Common Name: {commonName}");
                //var vaultHost = Config.Host;
                var vaultRole = productInfo.ProductParameters[Constants.TemplateConfig.ROLENAME];
                //var secretEnginePath = Config.MountPoint;

                var res = await _client.SignCSR(csr, subject, san, vaultRole);

                return new EnrollmentResult()
                {
                    CARequestID = GetTrackingIdFromSerial(res.Data.SerialNumber),
                    Status = (int)EndEntityStatus.NEW,
                    StatusMessage = $"Successfully enrolled for certificate {subject}",
                    Certificate = res.Data.CertificateContent
                };
            }

            catch (Exception ex)
            {
                logger.LogError($"Error when performing enrollment: {ex.Message}");
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

                var result = new AnyCAPluginCertificate
                {
                    CARequestID = caRequestID,
                    Certificate = cert.Data.CertificateContent,
                    //TODO: get status.  Not available in this version of VaultSharp.  Pending issue https://github.com/rajanadar/VaultSharp/issues/366
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
            throw new NotImplementedException();
        }

        /// <summary>
        /// Validates that the CA connection info is correct.
        /// </summary>
        /// <param name="connectionInfo">The information used to connect to the CA.</param>
        public async Task ValidateCAConnectionInfo(Dictionary<string, object> connectionInfo)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Validates that the product information for the CA is correct
        /// </summary>
        /// <param name="productInfo">The product information.</param>
        /// <param name="connectionInfo">The CA connection information.</param>
        public async Task ValidateProductInfo(EnrollmentProductInfo productInfo, Dictionary<string, object> connectionInfo)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Returns the default CA connector section of the config file.
        /// </summary>
        /// <returns></returns>
        public Dictionary<string, object> GetDefaultCAConnectorConfig()
        {
            return new Dictionary<string, object>()
            {
            };
        }

        /// <summary>
        /// Gets the default comment on the default product type.
        /// </summary>
        /// <returns></returns>
        public string GetProductIDComment()
        {
            return "";
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
                    Comments = "The client certificate information used to authenticate with Vault (if configured to use certificate authentication). This can be either a Windows cert store name and location (e.g. 'My' and 'LocalMachine' for the Local Computer personal cert store) and thumbprint, or a PFX file and password.",
                    Hidden = false,
                    DefaultValue = "https://<my-vault-instance",
                    Type = "String"
                },
                [Constants.CAConfig.NAMESPACE] = new PropertyConfigInfo()
                {
                    Comments = "Default namespace to use in the path to the Vault PKI secrets engine (Vault Enterprise only).  This will only be used if there is no value for Namespace in the Template Parameters.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                [Constants.CAConfig.MOUNTPOINT] = new PropertyConfigInfo()
                {
                    Comments = "The mount point of the PKI secrets engine.",
                    Hidden = true,
                    DefaultValue = "pki",
                    Type = "String"
                },
                [Constants.CAConfig.TOKEN] = new PropertyConfigInfo()
                {
                    Comments = "The default authentication token to use when authenticating into Vault if no value is set in the Template configuration.  If present, this will be used instead of Client Cert for authenticating into Vault.",
                    Hidden = true,
                    DefaultValue = "",
                    Type = "String"
                },
                [Constants.CAConfig.CLIENTCERT] = new PropertyConfigInfo()
                {
                    Comments = "The client certificate information used to authenticate with Vault (if configured to use certificate authentication). This can be either a Windows cert store name and location (e.g. 'My' and 'LocalMachine' for the Local Computer personal cert store) and thumbprint, or a PFX file and password.",
                    Hidden = false,
                    DefaultValue = "",
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
                [Constants.TemplateConfig.NAMESPACE] = new PropertyConfigInfo()
                {
                    Comments = "OPTIONAL: The namespace of the path to the PKI engine (Vault Enterprise).  If missing, will use the value set in the CA Connector configuration.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                [Constants.TemplateConfig.ROLENAME] = new PropertyConfigInfo()
                {
                    Comments = "Required Vault PKI Role Name corresponding to this template.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },

                [Constants.TemplateConfig.TOKEN] = new PropertyConfigInfo()
                {
                    Comments = "OPTIONAL: The default authentication token to use when authenticating into Vault if no value is set in the Template configuration.  If present, this will be used instead of Client Cert for authenticating into Vault.",
                    Hidden = true,
                    DefaultValue = "",
                    Type = "String"
                },
                [Constants.TemplateConfig.CLIENTCERT] = new PropertyConfigInfo()
                {
                    Comments = "OPTIONAL: The client certificate information used to authenticate with Vault (if configured to use certificate authentication). This can be either a Windows cert store name and location (e.g. 'My' and 'LocalMachine' for the Local Computer personal cert store) and thumbprint, or a PFX file and password.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "ClientCertificate"
                },
            };
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

        Task<AnyCAPluginCertificate> IAnyCAPlugin.GetSingleRecord(string caRequestID)
        {
            throw new NotImplementedException();
        }

        Task<int> IAnyCAPlugin.Revoke(string caRequestID, string hexSerialNumber, uint revocationReason)
        {
            throw new NotImplementedException();
        }

        Task IAnyCAPlugin.Ping()
        {
            throw new NotImplementedException();
        }

        Task IAnyCAPlugin.ValidateCAConnectionInfo(Dictionary<string, object> connectionInfo)
        {
            throw new NotImplementedException();
        }

        Task IAnyCAPlugin.ValidateProductInfo(EnrollmentProductInfo productInfo, Dictionary<string, object> connectionInfo)
        {
            throw new NotImplementedException();
        }

        public List<string> GetProductIds()
        {
            throw new NotImplementedException();
        }

        #endregion Helper Methods
    }
}