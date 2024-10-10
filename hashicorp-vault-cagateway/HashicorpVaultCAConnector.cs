using CAProxy.AnyGateway;
using CAProxy.AnyGateway.Configuration;
using CAProxy.AnyGateway.Interfaces;
using CAProxy.AnyGateway.Models;
using CAProxy.AnyGateway.Models.Configuration;
using CAProxy.Common;
using CSS.Common.Logging;
using CSS.PKI;
using Keyfactor.Extensions.AnyGateway.HashicorpVault.Client;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.ConstrainedExecution;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using static CAProxy.AnyGateway.Constants;

namespace Keyfactor.Extensions.AnyGateway.HashicorpVault
{
    public class HashicorpVaultCAConnector : BaseCAConnector, ICAConnectorConfigInfoProvider
    {
        #region Fields and Constructors

        private static readonly ILogger logger = Logging.LogHandler.GetClassLogger<HashicorpVaultCAConnector>();

        /// <summary>
        /// Provides configuration information for the <see cref="HashicorpVaultCAConnector"/>
        /// </summary>
        private HashicorpVaultCAConfig Config { get; set; }
        private HashicorpVaultClient _client { get; set; }
        //Define any additional private fields here

        #endregion Fields and Constructors

        #region ICAConnector Methods

        /// <summary>
        /// Initialize the <see cref="HashicorpVaultCAConnector"/>
        /// </summary>
        /// <param name="configProvider">The config provider contains information required to connect to the CA.</param>
        public override void Initialize(ICAConnectorConfigProvider configProvider)
        {
            logger.MethodEntry(LogLevel.Trace);
            string rawConfig = JsonConvert.SerializeObject(configProvider.CAConnectionData);
            logger.LogTrace($"serialized config: {rawConfig}");
            Config = JsonConvert.DeserializeObject<HashicorpVaultCAConfig>(rawConfig);
            _client = new HashicorpVaultClient(Config.Host);

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
        public override EnrollmentResult Enroll(ICertificateDataReader certificateDataReader, string csr, string subject, Dictionary<string, string[]> san, EnrollmentProductInfo productInfo, PKIConstants.X509.RequestFormat requestFormat, RequestUtilities.EnrollmentType enrollmentType)
        {
            logger.MethodEntry(LogLevel.Trace);
            Logger.Info($"Begin {enrollmentType} enrollment for {subject}");
            try
            {
                Logger.Debug("Parse subject for Common Name");
                string commonName = ParseSubject(subject, "CN=");
                Logger.Trace($"Common Name: {commonName}");
                var vaultHost = Config.Host;
                var vaultRole = Config.Role;
                var secretEnginePath = Config.EnginePath;

                var res = _client.SignCSR(csr, subject, san, Config.Role);


                return new EnrollmentResult()
                {
                    CARequestID = res.Data.SerialNumber.Replace("-", "").Replace(":", ""),
                    Status = (int)PKIConstants.Microsoft.RequestDisposition.ISSUED,
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
                logger.MethodExit(LogLevel.Trace);
            }
        }

        /// <summary>
        /// Returns a single certificate record by its serial number.
        /// </summary>
        /// <param name="caRequestID">The CA request ID for the certificate.</param>
        /// <returns></returns>
		public override CAConnectorCertificate GetSingleRecord(string caRequestID)
        {
            // example using vaultsharp:
            // var cert = await vaultClient.V1.Secrets.PKI.ReadCertificateAsync("17:67:16:b0:b9:45:58:c0:3a:29:e3:cb:d6:98:33:7a:a6:3b:66:c1", mountpoint);

            throw new NotImplementedException();
        }

        /// <summary>
        /// Attempts to reach the CA over the network.
        /// </summary>
        public override void Ping()
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Revokes a certificate by its serial number.
        /// </summary>
        /// <param name="caRequestID">The CA request ID.</param>
        /// <param name="hexSerialNumber">The hex-encoded serial number.</param>
        /// <param name="revocationReason">The revocation reason.</param>
        /// <returns></returns>
        public override int Revoke(string caRequestID, string hexSerialNumber, uint revocationReason)
        {
            // example using vaultsharp:
            // Secret<RevokeCertificateResponse> revoke = await vaultClient.V1.Secrets.PKI.RevokeCertificateAsync(serialNumber);

            throw new NotImplementedException();
        }

        /// <summary>
        /// Synchronizes the gateway with the external CA
        /// </summary>
        /// <param name="certificateDataReader">Provides information about the gateway's certificate database.</param>
        /// <param name="blockingBuffer">Buffer into which certificates are places from the CA.</param>
        /// <param name="certificateAuthoritySyncInfo">Information about the last CA sync.</param>
        /// <param name="cancelToken">The cancellation token.</param>
        public override void Synchronize(ICertificateDataReader certificateDataReader, BlockingCollection<CAConnectorCertificate> blockingBuffer, CertificateAuthoritySyncInfo certificateAuthoritySyncInfo, CancellationToken cancelToken)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Validates that the CA connection info is correct.
        /// </summary>
        /// <param name="connectionInfo">The information used to connect to the CA.</param>
        public override void ValidateCAConnectionInfo(Dictionary<string, object> connectionInfo)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Validates that the product information for the CA is correct
        /// </summary>
        /// <param name="productInfo">The product information.</param>
        /// <param name="connectionInfo">The CA connection information.</param>
        public override void ValidateProductInfo(EnrollmentProductInfo productInfo, Dictionary<string, object> connectionInfo)
        {
            throw new NotImplementedException();
        }

        [Obsolete]
        public override EnrollmentResult Enroll(string csr, string subject, Dictionary<string, string[]> san, EnrollmentProductInfo productInfo, PKIConstants.X509.RequestFormat requestFormat, RequestUtilities.EnrollmentType enrollmentType)
        {
            throw new NotImplementedException();
        }

        [Obsolete]
        public override void Synchronize(ICertificateDataReader certificateDataReader, BlockingCollection<CertificateRecord> blockingBuffer, CertificateAuthoritySyncInfo certificateAuthoritySyncInfo, CancellationToken cancelToken, string logicalName)
        {
            throw new NotImplementedException();
        }

        #endregion ICAConnector Methods

        #region ICAConnectorConfigInfoProvider Methods

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
            return new Dictionary<string, PropertyConfigInfo>();
        }

        /// <summary>
        /// Gets annotations for the template mapping parameters
        /// </summary>
        /// <returns></returns>
        public Dictionary<string, PropertyConfigInfo> GetTemplateParameterAnnotations()
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Gets default template map parameters for GlobalSign Atlas product types.
        /// </summary>
        /// <returns></returns>
        public Dictionary<string, string> GetDefaultTemplateParametersConfig()
        {
            throw new NotImplementedException();
        }

        #endregion ICAConnectorConfigInfoProvider Methods

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

        #endregion Helper Methods
    }
}