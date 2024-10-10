using CAProxy.AnyGateway.Models;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using VaultSharp;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.Cert;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.Commons;
using VaultSharp.V1.SecretsEngines.PKI;

namespace Keyfactor.Extensions.AnyGateway.HashicorpVault.Client
{
    public class HashicorpVaultClient
    {
        private VaultClient _vaultClient { get; set; }
        private static readonly ILogger logger = Logging.LogHandler.GetClassLogger<HashicorpVaultClient>();
        private string _mountPoint { get; set; }

        public HashicorpVaultClient(HashicorpVaultCAConfig config)
        {
            logger.MethodEntry();
            X509Certificate2 clientCert = null;
            IAuthMethodInfo authMethod = null;
            _mountPoint = config.MountPoint;
            if (config.Token != null)
            {
                logger.LogTrace("Token is present in config and will be used for authentication to Vault");
                authMethod = new TokenAuthMethodInfo(config.Token);
            }
            else
            {
                logger.LogTrace("No Token is present in the config.  Checking for certificate info for authentication");

                if (!string.IsNullOrEmpty(config.ClientCertificate?.Thumbprint))
                {
                    logger.LogTrace("Thumbprint is present in config.  Retreiving cert for authentication from store");
                    //Cert auth, cert in Windows store
                    string thumbprint = config.ClientCertificate.Thumbprint;

                    if (!Enum.TryParse(config.ClientCertificate.StoreName, out StoreName sn) || !Enum.TryParse(config.ClientCertificate.StoreLocation, out StoreLocation sl))
                    {
                        logger.LogError($"Both store name and store location values are needed to retreive the cert from the store.  Values from configuration - StoreName: {config.ClientCertificate.StoreName}, StoreLocation: {config.ClientCertificate.StoreLocation}");
                        throw new MissingFieldException("Unable to find client authentication certificate");
                    }

                    X509Certificate2Collection foundCerts;
                    using (X509Store currentStore = new X509Store(sn, sl))
                    {
                        logger.LogTrace($"Search for client auth certificates with Thumbprint {thumbprint} in the {sn}{sl} certificate store");

                        currentStore.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                        foundCerts = currentStore.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, true);
                        logger.LogTrace($"Found {foundCerts.Count} certificates in the {currentStore.Name} store");
                        currentStore.Close();
                    }
                    if (foundCerts.Count > 1)
                    {
                        throw new Exception($"Multiple certificates with Thumprint {thumbprint} found in the {sn}{sl} certificate store");
                    }
                    if (foundCerts.Count > 0)
                        clientCert = foundCerts[0];
                }
                else if (!string.IsNullOrEmpty(config.ClientCertificate.CertificatePath))
                {
                    logger.LogTrace($"CertificatePath is present in config.  Will attempt to read cert from {config.ClientCertificate.CertificatePath}");
                    //Cert auth, cert in pfx file
                    try
                    {
                        X509Certificate2 cert = new X509Certificate2(config.ClientCertificate.CertificatePath, config.ClientCertificate.CertificatePassword);
                        clientCert = cert;
                    }
                    catch (Exception ex)
                    {
                        throw new Exception($"Unable to open the client certificate file with the given password. Error: {ex.Message}");
                    }
                }
                if (clientCert != null)
                {
                    authMethod = new CertAuthMethodInfo(clientCert);
                }
            }

            if (authMethod == null) throw new MissingFieldException($"Neither token or certificate data are present in the configuration.  Unable to configure Vault Authentication.");

            _vaultClient = new VaultClient(new VaultClientSettings(config.Host, authMethod));

            logger.MethodExit();
        }


        public async Task<Secret<SignedCertificateData>> SignCSR(string csr, string subject, Dictionary<string, string[]> san, string roleName)
        {

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
        }




        // example using vaultsharp:
        // var signCertificateRequestOptions = new SignCertificateRequestOptions { // initialize };
        // Secret<SignedCertificateData> certSecret = await vaultClient.V1.Secrets.PKI.SignCertificateAsync(pkiRoleName, signCertificateRequestOptions);
        // string certificateContent = certSecret.Data.CertificateContent;
    }
}