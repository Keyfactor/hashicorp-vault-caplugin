using Org.BouncyCastle.Asn1.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VaultSharp;
using VaultSharp.V1.Commons;
using VaultSharp.V1.SecretsEngines.PKI;

namespace Keyfactor.Extensions.AnyGateway.HashicorpVault.Client
{
    public class HashicorpVaultClient
    {
        private VaultClient _vaultClient { get; set; }

        public HashicorpVaultClient(string vaultServerUri) { 
            _vaultClient = new VaultClient(new VaultClientSettings(vaultServerUri, n) {
            })
        
        }
        public Secret<SignedCertificateData> SignCSR(string csr, string subject, Dictionary<string, string[]> san, string roleName)
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
            reqOptions.TimeToLive = 
        }

        


        // example using vaultsharp:
        // var signCertificateRequestOptions = new SignCertificateRequestOptions { // initialize };
        // Secret<SignedCertificateData> certSecret = await vaultClient.V1.Secrets.PKI.SignCertificateAsync(pkiRoleName, signCertificateRequestOptions);
        // string certificateContent = certSecret.Data.CertificateContent;
    }
}