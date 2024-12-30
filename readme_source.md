# Introduction
This AnyGateway plug-in enables issuance, revocation, and synchronization of certificates from the Hashicorp Vault PKI Secrets Engine.  

# Hashicorp Vault Authentication
Currently this plug-in only supports authentication into Vault via Token.  

# Prerequisites
1. An instance of Hashicorp Vault v10.5+ that is accessible from the CA Gateway host
1. An instance of the CA Gateway Framework (REST version)

## Certificate Chain

In order to enroll for certificates the Keyfactor Command server must trust the trust chain. Once you create your Root and/or Subordinate CA, make sure to import the certificate chain into the AnyGateway and Command Server certificate store


# Installation

## Requirements
Make sure the following information is available, as it will be needed to complete the installation.

- The fully qualified URI of the instance of Hashicorp Vault
- The namespace and mountpoint of the instance of the PKI secrets engine running in Vault
- An authentication token that has sufficient authority to perform operations on the PKI Secrets engine
- PKI Secrets Engine Roles defined that will correspond to certificate templates to be used when signing certificates with the CA.

### Steps

1. Install the AnyCA Gateway Rest per the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/InstallIntroduction.htm).
1. Download latest successful build from [GitHub Releases](https://github.com/Keyfactor/hashicorp-vault-caplugin/releases/latest)
1. Copy the contents of the release zip file into the (AnyGatewayRest Installation Folder)\AnyGatewayREST\net6.0\Extensions AnyGateway directory.
1. The _manifest.json_ tells the Gateway how to locate our plugin.  It should be copied to the *Connectors* sub-folder in the AnyCA Gateway Rest installation path. 
1. Restart the gateway service.
1. Navigate to the AnyCA Gateway Rest portal and verify that the Gateway recognizes the Hashicorp Vault CA plugin by hovering over the ⓘ symbol to the right of the Gateway name.

#### _manifest.json_
```json
{
  "extensions": {
    "Keyfactor.AnyGateway.Extensions.IAnyCAPlugin": {
      "HashicorpVaultCAPlugin": {
        "assemblypath": "../HashicorpVaultCAPlugin.dll",
        "TypeFullName": "Keyfactor.Extensions.CAPlugin.HashicorpVault.HashicorpVaultCAConnector"
      }
    }
  }
}
```

# Configuration

1. Follow the [official AnyCA Gateway REST documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Gateway.htm) to define a new Certificate Authority, and use the notes below to configure the **Gateway Registration** and **CA Connection** tabs:

### Configure the CA in the AnyCA Gateway Rest Portal 


* **Gateway Registration**

    In order to enroll for certificates the Keyfactor Command server must trust the trust chain. Once you know your Root and/or Subordinate CA in your Hashicorp Vault instance, make sure to download and import the certificate chain into the Command Server certificate store

    Once the necessary files are copied to the appropriate locations and the AnyCA Gateway Rest is up and running, navigate to the AnyCA Gateway Rest portal and configure the CA. 

* **CA Connection**

    Populate using the configuration fields collected in the [requirements](##requirements) section.

    * **Host** - The fully qualified URI including port for the instance of vault.  ex: https://127.0.0.1:8001 
    * **Namespace** - If you are utilizing Vault Namespaces (Enterprise feature); the namespace containing the PKI secrets engine containing your CA.
    * **MountPoint** - The mount point of the PKI secrets engine. 
    * **Token** - The token that will be used by the gateway for authentication.  It should have policies defined that ensure it can perform operations on the path defined by `<host>/<namespace>/<mount point>`
    * **Enabled** - Flag to Enable or Disable gateway functionality. Disabling is primarily used to allow creation of the CA prior to configuration information being available. 


* **Template mapping**

    The product ID's correspond to the role names in the Hashicorp Vault PKI Secrets engine. After the certificate profile is associated with the product ID and imported as a certificate template into Command, requests for certificates will pass the associated role name as part of the request and the issuance policies defined in Vault for that role will be applied as if you were issuing the certificates directly from Vault.
 
    In order to create create the certificate templates associated with the role names once the CA has been defined in the gateway portal, follow these steps:
    
    1. navigate to the "Certificate Profiles" tab
    1. Create an entry for each of the PKI secrets engine roles you would like to use for issuing certificates from the Hashicorp Vault CA.          
    1. Navigate to the "Certificate Authorities" tab and click "Edit"
    1. In the "Edit CA" window, navigate to the "Templates" tab.
    1. Create an association between each of the certificate profiles we just created with the PKI secrets engine roles retreived from Vault.
    
### Configure the CA in Keyfactor Command

Now that the AnyCA Gateway Rest is configured with the details of our Hashicorp Vault hosted CA, we will need to define the CA in Keyfactor Command

* **Certificate Authorities**
    1. Log into Keyfactor Command with an account that has sufficient permissions to define a new Certificate Authorities.
    1. Navigate to "Locations > Certificate Authorities"  
    1. If the AnyCA Gateway Rest host is Active Directory joined with Command
        1. click "Import" to automatically load the details from the Gateway
    1. If not Active Directory domain joined, click "Add" in order to manually fill in the details
        * **Basic**
            1. **Logical Name**: The logical name of the CA, as defined in the Gateway Portal.
            1. **Host URL**: The host url of the instance of the AnyCA Gateway Rest.  This will be the same URL you use to navigate to the Gateway Portal 
            1. **Configuration Tenant**: this can be any name.  It is used by Command to create an Active Directory tenant for the CA.
            1. Fill in the rest of the details according to your requirements 
        
        * **Authorization Methods**        
        You will need to have the PFX certificate, including private key, for Keyfactor Command to use when authenticating into the Gateway.  This should be the certificate associated with the identifier (thumbprint or serial number) that was provided when the Gateway was installed.
            1. Click the "Select authentication certificate" button and choose this PFX file, enter the password if prompted.    
            1. Click "Save and Test" in order to save the configuration and see the result of Command attempting to authenticate.



### Troubleshooting

When troubleshooting the Gateway configuration, the log files can be very useful.  They are located in the "logs" sub-folder in the gateway installation path.

1. Authentication into the Gateway Portal fails

    - Make sure that the authentication certificate with private key is installed into the "Current User > Personal" certificate store
    - If you are seeing an error that indicates the gateway is unable to check the CRL for the certificate..
      - make sure the CRL endpoint is defined on the CA in Vault
      - If no CRL is available, you can turn off the CRL check on the authentication certificate by the Gateway thusly:
        - stop the Gateway service on the host
        - edit the "appsettings.json" file in the Gateway installation directory
        - Change the value of "CheckClientCRL" to "False"
        - Restart the gateway
        - re-attempt login

1. If an error response is returned when attempting to sign or issue certificates via the CA in Command
    - Check the CA_Gateway_Log.txt file in the "logs" subfolder of the Gateway installation path
    - Make sure that the Vault PKI Role policies allow issuing certificates with the defined values


