# Introduction
This AnyGateway plug-in enables issuance, revocation, and synchronization of certificates from the Hashicorp Vault PKI Secrets Engine.  

# Hashicorp Vault Authentication
Currently this plug-in only supports Token authentication.  

# Prerequisites
1. An instance of Hashicorp Vault v10.5+ that is accessible from the CA Gateway host
1. An instance of the CA Gateway Framework (REST version)

## Certificate Chain

In order to enroll for certificates the Keyfactor Command server must trust the trust chain. Once you create your Root and/or Subordinate CA, make sure to import the certificate chain into the AnyGateway and Command Server certificate store


# Install
* Download latest successful build from [GitHub Releases](https://github.com/Keyfactor/hashicorp-vault-caplugin/releases/latest)

* Copy the contents of the release zip file into the (AnyGatewayRest Installation Folder)\AnyGatewayREST\net6.0\Extensions AnyGateway directory.
* example path: "C:\Program Files\Keyfactor\HashiVaultCA\AnyGatewayREST\net6.0\Extensions"

* The _manifest.json_ tells the Gateway how to locate our plugin.  It should be copied to the *Connectors* sub-folder in the above path. 

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
The following sections will breakdown the required configurations for the AnyGatewayConfig.json file that will be imported to configure the AnyGateway.

## Templates
The Template section will map the CA's products to an AD template.
* ```ProductID```
This is the ID of the <Product> product to map to the specified template.

 ```json
  "Templates": {
	"WebServer": {
      "ProductID": "<productID>",
      "Parameters": {
      }
   }
}
 ```
 
## Security
The security section does not change specifically for the Hashicorp Vault PKI CA Gateway.  Refer to the AnyGateway Documentation for more detail.
```json
  /*Grant permissions on the CA to users or groups in the local domain.
	READ: Enumerate and read contents of certificates.
	ENROLL: Request certificates from the CA.
	OFFICER: Perform certificate functions such as issuance and revocation. This is equivalent to "Issue and Manage" permission on the Microsoft CA.
	ADMINISTRATOR: Configure/reconfigure the gateway.
	Valid permission settings are "Allow", "None", and "Deny".*/
    "Security": {
        "Keyfactor\\Administrator": {
            "READ": "Allow",
            "ENROLL": "Allow",
            "OFFICER": "Allow",
            "ADMINISTRATOR": "Allow"
        },
        "Keyfactor\\gateway_test": {
            "READ": "Allow",
            "ENROLL": "Allow",
            "OFFICER": "Allow",
            "ADMINISTRATOR": "Allow"
        },		
        "Keyfactor\\SVC_TimerService": {
            "READ": "Allow",
            "ENROLL": "Allow",
            "OFFICER": "Allow",
            "ADMINISTRATOR": "None"
        },
        "Keyfactor\\SVC_AppPool": {
            "READ": "Allow",
            "ENROLL": "Allow",
            "OFFICER": "Allow",
            "ADMINISTRATOR": "Allow"
        }
    }
```
## CerificateManagers
The Certificate Managers section is optional.
	If configured, all users or groups granted OFFICER permissions under the Security section
	must be configured for at least one Template and one Requester. 
	Uses "<All>" to specify all templates. Uses "Everyone" to specify all requesters.
	Valid permission values are "Allow" and "Deny".
```json
  "CertificateManagers":{
		"DOMAIN\\Username":{
			"Templates":{
				"MyTemplateShortName":{
					"Requesters":{
						"Everyone":"Allow",
						"DOMAIN\\Groupname":"Deny"
					}
				},
				"<All>":{
					"Requesters":{
						"Everyone":"Allow"
					}
				}
			}
		}
	}
```
## CAConnection
The CA Connection section will determine the API endpoint and configuration data used to connect to the <Product> API. 


```json
  "CAConnection": {
	"AuthToken":"<auth token value>",
	"ClientCertificate": {
        "StoreName": "My",
        "StoreLocation": "LocalMachine",
        "Thumbprint": "0123456789abcdef"
    },
    "Name": "TestUser",
    "Email": "email@email.invalid",
    "PhoneNumber": "0000000000",
	"IgnoreExpired": "false"
  },
```
## GatewayRegistration
There are no specific Changes for the GatewayRegistration section. Refer to the AnyGateway Documentation for more detail.
```json
  "GatewayRegistration": {
    "LogicalName": "CASandbox",
    "GatewayCertificate": {
      "StoreName": "CA",
      "StoreLocation": "LocalMachine",
      "Thumbprint": "0123456789abcdef"
    }
  }
```

## ServiceSettings
There are no specific Changes for the ServiceSettings section. Refer to the AnyGateway Documentation for more detail.
```json
  "ServiceSettings": {
    "ViewIdleMinutes": 8,
    "FullScanPeriodHours": 24,
	"PartialScanPeriodMinutes": 240 
  }
```
