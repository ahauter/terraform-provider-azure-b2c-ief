# Terraform Provider for Azure AD B2C IEF

[![GitHub Release](https://img.shields.io/github/release/ahauter/terraform-provider-azure-b2c-ief.svg)](https://github.com/ahauter/terraform-provider-azure-b2c-ief/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/ahauter/terraform-provider-azure-b2c-ief)](https://goreportcard.com/report/github.com/ahauter/terraform-provider-azure-b2c-ief)

This Terraform provider manages Azure AD B2C Identity Experience Framework (IEF) policies and cryptographic keys. It enables Infrastructure as Code practitioners to deploy and manage B2C custom policies programmatically.

## Features

- **IEF Policy Management**: Deploy and manage custom policies with XML configuration files
- **Cryptographic Key Management**: Generate RSA keys or upload existing secrets for policy signing and encryption
- **App Settings Injection**: Dynamic replacement of `{settings:KEY_NAME}` placeholders in policy XML
- **Secure Secret Handling**: Write-only secret fields with proper state sanitization
- **Version Management**: Track secret versions for cryptographic keys

## Resources

- **[`azure_b2c_ief_policy`](#resource-azure_b2c_ief_policy)** - Manages B2C IEF custom policies
- **[`azure_b2c_ief_policy_key`](#resource-azure_b2c_ief_policy_key)** - Manages cryptographic keys and secrets

## Requirements

- Terraform >= 1.0
- Go >= 1.24 (for development)
- Azure AD B2C tenant with appropriate permissions
- Azure AD application registration with Graph API access

## Installation

### From Terraform Registry

```hcl
terraform {
  required_providers {
    azure_b2c_ief = {
      source  = "ahauter/azure_b2c_ief"
      version = "~> 1.0"
    }
  }
}
```

### Local Development

```bash
go install .
terraform init -upgrade
```

## Authentication

The provider requires Azure AD credentials to access Microsoft Graph API:

```hcl
provider "azure_b2c_ief" {
  tenant_id     = var.azure_b2c_tenant_id
  client_id     = var.azure_b2c_client_id
  client_secret = var.azure_b2c_client_secret
}
```

### Required Permissions

The Azure AD application needs the following Graph API permissions:
- `Policy.ReadWrite.TrustFramework`
- `Application.ReadWrite.All` (for key management)

## Resources

### Resource: `azure_b2c_ief_policy`

Manages Azure AD B2C IEF custom policies.

#### Example Usage

```hcl
resource "azure_b2c_ief_policy" "signup_signin" {
  file        = "./policies/TrustFrameworkBase.xml"
  app_settings = {
    "clientId": "your-app-client-id",
    "apiUrl": "https://your-api.example.com"
  }
  publish = true
}
```

#### Arguments

- **`file`** (String, Required) - Path to the policy XML file
- **`app_settings`** (Map of String, Required) - Key-value pairs to inject into XML placeholders
- **`publish`** (Boolean, Required) - Whether to publish the policy to B2C tenant

#### Attributes

- **`id`** (String) - The policy ID
- **`xml`** (String, Computed) - The processed XML with settings injected

### Resource: `azure_b2c_ief_policy_key`

Manages cryptographic keys used by B2C IEF policies.

#### Example Usage

```hcl
# Generate a new RSA key
resource "azure_b2c_ief_policy_key" "signing_key" {
  name  = "B2C_1A_SigningKey"
  usage = "sig"
  generate {
    type = "RSA"
  }
}

# Upload an existing secret
resource "azure_b2c_ief_policy_key" "secret_key" {
  name  = "B2C_1A_SecretKey"
  usage = "enc"
  upload {
    value         = "your-secret-value"
    value_version = 1
  }
}
```

#### Arguments

- **`name`** (String, Required) - The key name identifier
- **`usage`** (String, Required) - Key usage: `sig` (signing) or `enc` (encryption)

##### `generate` Block (Optional)

- **`type`** (String, Required) - Key type to generate (currently supports `RSA`)

##### `upload` Block (Optional)

- **`value`** (String, Required, Write-only) - Secret value to upload
- **`value_version`** (Number, Optional) - Version of the secret

#### Attributes

- **`id`** (String) - The key identifier

## App Settings Injection

The provider automatically replaces `{settings:KEY_NAME}` placeholders in policy XML files:

```xml
<ClaimsProvider>
  <DisplayName>Local Account SignIn</DisplayName>
  <TechnicalProfiles>
    <TechnicalProfile Id="SelfAsserted-LocalAccountSignin-Email">
      <Metadata>
        <Item Key="client_id">{settings:clientId}</Item>
        <Item Key="api_endpoint">{settings:apiUrl}</Item>
      </Metadata>
    </TechnicalProfile>
  </TechnicalProfiles>
</ClaimsProvider>
```

## Development

### Building

```bash
make build
```

### Testing

```bash
make test
make testacc
```

### Linting

```bash
make lint
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For issues and questions:

- [GitHub Issues](https://github.com/ahauter/terraform-provider-azure-b2c-ief/issues)
- [Azure AD B2C Documentation](https://docs.microsoft.com/en-us/azure/active-directory-b2c/)
- [Terraform Provider Development](https://www.terraform.io/docs/extend/index.html)