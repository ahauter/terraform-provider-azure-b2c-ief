terraform {
  required_providers {
    azure_b2c_ief = {
      source  = "ahauter/azure_b2c_ief"
      version = "~> 1.0"
    }
  }
}

provider "azure_b2c_ief" {
  tenant_id     = var.b2c_tenant_id
  client_id     = var.b2c_client_id
  client_secret = var.b2c_client_secret
}

# Generate RSA signing key
resource "azure_b2c_ief_policy_key" "token_signing_key" {
  name  = "B2C_1A_TokenSigningKeyContainer"
  usage = "sig"
  generate {
    type = "RSA"
  }
}

# Upload encryption secret
resource "azure_b2c_ief_policy_key" "encryption_key" {
  name  = "B2C_1A_EncryptionKeyContainer"
  usage = "enc"
  upload {
    value         = var.encryption_secret
    value_version = 1
  }
}

# Base policy with common elements
resource "azure_b2c_ief_policy" "base" {
  file = "../policies/TrustFrameworkBase.xml"
  app_settings = {
    "tenantId" : var.b2c_tenant_id
  }
  publish = true
}

# Sign-up sign-in policy
resource "azure_b2c_ief_policy" "signup_signin" {
  file = "../policies/TrustFrameworkExtensions.xml"
  app_settings = {
    "tenantId" : var.b2c_tenant_id
    "apiClientId" : var.api_client_id
    "apiScope" : var.api_scope
  }
  publish = true
}

variable "b2c_tenant_id" {
  description = "Azure AD B2C tenant ID"
  type        = string
  sensitive   = true
}

variable "b2c_client_id" {
  description = "Azure AD application client ID"
  type        = string
  sensitive   = true
}

variable "b2c_client_secret" {
  description = "Azure AD application client secret"
  type        = string
  sensitive   = true
}

variable "encryption_secret" {
  description = "Encryption secret for B2C policies"
  type        = string
  sensitive   = true
  default     = "your-encryption-secret-here"
}

variable "api_client_id" {
  description = "API application client ID"
  type        = string
  default     = "your-api-client-id"
}

variable "api_scope" {
  description = "API scope for B2C policies"
  type        = string
  default     = "api://your-api/access_as_user"
}

output "policy_keys" {
  description = "Created policy keys"
  value = {
    signing_key_id    = azure_b2c_ief_policy_key.token_signing_key.id
    encryption_key_id = azure_b2c_ief_policy_key.encryption_key.id
  }
}

output "policies" {
  description = "Created policies"
  value = {
    base_policy_id   = azure_b2c_ief_policy.base.id
    signup_signin_id = azure_b2c_ief_policy.signup_signin.id
  }
}