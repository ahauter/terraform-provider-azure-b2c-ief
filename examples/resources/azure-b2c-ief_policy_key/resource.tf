# Generate a new RSA key for signing
resource "azure_b2c_ief_policy_key" "token_signing" {
  name  = "B2C_1A_TokenSigningKeyContainer"
  usage = "sig"

  generate = {
    type = "RSA"
  }
}

# Upload a secret for Facebook integration
resource "azure_b2c_ief_policy_key" "facebook_secret" {
  name  = "B2C_1A_FacebookSecret"
  usage = "sig"

  upload = {
    value         = var.facebook_client_secret
    value_version = 1
  }
}
