# Test configuration for generated policy key
resource "azure_b2c_ief_policy_key" "test_generated" {
  name  = "TestGeneratedKey"
  usage = "sig"
  generate {
    type = "RSA"
  }
}