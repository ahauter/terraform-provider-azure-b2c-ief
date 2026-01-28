# Basic test configuration for policy key upload
resource "azure_b2c_ief_policy_key" "test_basic_upload" {
  name  = "TestBasicUpload"
  usage = "sig"
  upload {
    value         = "test-secret-api-key-basic"
    value_version = 1
  }
}