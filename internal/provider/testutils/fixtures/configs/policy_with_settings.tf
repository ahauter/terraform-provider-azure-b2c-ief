# Test configuration for policy with app settings
resource "azure_b2c_ief_policy" "test_with_settings" {
  file = "policy_with_app_settings.xml"

  app_settings = {
    CLIENT_ID       = "test-client-id"
    CLIENT_SECRET   = "test-client-secret"
    REDIRECT_URI    = "https://jwt.ms/"
    LOGOUT_URI      = "https://jwt.ms/"
    SCOPES          = "openid profile email"
    APP_NAME        = "Test Application"
    APP_DESCRIPTION = "Test application description"
    CUSTOM_KEY      = "custom-api-key-value"
    API_ENDPOINT    = "https://api.example.com"
    DISPLAY_CONTROL = "UnverifiedEmail"
    TENANT_ID       = "test-tenant-id"
  }

  publish = true
}