resource "azure_b2c_ief_policy" "signup_signin" {
  file    = "policy.xml"
  publish = true

  app_settings = {
    tenant_name          = "yourtenant"
    ai_connection_string = "InstrumentationKey=00000000-0000-0000-0000-000000000000"
  }
}
