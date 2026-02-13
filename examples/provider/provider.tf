provider "azure_b2c_ief" {
  tenant_id     = "yourtenant.onmicrosoft.com"
  client_id     = "00000000-0000-0000-0000-000000000000"
  client_secret = var.client_secret
}
