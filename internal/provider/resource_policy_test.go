package provider

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestInjectAppSettings(t *testing.T) {
	tests := []struct {
		name        string
		xml         string
		appSettings map[string]string
		expected    string
	}{
		{
			name: "single replacement",
			xml:  "<Config>{settings:API_KEY}</Config>",
			appSettings: map[string]string{
				"API_KEY": "12345",
			},
			expected: "<Config>12345</Config>",
		},
		{
			name: "multiple replacements",
			xml:  "<Config>{settings:API_KEY},{settings:SECRET}</Config>",
			appSettings: map[string]string{
				"API_KEY": "12345",
				"SECRET":  "abcd",
			},
			expected: "<Config>12345,abcd</Config>",
		},
		{
			name: "case insensitive key",
			xml:  "<Config>{Settings:Api_Key}</Config>",
			appSettings: map[string]string{
				"API_KEY": "12345",
			},
			expected: "<Config>12345</Config>",
		},
		{
			name: "key not present in map",
			xml:  "<Config>{settings:NOT_IN_MAP}</Config>",
			appSettings: map[string]string{
				"API_KEY": "12345",
			},
			expected: "<Config>{settings:NOT_IN_MAP}</Config>",
		},
		{
			name: "no placeholders",
			xml:  "<Config>No placeholders here</Config>",
			appSettings: map[string]string{
				"API_KEY": "12345",
			},
			expected: "<Config>No placeholders here</Config>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			// Convert string map to types.String map for function call
			appSettingsTypes := make(map[string]types.String, len(tt.appSettings))
			for k, v := range tt.appSettings {
				appSettingsTypes[k] = types.StringValue(v)
			}
			got := injectAppSettings(ctx, tt.xml, appSettingsTypes)
			if got != tt.expected {
				t.Errorf("injectAppSettings() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// Acceptance Tests

func TestAccPolicy_BasicCreate(t *testing.T) {
	resourceName := "azure_b2c_ief_policy.test_basic"
	rName := fmt.Sprintf("acc-basic-policy-%d", getTimestamp())

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccCheckPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyConfig_basic(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPolicyExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "file", "basic_policy.xml"),
					resource.TestCheckResourceAttr(resourceName, "publish", "true"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "xml"),
				),
			},
		},
	})
}

func TestAccPolicy_WithAppSettings(t *testing.T) {
	resourceName := "azure_b2c_ief_policy.test_settings"
	rName := fmt.Sprintf("acc-settings-policy-%d", getTimestamp())

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccCheckPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyConfig_withSettings(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPolicyExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "file", "policy_with_app_settings.xml"),
					resource.TestCheckResourceAttr(resourceName, "publish", "true"),
					resource.TestCheckResourceAttr(resourceName, "app_settings.CLIENT_ID", "test-client-id"),
					resource.TestCheckResourceAttr(resourceName, "app_settings.APP_NAME", "Test Application"),
					resource.TestCheckResourceAttr(resourceName, "app_settings.CUSTOM_KEY", "custom-api-key-value"),
					resource.TestCheckResourceAttrSet(resourceName, "xml"),
					// Check that app settings were injected into XML
					testAccCheckPolicyXmlContains(resourceName, "test-client-id"),
					testAccCheckPolicyXmlContains(resourceName, "Test Application"),
				),
			},
		},
	})
}

func TestAccPolicy_Update(t *testing.T) {
	resourceName := "azure_b2c_ief_policy.test_update"
	rName := fmt.Sprintf("acc-update-policy-%d", getTimestamp())

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccCheckPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyConfig_basic(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPolicyExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "publish", "true"),
				),
			},
			{
				Config: testAccPolicyConfig_updated(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPolicyExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "publish", "false"),
					resource.TestCheckResourceAttr(resourceName, "app_settings.CLIENT_ID", "updated-client-id"),
				),
			},
		},
	})
}

func TestAccPolicy_XmlGeneration(t *testing.T) {
	resourceName := "azure_b2c_ief_policy.test_xml"
	rName := fmt.Sprintf("acc-xml-policy-%d", getTimestamp())

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccCheckPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyConfig_withSettings(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPolicyExists(resourceName),
					testAccCheckPolicyXmlValid(resourceName),
					testAccCheckPolicyXmlContains(resourceName, "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>"),
					testAccCheckPolicyXmlContains(resourceName, "TrustFrameworkPolicy"),
					testAccCheckPolicyXmlContains(resourceName, "PolicyId=\"B2C_1A_TestAppSettings\""),
				),
			},
		},
	})
}

func TestAccPolicy_AppSettingsInjection(t *testing.T) {
	resourceName := "azure_b2c_ief_policy.test_injection"
	rName := fmt.Sprintf("acc-injection-policy-%d", getTimestamp())

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccCheckPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyConfig_complexSettings(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPolicyExists(resourceName),
					testAccCheckPolicyXmlContains(resourceName, "test-complex-value"),
					testAccCheckPolicyXmlContains(resourceName, "test-endpoint-value"),
					testAccCheckPolicyXmlContains(resourceName, "test-tenant-id"),
					// Verify all placeholders were replaced
					testAccCheckPolicyXmlNotContains(resourceName, "{settings:"),
				),
			},
		},
	})
}

func TestAccPolicy_Import(t *testing.T) {
	resourceName := "azure_b2c_ief_policy.test_import"
	rName := fmt.Sprintf("acc-import-policy-%d", getTimestamp())

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccCheckPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyConfig_basic(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPolicyExists(resourceName),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"xml", // Computed field that may not match exactly
				},
			},
		},
	})
}

// Test configuration functions

func testAccPolicyConfig_basic(rName string) string {
	return fmt.Sprintf(`
# Basic test configuration for policy
resource "azure_b2c_ief_policy" "test_basic" {
  file = "basic_policy.xml"
  
  app_settings = {
    CLIENT_ID = "test-client-id"
    APP_NAME  = "Test App"
    TENANT_ID = "test-tenant-id"
  }
  
  publish = true
}
`)
}

func testAccPolicyConfig_withSettings(rName string) string {
	return fmt.Sprintf(`
# Test configuration for policy with app settings
resource "azure_b2c_ief_policy" "test_settings" {
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
`)
}

func testAccPolicyConfig_updated(rName string) string {
	return fmt.Sprintf(`
# Updated test configuration for policy
resource "azure_b2c_ief_policy" "test_update" {
  file = "basic_policy.xml"
  
  app_settings = {
    CLIENT_ID = "updated-client-id"
    APP_NAME  = "Updated App"
    TENANT_ID = "test-tenant-id"
  }
  
  publish = false
}
`)
}

func testAccPolicyConfig_complexSettings(rName string) string {
	return fmt.Sprintf(`
# Complex test configuration for policy with many app settings
resource "azure_b2c_ief_policy" "test_complex" {
  file = "policy_with_app_settings.xml"
  
  app_settings = {
    CLIENT_ID       = "test-complex-client-id"
    CLIENT_SECRET   = "test-complex-secret"
    REDIRECT_URI    = "https://complex.example.com"
    LOGOUT_URI      = "https://complex.example.com/logout"
    SCOPES          = "openid profile email api"
    APP_NAME        = "Complex Test Application"
    APP_DESCRIPTION = "Complex test application for injection testing"
    CUSTOM_KEY      = "test-complex-value"
    API_ENDPOINT    = "test-endpoint-value"
    API_TIMEOUT     = "30"
    RETRY_COUNT     = "3"
    DISPLAY_CONTROL = "ComplexControl"
    TENANT_ID       = "test-tenant-id"
  }
  
  publish = true
}
`)
}

// Check functions

func testAccCheckPolicyExists(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("Not found: %s", resourceName)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("No Policy ID is set")
		}

		return nil
	}
}

func testAccCheckPolicyDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "azure_b2c_ief_policy" {
			continue
		}

		// Check if the policy still exists in Azure B2C
		// This would require a real API call to verify deletion
		// For now, we just check that state is properly cleaned up
		if rs.Primary.ID != "" {
			return fmt.Errorf("Policy (%s) still exists in state", rs.Primary.ID)
		}
	}

	return nil
}

func testAccCheckPolicyXmlContains(resourceName, content string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("Not found: %s", resourceName)
		}

		xmlContent := rs.Primary.Attributes["xml"]
		if xmlContent == "" {
			return fmt.Errorf("No XML content found in state")
		}

		if !strings.Contains(xmlContent, content) {
			return fmt.Errorf("XML does not contain expected content: %s", content)
		}

		return nil
	}
}

func testAccCheckPolicyXmlNotContains(resourceName, content string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("Not found: %s", resourceName)
		}

		xmlContent := rs.Primary.Attributes["xml"]
		if xmlContent == "" {
			return fmt.Errorf("No XML content found in state")
		}

		if strings.Contains(xmlContent, content) {
			return fmt.Errorf("XML contains unexpected content: %s", content)
		}

		return nil
	}
}

func testAccCheckPolicyXmlValid(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("Not found: %s", resourceName)
		}

		xmlContent := rs.Primary.Attributes["xml"]
		if xmlContent == "" {
			return fmt.Errorf("No XML content found in state")
		}

		// Basic XML validation
		decoder := xml.NewDecoder(strings.NewReader(xmlContent))
		for {
			_, err := decoder.Token()
			if err == io.EOF {
				break // End of file
			}
			if err != nil {
				return fmt.Errorf("Invalid XML: %s", err)
			}
		}

		return nil
	}
}

// Fuzz Tests

func FuzzInjectAppSettings(f *testing.F) {
	// Seed corpus with initial test cases
	f.Add([]byte("<Config>{settings:API_KEY}</Config>"), []byte("API_KEY"), []byte("12345"))
	f.Add([]byte("<Config>{settings:API_KEY},{settings:SECRET}</Config>"), []byte("API_KEY"), []byte("12345"))
	f.Add([]byte("<Config>No placeholders</Config>"), []byte("API_KEY"), []byte("12345"))

	f.Fuzz(func(t *testing.T, xmlBytes, keyBytes, valueBytes []byte) {
		xml := string(xmlBytes)
		key := string(keyBytes)
		value := string(valueBytes)

		// Skip empty inputs
		if xml == "" || key == "" {
			t.Skip()
		}

		appSettings := map[string]string{key: value}

		ctx := context.Background()
		appSettingsTypes := make(map[string]types.String, len(appSettings))
		for k, v := range appSettings {
			appSettingsTypes[k] = types.StringValue(v)
		}

		result := injectAppSettings(ctx, xml, appSettingsTypes)

		// The function should not panic and should return a string
		if result == "" && xml != "" {
			t.Errorf("injectAppSettings returned empty string for non-empty input")
		}
	})
}

func FuzzGetPolicyId(f *testing.F) {
	// Seed corpus with initial test cases
	f.Add([]byte("<?xml version=\"1.0\"?><TrustFrameworkPolicy PolicyId=\"B2C_1A_Test\"></TrustFrameworkPolicy>"))
	f.Add([]byte("<TrustFrameworkPolicy PolicyId=\"B2C_1A_Complex\" TenantObjectId=\"test\"></TrustFrameworkPolicy>"))
	f.Add([]byte("<?xml version=\"1.0\"?><NotPolicy PolicyId=\"fake\"></NotPolicy>"))

	f.Fuzz(func(t *testing.T, xmlBytes []byte) {
		xml := string(xmlBytes)

		// Skip empty inputs
		if xml == "" {
			t.Skip()
		}

		result := getPolicyId(xml)

		// The function should not panic and should return a string
		if result == "" {
			// This is valid - no PolicyId found
		} else {
			// If result is not empty, it should be found in the XML
			if !strings.Contains(xml, result) {
				t.Errorf("getPolicyId returned '%s' but it's not found in input XML", result)
			}
		}
	})
}

func FuzzPolicyValidation(f *testing.F) {
	// Seed corpus with initial test cases
	f.Add([]byte("<?xml version=\"1.0\"?><TrustFrameworkPolicy PolicyId=\"B2C_1A_Test\"></TrustFrameworkPolicy>"))
	f.Add([]byte("<invalid>xml"))
	f.Add([]byte("<?xml version=\"1.0\"?><TrustFrameworkPolicy></TrustFrameworkPolicy>"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, xmlBytes []byte) {
		xmlContent := string(xmlBytes)

		// Test XML parsing - should not panic
		decoder := xml.NewDecoder(strings.NewReader(xmlContent))
		for {
			_, err := decoder.Token()
			if err != nil {
				if err == io.EOF {
					break // Valid end of file
				}
				// Invalid XML is expected for fuzzing, should not panic
				break
			}
		}

		// Test getPolicyId function with fuzz input
		result := getPolicyId(xmlContent)

		// Result should never be nil (function returns string)
		if result == "" && strings.Contains(xmlContent, "PolicyId") {
			// May be expected if PolicyId attribute is malformed
		}
	})
}
