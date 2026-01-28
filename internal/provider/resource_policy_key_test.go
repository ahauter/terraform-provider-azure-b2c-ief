package provider

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func testAccPreCheck(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC environment variable not set - skipping acceptance tests")
	}

	requiredVars := []string{"AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"}
	for _, envVar := range requiredVars {
		if os.Getenv(envVar) == "" {
			t.Fatalf("Required environment variable %s is not set", envVar)
		}
	}
}

func testAccProtoV6ProviderFactories() map[string]func() (tfprotov6.ProviderServer, error) {
	return map[string]func() (tfprotov6.ProviderServer, error){
		"azure-b2c-ief": func() (tfprotov6.ProviderServer, error) {
			serverFunc := providerserver.NewProtocol6(New())
			return serverFunc(), nil
		},
	}
}

func getTimestamp() int {
	return int(time.Now().Unix())
}

func TestAccPolicyKey_BasicCreate(t *testing.T) {
	resourceName := "azure_b2c_ief_policy_key.acc_test_basic"
	rName := fmt.Sprintf("acc-basic-key-%d", getTimestamp())

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccCheckPolicyKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyKeyConfig_basic(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPolicyKeyExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "usage", "sig"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckNoResourceAttr(resourceName, "upload.value"), // Ensure write-only field is not stored
				),
			},
		},
	})
}

func TestAccPolicyKey_GenerateRSA(t *testing.T) {
	resourceName := "azure_b2c_ief_policy_key.acc_test_generated"
	rName := fmt.Sprintf("acc-generated-key-%d", getTimestamp())

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccCheckPolicyKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyKeyConfig_generated(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPolicyKeyExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "usage", "sig"),
					resource.TestCheckResourceAttr(resourceName, "generate.type", "RSA"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckNoResourceAttr(resourceName, "upload"),       // Generated keys shouldn't have upload block
					resource.TestCheckNoResourceAttr(resourceName, "upload.value"), // Ensure no upload field
				),
			},
		},
	})
}

func TestAccPolicyKey_Import(t *testing.T) {
	resourceName := "azure_b2c_ief_policy_key.test_import"
	rName := fmt.Sprintf("acc-import-key-%d", getTimestamp())

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccCheckPolicyKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyKeyConfig_basic(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPolicyKeyExists(resourceName),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"upload.value", // Write-only field
				},
			},
		},
	})
}

func TestAccPolicyKey_WriteOnlyValueNotInState(t *testing.T) {
	resourceName := "azure_b2c_ief_policy_key.test_writeonly"
	rName := fmt.Sprintf("acc-writeonly-%d", getTimestamp())

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccCheckPolicyKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyKeyConfig_writeOnly(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPolicyKeyExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "usage", "sig"),
					resource.TestCheckNoResourceAttr(resourceName, "upload.value"),            // Ensure write-only field is not stored
					resource.TestCheckResourceAttr(resourceName, "upload.value_version", "1"), // But version should be stored
				),
			},
			{
				// Test that after reading, write-only value is still not in state
				Config: testAccPolicyKeyConfig_writeOnly(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPolicyKeyExists(resourceName),
					resource.TestCheckNoResourceAttr(resourceName, "upload.value"), // Still should not be in state
				),
			},
		},
	})
}

func TestAccPolicyKey_WriteOnlyVersionTracking(t *testing.T) {
	resourceName := "azure_b2c_ief_policy_key.test_version"
	rName := fmt.Sprintf("acc-version-%d", getTimestamp())

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccCheckPolicyKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyKeyConfig_versionTracking(rName, 1),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPolicyKeyExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "upload.value_version", "1"),
					resource.TestCheckNoResourceAttr(resourceName, "upload.value"),
				),
			},
			{
				Config: testAccPolicyKeyConfig_versionTracking(rName, 2),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPolicyKeyExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "upload.value_version", "2"),
					resource.TestCheckNoResourceAttr(resourceName, "upload.value"),
				),
			},
		},
	})
}

// Test configuration functions

func testAccPolicyKeyConfig_basic(rName string) string {
	return fmt.Sprintf(`
resource "azure_b2c_ief_policy_key" "acc_test_basic" {
  name  = "%s"
  usage = "sig"
  upload {
    value         = "test-secret-api-key-basic"
    value_version = 1
  }
}
`, rName)
}

func testAccPolicyKeyConfig_generated(rName string) string {
	return fmt.Sprintf(`
resource "azure_b2c_ief_policy_key" "acc_test_generated" {
  name  = "%s"
  usage = "sig"
  generate {
    type = "RSA"
  }
}
`, rName)
}

func testAccPolicyKeyConfig_writeOnly(rName string) string {
	return fmt.Sprintf(`
resource "azure_b2c_ief_policy_key" "test_writeonly" {
  name  = "%s"
  usage = "sig"
  upload {
    value         = "super-secret-write-only-test"
    value_version = 1
  }
}
`, rName)
}

func testAccPolicyKeyConfig_versionTracking(rName string, version int64) string {
	return fmt.Sprintf(`
resource "azure_b2c_ief_policy_key" "test_version" {
  name  = "%s"
  usage = "sig"
  upload {
    value         = "super-secret-version-test"
    value_version = %d
  }
}
`, rName, version)
}

// Check functions

func testAccCheckPolicyKeyExists(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("Not found: %s", resourceName)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("No Policy Key ID is set")
		}

		return nil
	}
}

func TestAccPolicyKey_WriteOnlyValueUpdateWithNoChange(t *testing.T) {
	// This test specifically reproduces the bug where upload.value leaks into state
	// during updates where no actual upload occurs (same version)
	resourceName := "azure_b2c_ief_policy_key.test_writeonly_update"
	rName := fmt.Sprintf("acc-writeonly-update-%d", getTimestamp())

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccCheckPolicyKeyDestroy,
		Steps: []resource.TestStep{
			{
				// Step 1: Create resource with upload value
				Config: testAccPolicyKeyConfig_writeOnlyUpdate(rName, 1),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPolicyKeyExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "usage", "sig"),
					resource.TestCheckNoResourceAttr(resourceName, "upload.value"),            // Should not be in state
					resource.TestCheckResourceAttr(resourceName, "upload.value_version", "1"), // But version should be stored
				),
			},
			{
				// Step 2: Update with SAME version (no upload should happen)
				// This is the critical test case that previously failed
				Config: testAccPolicyKeyConfig_writeOnlyUpdate(rName, 1),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPolicyKeyExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "usage", "sig"),
					resource.TestCheckResourceAttr(resourceName, "upload.value_version", "1"), // Version preserved
					resource.TestCheckNoResourceAttr(resourceName, "upload.value"),            // MUST still be null!
				),
			},
			{
				// Step 3: Update with different version (upload should happen)
				Config: testAccPolicyKeyConfig_writeOnlyUpdate(rName, 2),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPolicyKeyExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "usage", "sig"),
					resource.TestCheckResourceAttr(resourceName, "upload.value_version", "2"), // Version updated
					resource.TestCheckNoResourceAttr(resourceName, "upload.value"),            // MUST still be null!
				),
			},
		},
	})
}

func TestAccPolicyKey_LegacyStateCleanup(t *testing.T) {
	// This test specifically tests legacy state cleanup without needing Azure credentials
	// It simulates the scenario where existing state has secrets from previous buggy version
	t.Run("LegacyStateSanitization", func(t *testing.T) {
		// Simulate legacy state data with stored secret (from buggy provider)
		legacyState := PolicyKeyModel{
			ID:    types.StringValue("legacy-key-id"),
			Name:  types.StringValue("LegacyTestKey"),
			Usage: types.StringValue("sig"),
			Upload: &PolicyKeyUpload{
				Value:        types.StringValue("legacy-secret-stored-in-state"), // Should not be here!
				ValueVersion: types.Int64Value(1),
			},
		}

		// Verify initial state has the secret
		if legacyState.Upload.Value.IsNull() {
			t.Fatal("Test setup error: legacy state should have non-null upload.value")
		}

		// Call legacy state sanitization (what Read method does)
		sanitizeLegacyState(context.Background(), &legacyState)

		// Verify the secret is cleaned up but version is preserved
		if !legacyState.Upload.Value.IsNull() {
			t.Errorf("Expected upload.value to be null after legacy cleanup, got: %s", legacyState.Upload.Value.ValueString())
		}

		if legacyState.Upload.ValueVersion.ValueInt64() != 1 {
			t.Errorf("Expected version tracking to be preserved as 1, got: %d", legacyState.Upload.ValueVersion.ValueInt64())
		}

		t.Log("✅ Legacy state cleanup test passed: Secret removed, version preserved")
	})

	t.Run("ModernStateNoCleanup", func(t *testing.T) {
		// Test that already-clean state doesn't trigger unnecessary cleanup
		modernState := PolicyKeyModel{
			ID:    types.StringValue("modern-key-id"),
			Name:  types.StringValue("ModernTestKey"),
			Usage: types.StringValue("sig"),
			Upload: &PolicyKeyUpload{
				Value:        types.StringNull(), // Already properly null
				ValueVersion: types.Int64Value(2),
			},
		}

		// Call legacy state sanitization on clean state
		sanitizeLegacyState(context.Background(), &modernState)

		// Verify state remains unchanged
		if !modernState.Upload.Value.IsNull() {
			t.Errorf("Expected upload.value to remain null, got: %s", modernState.Upload.Value.ValueString())
		}

		if modernState.Upload.ValueVersion.ValueInt64() != 2 {
			t.Errorf("Expected version to remain 2, got: %d", modernState.Upload.ValueVersion.ValueInt64())
		}

		t.Log("✅ Modern state test passed: No unnecessary cleanup triggered")
	})
}

func testAccPolicyKeyConfig_writeOnlyUpdate(rName string, version int64) string {
	return fmt.Sprintf(`
resource "azure_b2c_ief_policy_key" "test_writeonly_update" {
  name  = "%s"
  usage = "sig"
  upload {
    value         = "super-secret-write-only-update-test"
    value_version = %d
  }
}
`, rName, version)
}

func testAccCheckPolicyKeyDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "azure_b2c_ief_policy_key" {
			continue
		}

		// Check if resource still exists in Azure B2C
		// This would require a real API call to verify deletion
		// For now, we just check that state is properly cleaned up
		if rs.Primary.ID != "" {
			return fmt.Errorf("Policy Key (%s) still exists in state", rs.Primary.ID)
		}
	}

	return nil
}
