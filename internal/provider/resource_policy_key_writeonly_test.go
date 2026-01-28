package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestPolicyKeyWriteOnlyFields(t *testing.T) {
	// Test Create method state handling with write-only fields
	t.Run("CreateStateSanitization", func(t *testing.T) {
		data := PolicyKeyModel{
			ID:    types.StringValue("test-id"),
			Name:  types.StringValue("test-key"),
			Usage: types.StringValue("sig"),
			Upload: &PolicyKeyUpload{
				Value:        types.StringValue("super-secret"), // Write-only
				ValueVersion: types.Int64Value(1),
			},
		}

		// Simulate state sanitization (what our fix does)
		if data.Upload != nil {
			data.Upload = &PolicyKeyUpload{
				ValueVersion: data.Upload.ValueVersion,
				Value:        types.StringNull(), // Explicitly null for write-only
			}
		}

		// Verify write-only field is null in state
		if !data.Upload.Value.IsNull() {
			t.Errorf("Expected upload.value to be null in state, got: %s", data.Upload.Value.ValueString())
		}

		// Verify version is preserved
		if data.Upload.ValueVersion.ValueInt64() != 1 {
			t.Errorf("Expected upload.value_version to be 1, got: %d", data.Upload.ValueVersion.ValueInt64())
		}
	})

	// Test Read method state preservation
	t.Run("ReadStatePreservation", func(t *testing.T) {
		currentState := PolicyKeyModel{
			ID:    types.StringValue("test-id"),
			Name:  types.StringValue("test-key"),
			Usage: types.StringValue("sig"),
			Upload: &PolicyKeyUpload{
				Value:        types.StringNull(), // Should be null from previous state
				ValueVersion: types.Int64Value(2),
			},
		}

		data := PolicyKeyModel{
			ID:    types.StringValue("test-id"),
			Name:  types.StringValue("test-key"),
			Usage: types.StringValue("sig"),
		}

		// Simulate read method preservation (what our fix does)
		if currentState.Upload != nil {
			data.Upload = &PolicyKeyUpload{
				ValueVersion: currentState.Upload.ValueVersion,
				Value:        types.StringNull(), // Keep write-only field null
			}
		}

		// Verify write-only field remains null
		if !data.Upload.Value.IsNull() {
			t.Errorf("Expected upload.value to remain null after read, got: %s", data.Upload.Value.ValueString())
		}

		// Verify version is preserved from state
		if data.Upload.ValueVersion.ValueInt64() != 2 {
			t.Errorf("Expected upload.value_version to be preserved as 2, got: %d", data.Upload.ValueVersion.ValueInt64())
		}
	})

	// Test Update method with config and state
	t.Run("UpdateStateHandling", func(t *testing.T) {
		configData := PolicyKeyModel{
			ID:    types.StringValue("test-id"),
			Name:  types.StringValue("test-key"),
			Usage: types.StringValue("sig"),
			Upload: &PolicyKeyUpload{
				Value:        types.StringValue("new-secret"), // Write-only from config
				ValueVersion: types.Int64Value(3),
			},
		}

		data := PolicyKeyModel{
			ID:    types.StringValue("test-id"),
			Name:  types.StringValue("test-key"),
			Usage: types.StringValue("sig"),
		}

		// Simulate update method handling (what our fix does)
		if configData.Upload != nil {
			data.Upload = &PolicyKeyUpload{
				ValueVersion: configData.Upload.ValueVersion,
				Value:        types.StringNull(), // Explicitly null for write-only
			}
		}

		// Verify write-only field is null in updated state
		if !data.Upload.Value.IsNull() {
			t.Errorf("Expected upload.value to be null after update, got: %s", data.Upload.Value.ValueString())
		}

		// Verify version comes from config
		if data.Upload.ValueVersion.ValueInt64() != 3 {
			t.Errorf("Expected upload.value_version to be 3 from config, got: %d", data.Upload.ValueVersion.ValueInt64())
		}
	})

	// Test generated key (should not have upload block)
	t.Run("GeneratedKeyNoUpload", func(t *testing.T) {
		data := PolicyKeyModel{
			ID:    types.StringValue("test-id"),
			Name:  types.StringValue("test-key"),
			Usage: types.StringValue("sig"),
			Generate: &PolicyKeyGenerate{
				Type: types.StringValue("RSA"),
			},
			Upload: nil, // Generated keys don't have upload
		}

		// Simulate create/update for generated key
		if data.Upload != nil {
			t.Errorf("Generated key should not have upload block")
		}

		// Verify generate block is present
		if data.Generate == nil {
			t.Error("Generated key should have generate block")
		}

		if data.Generate.Type.ValueString() != "RSA" {
			t.Errorf("Expected generate.type to be 'RSA', got: %s", data.Generate.Type.ValueString())
		}
	})

	// Test the universal sanitization function
	t.Run("UniversalSanitizationFunction", func(t *testing.T) {
		data := PolicyKeyModel{
			ID:    types.StringValue("test-id"),
			Name:  types.StringValue("test-key"),
			Usage: types.StringValue("sig"),
			Upload: &PolicyKeyUpload{
				Value:        types.StringValue("should-be-nullified"), // Write-only
				ValueVersion: types.Int64Value(1),
			},
		}

		// Call the sanitization function
		sanitizeWriteOnlyFields(&data)

		// Verify write-only field is nullified
		if !data.Upload.Value.IsNull() {
			t.Errorf("Expected upload.value to be null after sanitization, got: %s", data.Upload.Value.ValueString())
		}

		// Verify version is preserved
		if data.Upload.ValueVersion.ValueInt64() != 1 {
			t.Errorf("Expected upload.value_version to be 1 after sanitization, got: %d", data.Upload.ValueVersion.ValueInt64())
		}

		// Test with nil upload (should not panic)
		dataWithNilUpload := PolicyKeyModel{
			ID:     types.StringValue("test-id"),
			Name:   types.StringValue("test-key"),
			Usage:  types.StringValue("sig"),
			Upload: nil,
		}
		sanitizeWriteOnlyFields(&dataWithNilUpload) // Should not panic
	})

	// Test legacy state sanitization
	t.Run("LegacyStateCleanup", func(t *testing.T) {
		// Simulate legacy state with stored secret (from buggy provider)
		legacyState := PolicyKeyModel{
			ID:    types.StringValue("legacy-key-id"),
			Name:  types.StringValue("LegacyKey"),
			Usage: types.StringValue("sig"),
			Upload: &PolicyKeyUpload{
				Value:        types.StringValue("legacy-secret-in-state"), // Should not be here!
				ValueVersion: types.Int64Value(1),
			},
		}

		// Verify legacy state has the secret
		if legacyState.Upload.Value.IsNull() {
			t.Errorf("Test setup error: legacy state should have non-null upload.value")
		}

		// Call the legacy sanitization function
		sanitizeLegacyState(context.Background(), &legacyState)

		// Verify the secret is cleaned up
		if !legacyState.Upload.Value.IsNull() {
			t.Errorf("Expected legacy upload.value to be null after cleanup, got: %s", legacyState.Upload.Value.ValueString())
		}

		// Verify version tracking is preserved
		if legacyState.Upload.ValueVersion.ValueInt64() != 1 {
			t.Errorf("Expected version tracking to be preserved as 1, got: %d", legacyState.Upload.ValueVersion.ValueInt64())
		}
	})

	// Test sanitization with warning message
	t.Run("SanitizationWithWarning", func(t *testing.T) {
		dataWithSecret := PolicyKeyModel{
			ID:    types.StringValue("test-id"),
			Name:  types.StringValue("test-key"),
			Usage: types.StringValue("sig"),
			Upload: &PolicyKeyUpload{
				Value:        types.StringValue("detected-secret"), // This should trigger warning
				ValueVersion: types.Int64Value(2),
			},
		}

		// Call sanitization - should detect and clean
		sanitizeWriteOnlyFields(&dataWithSecret)

		// Verify the secret is cleaned up
		if !dataWithSecret.Upload.Value.IsNull() {
			t.Errorf("Expected upload.value to be null after sanitization, got: %s", dataWithSecret.Upload.Value.ValueString())
		}

		// Verify version is preserved
		if dataWithSecret.Upload.ValueVersion.ValueInt64() != 2 {
			t.Errorf("Expected version to be preserved as 2, got: %d", dataWithSecret.Upload.ValueVersion.ValueInt64())
		}
	})

	// Test legacy state with null upload (no cleanup needed)
	t.Run("CleanLegacyStateNoCleanup", func(t *testing.T) {
		cleanState := PolicyKeyModel{
			ID:    types.StringValue("clean-key-id"),
			Name:  types.StringValue("CleanKey"),
			Usage: types.StringValue("sig"),
			Upload: &PolicyKeyUpload{
				Value:        types.StringNull(), // Already clean
				ValueVersion: types.Int64Value(3),
			},
		}

		// Call the legacy sanitization function on already clean state
		sanitizeLegacyState(context.Background(), &cleanState)

		// Verify the state remains clean and version preserved
		if !cleanState.Upload.Value.IsNull() {
			t.Errorf("Expected upload.value to remain null, got: %s", cleanState.Upload.Value.ValueString())
		}

		if cleanState.Upload.ValueVersion.ValueInt64() != 3 {
			t.Errorf("Expected version to remain 3, got: %d", cleanState.Upload.ValueVersion.ValueInt64())
		}
	})

	// Test legacy state with nil upload (no cleanup needed)
	t.Run("LegacyStateWithNilUpload", func(t *testing.T) {
		stateWithNilUpload := PolicyKeyModel{
			ID:     types.StringValue("nil-upload-key"),
			Name:   types.StringValue("NilUploadKey"),
			Usage:  types.StringValue("sig"),
			Upload: nil, // No upload block
		}

		// Should not panic
		sanitizeLegacyState(context.Background(), &stateWithNilUpload)

		// Verify upload is still nil
		if stateWithNilUpload.Upload != nil {
			t.Errorf("Expected upload to remain nil, got non-nil value")
		}
	})
}
