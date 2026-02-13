package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/resourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const logPrefix = "B2C_POLICY_KEY"

// Utility: pretty print any object as JSON
func jsonDebug(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

type PolicyKeyResource struct {
	client *GraphClient
}

type PolicyKeyModel struct {
	ID       types.String       `tfsdk:"id"`
	Name     types.String       `tfsdk:"name"`
	Usage    types.String       `tfsdk:"usage"`
	Upload   *PolicyKeyUpload   `tfsdk:"upload"`
	Generate *PolicyKeyGenerate `tfsdk:"generate"`
}

type PolicyKeyUpload struct {
	Value        types.String `tfsdk:"value"`
	ValueVersion types.Int64  `tfsdk:"value_version"`
}

type PolicyKeyGenerate struct {
	Type types.String `tfsdk:"type"`
}

// sanitizeWriteOnlyFields ensures write-only attributes are null before state is set
func sanitizeWriteOnlyFields(data *PolicyKeyModel) {
	if data.Upload != nil {
		// Detect legacy state with non-null write-only value
		hadSecret := !data.Upload.Value.IsNull()
		if hadSecret {
			tflog.Warn(context.Background(), "🔒 CLEANING DETECTED SECRET: upload.value was found in state and has been sanitized")
		}

		data.Upload = &PolicyKeyUpload{
			ValueVersion: data.Upload.ValueVersion,
			Value:        types.StringNull(), // Force null for write-only field
		}
	}
}

// sanitizeLegacyState detects and cleans existing secrets from state files
func sanitizeLegacyState(ctx context.Context, data *PolicyKeyModel) {
	if data.Upload != nil && !data.Upload.Value.IsNull() {
		// Log security event for user awareness
		tflog.Warn(ctx, "🔒 LEGACY STATE CLEANUP: Removing write-only value from state. Previous provider version stored secrets in state - this has been fixed for security.")
		tflog.Debug(ctx, "Legacy secret detected and sanitized", map[string]any{
			"key_name": data.Name.ValueString(),
			"key_id":   data.ID.ValueString(),
		})

		// Sanitize the legacy secret
		data.Upload.Value = types.StringNull()
	}
}

func NewPolicyKeyResource() resource.Resource {
	return &PolicyKeyResource{}
}

func (r *PolicyKeyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy_key"
}

func (r *PolicyKeyResource) Schema(
	ctx context.Context,
	req resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		Description: "Manages an Azure AD B2C IEF policy key container.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The object ID of the key container in Microsoft Graph. Use this to reference the policy key in a policy.",
			},

			"name": schema.StringAttribute{
				Required:    true,
				Description: "The IEF policy key container name. The B2C_1A_ prefix is not added! This will cause errors if the name is used in a policy",
			},

			"usage": schema.StringAttribute{
				Required:    true,
				Description: "Key usage: sig (signing) or enc (encryption).",
				Validators: []validator.String{
					stringvalidator.OneOf("sig", "enc"),
				},
			},
		},

		Blocks: map[string]schema.Block{
			"generate": schema.SingleNestedBlock{
				Description: "Generate a new key in the key container.",
				Attributes: map[string]schema.Attribute{
					"type": schema.StringAttribute{
						Optional:    true,
						Description: "Key type. Only RSA is currently supported by Azure AD B2C.",
						Validators: []validator.String{
							stringvalidator.OneOf("RSA"),
						},
					},
				},
			},

			"upload": schema.SingleNestedBlock{
				Description: "Upload an existing key or secret.",
				Attributes: map[string]schema.Attribute{
					"value": schema.StringAttribute{
						WriteOnly:   true,
						Optional:    true,
						Description: "Raw secret value (write-only, never stored in state)",
					},
					"value_version": schema.Int64Attribute{
						Optional:    true,
						Description: "Version tracker. Omit to always upload, 0+ to manage versions, -1 to force upload.",
					},
				},
			},
		},
	}
}

// ConfigValidators enforces exactly one of generate or upload
func (r *PolicyKeyResource) ConfigValidators(
	ctx context.Context,
) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		resourcevalidator.ExactlyOneOf(
			path.MatchRoot("generate"),
			path.MatchRoot("upload"),
		),
	}
}

func (r *PolicyKeyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(*GraphClient)
}

type CreateKeysetResponse struct {
	Id string `json:"id"`
}

func (r *PolicyKeyResource) uploadOrGenerate(ctx context.Context, data PolicyKeyModel, configData PolicyKeyModel, stateData PolicyKeyModel) error {
	var uploadBody map[string]any
	var endpoint string

	if data.Generate != nil {
		uploadBody = map[string]any{
			"use": data.Usage.ValueString(),
			"kty": data.Generate.Type.ValueString(), //THIS could be hard-code "RSA" lol
		}
		endpoint = fmt.Sprintf(
			"https://graph.microsoft.com/beta/trustFramework/keySets/%s/generateKey",
			data.ID.ValueString(),
		)
	} else if data.Upload != nil {
		// Validate config is non-negative (defensive check)
		if !configData.Upload.ValueVersion.IsNull() {
			version := configData.Upload.ValueVersion.ValueInt64()
			if version < 0 && version != -1 {
				return errors.New("value_version must be -1 or >= 0")
			}
		}

		// Check if we should upload based on version
		shouldUpload := configData.Upload.ValueVersion.IsNull() || // Null = always upload
			configData.Upload.ValueVersion.ValueInt64() == -1 || // Explicit -1 = upload
			(configData.Upload.ValueVersion.ValueInt64() >= 0 && // Non-negative check + version change
				stateData.Upload != nil &&
				configData.Upload.ValueVersion.ValueInt64() != stateData.Upload.ValueVersion.ValueInt64())

		if shouldUpload {
			if configData.Upload.Value.IsNull() {
				return errors.New("upload.value cannot be null when upload block is specified")
			}

			// Add debug log for null version
			if configData.Upload.ValueVersion.IsNull() {
				tflog.Debug(ctx, "value_version is null, triggering upload (assuming fresh secret each run)")
			} else {
				tflog.Debug(ctx, fmt.Sprintf("value_version: %d", configData.Upload.ValueVersion.ValueInt64()))
			}

			uploadBody = map[string]any{
				"use": data.Usage.ValueString(),
				"k":   configData.Upload.Value.ValueString(), // Use config value for write-only access
			}
			endpoint = fmt.Sprintf(
				"https://graph.microsoft.com/beta/trustFramework/keySets/%s/uploadSecret",
				data.ID.ValueString(),
			)
		} else {
			// No upload needed, return early
			return nil
		}
	} else {
		// Neither block specified — should not happen if schema validators are working
		return errors.New("No provisioning method specified OR an invalid block was given")
	}

	tflog.Debug(ctx, fmt.Sprintf("%s: POST %s\nBody:\n%s", logPrefix, endpoint, jsonDebug(uploadBody)))

	graphResp, err := r.client.doGraph(ctx, "POST", endpoint, uploadBody)
	if err != nil {
		tflog.Error(ctx, fmt.Sprintf("%s: Upload secret error: %s", logPrefix, err))
		return err
	} else if graphResp.StatusCode != http.StatusOK {
		tflog.Error(ctx, fmt.Sprintf("Error in create secret response!\n%s", readBodyString(graphResp)))
		return errors.New(readBodyString(graphResp))
	}
	logHTTPResponse(ctx, "Upload secret response", graphResp)
	return nil
}

// ────────────────────────────────────────────────────────────────────────────────
//
//	CREATE
//
// ────────────────────────────────────────────────────────────────────────────────
func (r *PolicyKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	tflog.Debug(ctx, fmt.Sprintf("%s: CREATE begin", logPrefix))

	var data PolicyKeyModel
	diags := req.Config.Get(ctx, &data)
	resp.Diagnostics.Append(diags...)

	tflog.Debug(ctx, fmt.Sprintf("%s: Create plan: %s", logPrefix, jsonDebug(data)))

	// 1. Create keyset
	createBody := map[string]any{
		"id":    data.Name.ValueString(),
		"usage": data.Usage.ValueString(),
		"keys":  []any{},
	}

	createURL := "https://graph.microsoft.com/beta/trustFramework/keySets"
	tflog.Debug(ctx, fmt.Sprintf("%s: POST %s\nBody:\n%s", logPrefix, createURL, jsonDebug(createBody)))

	graphResp, err := r.client.doGraph(ctx, "POST", createURL, createBody)
	if err != nil {
		tflog.Error(ctx, fmt.Sprintf("%s: Create keyset error: %s", logPrefix, err))
		resp.Diagnostics.AddError("Create keyset failed", err.Error())
		return
		//TODO handle _ already exists error
	} else if graphResp.StatusCode != http.StatusCreated {
		tflog.Debug(ctx, graphResp.Status)
		tflog.Error(ctx, fmt.Sprintf("Error in create keyset response!\n%s", readBodyString(graphResp)))
		resp.Diagnostics.AddError("Create keyset failed", readBodyString(graphResp))
		return
	}
	logHTTPResponse(ctx, "Create keyset response", graphResp)
	// set ID to proper ID
	var keysetResp CreateKeysetResponse
	err = json.Unmarshal(readBodyBytes(graphResp), &keysetResp)
	if err != nil || keysetResp.Id == "" {
		tflog.Error(ctx, fmt.Sprintf("Error in create keyset response!\n%s", readBodyString(graphResp)))
		resp.Diagnostics.AddError("Create keyset failed", readBodyString(graphResp))
		return
	}
	data.ID = types.StringValue(keysetResp.Id)

	//TODO Create upload methods for x.509 and PKCS
	//TODO Not-good-before and expiry for keys :)
	// 2. Upload secret /generate secret !
	err = r.uploadOrGenerate(ctx, data, data, PolicyKeyModel{}) // Use data as both config and plan
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating or uploading policy key",
			err.Error(),
		)
	}

	// Sanitize write-only fields before storing in state
	sanitizeWriteOnlyFields(&data)

	resp.State.Set(ctx, &data)
	tflog.Debug(ctx, fmt.Sprintf("%s: CREATE complete", logPrefix))
}

// ────────────────────────────────────────────────────────────────────────────────
//
//	READ
//
// ────────────────────────────────────────────────────────────────────────────────
func (r *PolicyKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	tflog.Debug(ctx, fmt.Sprintf("%s: READ begin", logPrefix))

	var data PolicyKeyModel
	diags := req.State.Get(ctx, &data)
	resp.Diagnostics.Append(diags...)

	// CRITICAL: Always sanitize legacy state for backwards compatibility
	sanitizeLegacyState(ctx, &data)

	tflog.Debug(ctx, fmt.Sprintf("%s: State after legacy cleanup: %s", logPrefix, jsonDebug(data)))

	n := data.ID.ValueString()
	getURL := fmt.Sprintf("https://graph.microsoft.com/beta/trustFramework/keySets/%s", n)

	tflog.Debug(ctx, fmt.Sprintf("%s: GET %s", logPrefix, getURL))

	graphResp, err := r.client.doGraph(ctx, "GET", getURL, nil)
	if err != nil {
		tflog.Error(ctx, fmt.Sprintf("%s: Read error: %s", logPrefix, err))
		resp.Diagnostics.AddError("Read keysets failed", err.Error())
		return
	}
	logHTTPResponse(ctx, "Read keysets response", graphResp)

	if graphResp.StatusCode != http.StatusOK {
		body := readBodyString(graphResp)
		if strings.Contains(body, "AADB2C90073") { // ___ DOES NOT EXIST IN DIRECTORY ERROR CODE
			//We know the keysets don't exist under the name, remove the id
			tflog.Debug(ctx, "Keyset does not exist, we will reset!")
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError(
			fmt.Sprintf("Graph returned %s", graphResp.Status),
			body,
		)
	}
	var parsed_resp CreateKeysetResponse
	raw_body := readBodyBytes(graphResp)
	err = json.Unmarshal(raw_body, &parsed_resp)
	if err != nil {
		tflog.Error(ctx, fmt.Sprintf("Keyset Parsing error! Error value: %s", err))
		tflog.Error(ctx, fmt.Sprintf("Raw response: %s", string(raw_body)))
		resp.Diagnostics.AddError(
			fmt.Sprintf("Error parsing graph response!"),
			fmt.Sprintf("The response was: %s", string(raw_body)),
		)
		return
	}

	// Get current state to preserve write-only field structure and version tracking
	var currentState PolicyKeyModel
	req.State.Get(ctx, &currentState)

	// Preserve version tracking from state
	if currentState.Upload != nil && data.Upload == nil {
		data.Upload = &PolicyKeyUpload{
			ValueVersion: currentState.Upload.ValueVersion,
			Value:        types.StringNull(), // Keep write-only field null
		}
	}

	// Ensure write-only fields are sanitized before storing in state
	sanitizeWriteOnlyFields(&data)

	resp.State.Set(ctx, &data)
	tflog.Debug(ctx, "READ complete")
}

// ────────────────────────────────────────────────────────────────────────────────
//
//	UPDATE
//
// ────────────────────────────────────────────────────────────────────────────────
func (r *PolicyKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	tflog.Debug(ctx, fmt.Sprintf("%s: UPDATE begin", logPrefix))

	// Get both config and state data for version comparison
	var configData, stateData PolicyKeyModel
	configDiags := req.Config.Get(ctx, &configData)
	stateDiags := req.State.Get(ctx, &stateData)
	resp.Diagnostics.Append(configDiags...)
	resp.Diagnostics.Append(stateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// CRITICAL: Always sanitize legacy state for backwards compatibility
	sanitizeLegacyState(ctx, &stateData)

	tflog.Debug(ctx, fmt.Sprintf("%s: Update plan: %s", logPrefix, jsonDebug(configData)))

	err := r.uploadOrGenerate(ctx, configData, configData, stateData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating or uploading policy key",
			err.Error(),
		)
		return
	}

	// Rebuild state data from sanitized sources - don't use plan data directly
	data := PolicyKeyModel{
		ID:    configData.ID,
		Name:  configData.Name,
		Usage: configData.Usage,
	}

	// Handle generate block if present
	if configData.Generate != nil {
		data.Generate = configData.Generate
	}

	// Handle upload block with proper version tracking
	if configData.Upload != nil {
		data.Upload = &PolicyKeyUpload{
			ValueVersion: configData.Upload.ValueVersion,
			Value:        types.StringNull(), // Explicitly null for write-only field
		}
	} else if stateData.Upload != nil {
		// Preserve existing upload structure if no upload in config
		data.Upload = &PolicyKeyUpload{
			ValueVersion: stateData.Upload.ValueVersion,
			Value:        types.StringNull(), // Explicitly null for write-only field
		}
	}

	// Ensure write-only fields are sanitized before storing in state
	sanitizeWriteOnlyFields(&data)

	resp.State.Set(ctx, &data)
	tflog.Debug(ctx, fmt.Sprintf("%s: UPDATE complete", logPrefix))
}

// ────────────────────────────────────────────────────────────────────────────────
//
//	DELETE
//
// ────────────────────────────────────────────────────────────────────────────────
func (r *PolicyKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	tflog.Debug(ctx, fmt.Sprintf("%s: DELETE begin", logPrefix))

	var data PolicyKeyModel
	diags := req.State.Get(ctx, &data)
	resp.Diagnostics.Append(diags...)

	// Sanitize legacy state for consistency
	sanitizeLegacyState(ctx, &data)

	tflog.Debug(ctx, fmt.Sprintf("%s: Delete target: %s", logPrefix, jsonDebug(data)))
	n := data.ID.ValueString()
	deleteURL := fmt.Sprintf("https://graph.microsoft.com/beta/trustFramework/keySets/%s", n)

	tflog.Debug(ctx, fmt.Sprintf("%s: DELETE %s", logPrefix, deleteURL))

	graphResp, err := r.client.doGraph(ctx, "DELETE", deleteURL, nil)
	if err != nil {
		tflog.Error(ctx, fmt.Sprintf("%s: Delete error: %s", logPrefix, err))
		resp.Diagnostics.AddError("Delete failed", err.Error())
		return
	}

	logHTTPResponse(ctx, "Delete response", graphResp)

	// Expected result from success is 204: No Content
	if graphResp.StatusCode != http.StatusNoContent {
		body := readBodyString(graphResp)
		resp.Diagnostics.AddError(
			fmt.Sprintf("Graph returned %s", graphResp.Status),
			body,
		)
	}

	tflog.Debug(ctx, fmt.Sprintf("%s: DELETE complete", logPrefix))
}

func logHTTPResponse(ctx context.Context, title string, resp *http.Response) {
	body := readBodyString(resp)
	tflog.Debug(ctx, fmt.Sprintf("%s: %s\nStatus: %s\nBody:\n%s", logPrefix, title, resp.Status, body))
}

func readBodyBytes(resp *http.Response) []byte {
	if resp == nil || resp.Body == nil {
		return []byte{}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)

	// Rewind the body so Terraform doesn't panic later when it tries to read it again
	resp.Body = io.NopCloser(bytes.NewBuffer(b))

	return b
}

func readBodyString(resp *http.Response) string {
	if resp == nil || resp.Body == nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)

	// Rewind the body so Terraform doesn't panic later when it tries to read it again
	resp.Body = io.NopCloser(bytes.NewBuffer(b))

	return string(b)
}
