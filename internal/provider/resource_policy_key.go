package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
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
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	SecretValue types.String `tfsdk:"secret_value"`
}

func NewPolicyKeyResource() resource.Resource {
	return &PolicyKeyResource{}
}

func (r *PolicyKeyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy_key"
}

func (r *PolicyKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema.Attributes = map[string]schema.Attribute{
		"id": schema.StringAttribute{
			Computed: true,
		},
		"name": schema.StringAttribute{
			Required: true,
		},
		"secret_value": schema.StringAttribute{
			Required:  true,
			Sensitive: true,
		},
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

// ────────────────────────────────────────────────────────────────────────────────
//
//	CREATE
//
// ────────────────────────────────────────────────────────────────────────────────
func (r *PolicyKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	tflog.Debug(ctx, fmt.Sprintf("%s: CREATE begin", logPrefix))

	var data PolicyKeyModel
	diags := req.Plan.Get(ctx, &data)
	resp.Diagnostics.Append(diags...)

	tflog.Debug(ctx, fmt.Sprintf("%s: Create plan: %s", logPrefix, jsonDebug(data)))

	// 1. Create keyset
	createBody := map[string]any{
		"id":    data.Name.ValueString(),
		"usage": "sig",
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

	// 2. Upload secret
	uploadBody := map[string]any{
		"use": "sig",
		"k":   data.SecretValue.ValueString(),
	}
	uploadURL := fmt.Sprintf(
		"https://graph.microsoft.com/beta/trustFramework/keySets/%s/uploadSecret",
		data.ID.ValueString(),
	)

	tflog.Debug(ctx, fmt.Sprintf("%s: POST %s\nBody:\n%s", logPrefix, uploadURL, jsonDebug(uploadBody)))

	graphResp, err = r.client.doGraph(ctx, "POST", uploadURL, uploadBody)
	if err != nil {
		tflog.Error(ctx, fmt.Sprintf("%s: Upload secret error: %s", logPrefix, err))
		resp.Diagnostics.AddError("Upload secret failed", err.Error())
		return
	} else if graphResp.StatusCode != http.StatusOK {
		tflog.Error(ctx, fmt.Sprintf("Error in create secret response!\n%s", readBodyString(graphResp)))
		resp.Diagnostics.AddError("Create keyset failed", readBodyString(graphResp))
	}
	logHTTPResponse(ctx, "Upload secret response", graphResp)

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

	tflog.Debug(ctx, fmt.Sprintf("%s: State before read: %s", logPrefix, jsonDebug(data)))

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
	resp.State.Set(ctx, &data)
	tflog.Debug(ctx, fmt.Sprintf("READ complete", logPrefix))
}

// ────────────────────────────────────────────────────────────────────────────────
//
//	UPDATE
//
// ────────────────────────────────────────────────────────────────────────────────
func (r *PolicyKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	tflog.Debug(ctx, fmt.Sprintf("%s: UPDATE begin", logPrefix))

	var data PolicyKeyModel
	diags := req.Plan.Get(ctx, &data)
	resp.Diagnostics.Append(diags...)

	tflog.Debug(ctx, fmt.Sprintf("%s: Update plan: %s", logPrefix, jsonDebug(data)))

	uploadBody := map[string]any{
		"value": data.SecretValue.ValueString(),
	}
	uploadURL := fmt.Sprintf("https://graph.microsoft.com/beta/trustFramework/keySets/%s/uploadSecret", data.Name.ValueString())

	tflog.Debug(ctx, fmt.Sprintf("%s: POST %s\nBody:\n%s", logPrefix, uploadURL, jsonDebug(uploadBody)))

	graphResp, err := r.client.doGraph(ctx, "POST", uploadURL, uploadBody)
	if err != nil {
		tflog.Error(ctx, fmt.Sprintf("%s: Update error: %s", logPrefix, err))
		resp.Diagnostics.AddError("Upload secret failed", err.Error())
		return
	}
	logHTTPResponse(ctx, "Update uploadSecret response", graphResp)

	if graphResp.StatusCode != http.StatusOK {
		body := readBodyString(graphResp)
		resp.Diagnostics.AddError(
			fmt.Sprintf("Graph returned %s", graphResp.Status),
			body,
		)
	}

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
