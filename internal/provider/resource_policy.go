package provider

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type PolicyResource struct {
	client *GraphClient
}

type IEFPolicyModel struct {
	ID          types.String `tfsdk:"id"`
	XML         types.String `tfsdk:"xml"`
	File        types.String `tfsdk:"file"`
	AppSettings types.Map    `tfsdk:"app_settings"`
	Publish     types.Bool   `tfsdk:"publish"`
}

func NewIEFPolicyResource() resource.Resource {
	return &PolicyResource{}
}

func (r *PolicyResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_policy"
}

func (r *PolicyResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema.Attributes = map[string]schema.Attribute{
		"id": schema.StringAttribute{
			Computed: true,
		},
		"file": schema.StringAttribute{
			Required: true,
		},
		"app_settings": schema.MapAttribute{
			Required:    true,
			ElementType: types.StringType,
		},
		"publish": schema.BoolAttribute{
			Required: true,
		},
		"xml": schema.StringAttribute{
			Computed: true,
		},
	}
}

func (r *PolicyResource) Configure(
	_ context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(*GraphClient)
}

func isNullOrEmpty(a types.String) bool {
	return a.IsUnknown() || a.IsNull() || "" == a.ValueString()
}

func getPolicyId(p string) string {
	result := ""
	decoder := xml.NewDecoder(strings.NewReader(p))
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch se := tok.(type) {
		case xml.StartElement:
			fmt.Println("First element name:", se.Name.Local)
			for _, attr := range se.Attr {
				if attr.Name.Local == "PolicyId" {
					result = attr.Value
				}
			}
			return result
		}
	}
	return result
}

func injectAppSettings(
	ctx context.Context,
	xml string,
	app_settings map[string]types.String,
) string {
	result := xml
	for k, v := range app_settings {
		re := regexp.MustCompile(fmt.Sprintf(
			`(?i)\{settings:%s\}`, k),
		)
		if !isNullOrEmpty(v) {
			result = re.ReplaceAllString(result, v.ValueString())
			tflog.Debug(ctx, "App setting found!", map[string]any{
				"KEY":   k,
				"VALUE": v.ValueString(),
			})
		} else {
			tflog.Warn(ctx, "App setting is null or empty", map[string]any{
				"KEY":   k,
				"VALUE": v.ValueString(),
			})
		}
	}
	return result
}

func (r *PolicyResource) putPolicy(ctx context.Context, policyXml string) error {
	policyId := getPolicyId(policyXml)
	tflog.Debug(ctx, "Policy ID", map[string]any{
		"ID": policyId,
	})
	endpoint := fmt.Sprintf(
		"https://graph.microsoft.com/beta/trustFramework/policies/%s/$value",
		policyId,
	)
	gr, err := r.client.doGraphXML(
		ctx, "PUT",
		endpoint,
		&policyXml,
	)
	if err != nil {
		return err
	}
	if gr.StatusCode != http.StatusOK && gr.StatusCode != http.StatusCreated {
		return errors.New(fmt.Sprintf(
			"Error code received from graph! %s \n%s", gr.Status,
			readBodyString(gr),
		))
	}
	return nil
}

func (r *PolicyResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var data IEFPolicyModel
	diags := req.Config.Get(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Debug(ctx, "Create plan: ", map[string]any{
		"FILE":    data.File.ValueString(),
		"PUBLISH": data.Publish.ValueBool(),
	})

	// if xml is undefined, read it from file
	var content string
	if isNullOrEmpty(data.File) {
		tflog.Error(ctx, "XML is not defined and file path is not defined!")
		resp.Diagnostics.AddError(
			"Invalid config",
			"XML is not defined and file path is not defined!",
		)
		return
	}
	p := data.File.ValueString()
	_, err := os.Stat(p)
	if err != nil && os.IsNotExist(err) {
		resp.Diagnostics.AddError(
			"File does not exist!",
			fmt.Sprintf("File path %s does not exist (Create)", p),
		)
		return
	}
	raw_byte, err := os.ReadFile(p)
	if err != nil {
		tflog.Error(ctx, "Error reading file!", map[string]any{
			"path": p,
		})
		resp.Diagnostics.AddError(
			"Invalid config",
			fmt.Sprintf("Invalid Path! %s", p),
		)
		return
	}
	content = string(raw_byte)
	settings := make(map[string]types.String, len(data.AppSettings.Elements()))
	diags = data.AppSettings.ElementsAs(ctx, &settings, false)
	if diags.HasError() {
		tflog.Error(ctx, "Failed to read AppSettings", map[string]interface{}{
			"diagnostics": diags,
		})
	}
	ief_policy_raw := injectAppSettings(ctx, content, settings)
	data.XML = types.StringValue(ief_policy_raw)
	data.ID = types.StringValue(getPolicyId(ief_policy_raw))

	if data.Publish.ValueBool() {
		err = r.putPolicy(ctx, ief_policy_raw)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error uploading policy",
				fmt.Sprintf(
					"Error creating policy!\n %s",
					err.Error(),
				),
			)
		}
	}
	resp.State.Set(ctx, &data)
	tflog.Debug(ctx, "Create policy complete!", map[string]any{
		"ID": data.ID.ValueString(),
	})
}

func (r *PolicyResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var data IEFPolicyModel
	diags := req.State.Get(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	p := data.File.ValueString()
	_, err := os.Stat(p)
	if err != nil && os.IsNotExist(err) {
		resp.Diagnostics.AddError(
			"File does not exist! (Read)",
			fmt.Sprintf("File path %s does not exist", p),
		)
		return
	}
	raw_byte, err := os.ReadFile(p)
	if err != nil {
		tflog.Error(ctx, "Error reading file!", map[string]any{
			"path": p,
		})
		resp.Diagnostics.AddError(
			"Invalid config",
			fmt.Sprintf("Invalid Path! %s", p),
		)
		return
	}
	content := string(raw_byte)
	settings := make(map[string]types.String, len(data.AppSettings.Elements()))
	diags = data.AppSettings.ElementsAs(ctx, &settings, false)
	if diags.HasError() {
		tflog.Error(ctx, "Failed to read AppSettings", map[string]interface{}{
			"diagnostics": diags,
		})
	}
	ief_policy_raw := injectAppSettings(ctx, content, settings)
	read_xml := data.XML.ValueString()
	if read_xml != ief_policy_raw {
		resp.State.RemoveResource(ctx)
		return
	}

	if data.Publish.ValueBool() {
		policy_id := getPolicyId(ief_policy_raw)
		endpoint := fmt.Sprintf("https://graph.microsoft.com/beta/trustFramework/policies/%s/$value", policy_id)
		gr, err := r.client.doGraphXML(ctx, "GET", endpoint, nil)
		if err != nil {
			resp.State.RemoveResource(ctx)
			return
		}
		if gr.StatusCode != http.StatusOK {
			resp.State.RemoveResource(ctx)
			return
		}
	}
	resp.State.Set(ctx, &data)
	tflog.Debug(ctx, "READ complete")
}

func (r *PolicyResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var data IEFPolicyModel
	diags := req.Config.Get(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// if xml is undefined, read it from file
	var content string
	if isNullOrEmpty(data.File) {
		tflog.Error(ctx, "XML is not defined and file path is not defined!")
		resp.Diagnostics.AddError(
			"Invalid config",
			"XML is not defined and file path is not defined!",
		)
		return
	}
	p := data.File.ValueString()
	_, err := os.Stat(p)
	if err != nil && os.IsNotExist(err) {
		resp.Diagnostics.AddError(
			"File does not exist! (Update)",
			fmt.Sprintf("File path %s does not exist", p),
		)
		return
	}
	raw_byte, err := os.ReadFile(p)
	if err != nil {
		tflog.Error(ctx, "Error reading file!", map[string]any{
			"path": p,
		})
		resp.Diagnostics.AddError(
			"Invalid config",
			fmt.Sprintf("Invalid Path! %s", p),
		)
		return
	}
	content = string(raw_byte)
	settings := make(map[string]types.String, len(data.AppSettings.Elements()))
	diags = data.AppSettings.ElementsAs(ctx, &settings, false)
	if diags.HasError() {
		tflog.Error(ctx, "Failed to read AppSettings", map[string]interface{}{
			"diagnostics": diags,
		})
	}

	ief_policy_raw := injectAppSettings(ctx, content, settings)
	data.XML = types.StringValue(ief_policy_raw)
	data.ID = types.StringValue(getPolicyId(ief_policy_raw))

	if data.Publish.ValueBool() {
		err = r.putPolicy(ctx, ief_policy_raw)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error uploading policy",
				fmt.Sprintf(
					"Error creating policy!\n %s",
					err.Error(),
				),
			)
		}
	}
	resp.State.Set(ctx, &data)
	tflog.Debug(ctx, "Create policy complete!", map[string]any{
		"ID": data.ID.ValueString(),
	})
}

func (r *PolicyResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	tflog.Debug(ctx, "%s: DELETE begin")

	var data IEFPolicyModel
	diags := req.State.Get(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if data.Publish.ValueBool() {
		n := data.ID.ValueString()
		deleteURL := fmt.Sprintf("https://graph.microsoft.com/beta/trustFramework/policies/%s", n)
		gr, err := r.client.doGraphXML(ctx, "DELETE", deleteURL, nil)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error deleting ief policy",
				fmt.Sprintf(
					"Error deleting policy!\n %s",
					err.Error(),
				),
			)
			return
		}
		if gr.StatusCode != http.StatusNoContent {
			resp.Diagnostics.AddError(
				"Error deleting ief policy",
				fmt.Sprintf(
					"Graph Error deleting policy!\n %s",
					readBodyString(gr),
				),
			)
			return
		}
	}

	tflog.Debug(ctx, "DELETE complete")
}
