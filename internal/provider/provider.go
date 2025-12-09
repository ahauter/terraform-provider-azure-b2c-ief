package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type b2ciefProvider struct {
}

type providerConfig struct {
	TenantId     types.String `tfsdk:"tenant_id"`
	ClientId     types.String `tfsdk:"client_id"`
	ClientSecret types.String `tfsdk:"client_secret"`
}

func New() provider.Provider {
	return &b2ciefProvider{}
}

func (p *b2ciefProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "azure-b2c-ief"
}

func (p *b2ciefProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema.Attributes = map[string]schema.Attribute{
		"tenant_id": schema.StringAttribute{
			Required: true,
		},
		"client_id": schema.StringAttribute{
			Required: true,
		},
		"client_secret": schema.StringAttribute{
			Required: true,
		},
	}
}

func (p *b2ciefProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerConfig
	diags := req.Config.Get(ctx, &cfg)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	client, err := NewGraphClient(
		ctx,
		cfg.TenantId.ValueString(),
		cfg.ClientId.ValueString(),
		cfg.TenantId.ValueString(),
	)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create Graph client", err.Error())
		return
	}

	resp.DataSourceData = client
	resp.ResourceData = client
}

func (p *b2ciefProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewPolicyKeyResource,
	}
}

func (p *b2ciefProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}
