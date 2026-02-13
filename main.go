package main

import (
	"context"

	"github.com/ahauter/terraform-provider-azure-b2c-ief/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

//go:generate go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs generate --provider-name azure-b2c-ief

func main() {
	providerserver.Serve(context.Background(), provider.New, providerserver.ServeOpts{
		Address: "registry.terraform.io/local/azure-b2c-ief", // updated
	})
}
