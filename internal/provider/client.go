package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type GraphClient struct {
	tenantId   string
	credential *azidentity.ClientSecretCredential
	client     *http.Client
}

func NewGraphClient(ctx context.Context, tenantId string, clientId string, clientSecret string) (*GraphClient, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	credential, err := azidentity.NewClientSecretCredential(tenantId, clientId, clientSecret, nil)
	if err != nil {
		tflog.Error(context.Background(), "Credential failed", map[string]any{
			"error": err.Error(),
		})
		return nil, err
	}
	tflog.Debug(ctx, "Success getting default credential!")
	return &GraphClient{
		tenantId:   tenantId,
		credential: credential,
		client:     client,
	}, nil
}

func (c *GraphClient) getToken(ctx context.Context) (string, error) {
	// Get token for Graph
	token, err := c.credential.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://graph.microsoft.com/.default"},
	})
	if err != nil {
		return "", err
	}
	tflog.Debug(ctx, fmt.Sprintf("Token value: %s", token.Token))
	return token.Token, nil
}

func (c *GraphClient) doGraph(ctx context.Context, method, url string, body any) (*http.Response, error) {

	var buf *bytes.Buffer
	var payload string

	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			tflog.Error(ctx, "JSON marshal error", map[string]any{
				"error": err.Error(),
			})
			return nil, err
		}
		buf = bytes.NewBuffer(b)
		payload = string(b)
	} else {
		buf = &bytes.Buffer{}
		payload = "<empty>"
	}

	tflog.Debug(ctx, "sending Graph request", map[string]any{
		"method":  method,
		"url":     url,
		"payload": payload,
	})

	req, err := http.NewRequest(method, url, buf)
	if err != nil {
		tflog.Error(ctx, "failed to build Graph HTTP request", map[string]any{
			"error": err.Error(),
		})
		return nil, err
	}

	token, err := c.getToken(ctx)
	if err != nil {
		tflog.Error(ctx, "Error getting token from credential!", map[string]any{
			"error": err.Error(),
		})
		return nil, err
	} else {
		tflog.Debug(ctx, fmt.Sprintf("Token value: %s", token))
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		tflog.Error(ctx, "Graph API request failed", map[string]any{
			"error": err.Error(),
		})
		return nil, err
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	tflog.Debug(ctx, "Graph API response", map[string]any{
		"status": resp.Status,
		"body":   string(bodyBytes),
	})

	return resp, nil
}
