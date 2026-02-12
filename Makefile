.PHONY: test test-unit test-acc test-fuzz clean build help install-deps

# Default test target - run all tests
test:
	@echo "Running all tests..."
	@go test ./... -v

# Unit tests only (no external dependencies, <5s)
test-unit:
	@echo "Running unit tests..."
	@go test ./internal/provider -run="^Test[^A]" -timeout=5m -v

# Acceptance tests (requires TF_ACC=1)
test-acc:
	@echo "Running acceptance tests..."
	@if [ -z "$(TF_ACC)" ]; then \
		echo "Error: TF_ACC environment variable not set. See TESTING.md"; \
		exit 1; \
	fi
	@go test ./internal/provider -run="^TestAcc" -timeout=30m -v

# Fuzz tests (90s default, based on Go fuzzing docs)
test-fuzz:
	@echo "Running fuzz tests (90s default)..."
	@go test -fuzz=FuzzInjectAppSettings -fuzztime=90s
	@go test -fuzz=FuzzGetPolicyId -fuzztime=60s

# Install test dependencies
install-deps:
	@echo "Installing test dependencies..."
	@go mod tidy
	@go mod download

# Build the provider
build:
	@echo "Building provider..."
	@go build -o terraform-provider-azure-b2c-ief

# Clean test artifacts and build files
clean:
	@echo "Cleaning up..."
	@rm -rf .terraform/
	@rm -f terraform-provider-azure-b2c-ief*
	@rm -f terraform.crash.log
	@rm -f terraform.tfplan
	@rm -f terraform.tfstate

# Install provider locally
install: build
	@echo "Installing provider to ~/.terraform.d/plugins..."
	@mkdir -p ~/.terraform.d/plugins/$(shell go env GOOS)_$(shell go env GOARCH)/local/azure-b2c-ief/0.1.0/
	@cp terraform-provider-azure-b2c-ief ~/.terraform.d/plugins/$(shell go env GOOS)_$(shell go env GOARCH)/local/azure-b2c-ief/0.1.0/

# Run specific acceptance test (useful for development)
test-acc-key:
	@echo "Running policy key acceptance tests..."
	@if [ -z "$(TF_ACC)" ]; then \
		echo "Error: TF_ACC environment variable not set. See TESTING.md"; \
		exit 1; \
	fi
	@go test ./internal/provider -run="^TestAccPolicyKey" -timeout=15m -v

test-acc-policy:
	@echo "Running policy acceptance tests..."
	@if [ -z "$(TF_ACC)" ]; then \
		echo "Error: TF_ACC environment variable not set. See TESTING.md"; \
		exit 1; \
	fi
	@go test ./internal/provider -run="^TestAccPolicy" -timeout=15m -v

# Help target
help:
	@echo "Available targets:"
	@echo "  test      - Run all tests"
	@echo "  test-unit - Run unit tests only"
	@echo "  test-acc  - Run acceptance tests (requires TF_ACC=1)"
	@echo "  test-fuzz - Run fuzz tests (90s default)"
	@echo "  test-acc-key - Run policy key acceptance tests only"
	@echo "  test-acc-policy - Run policy acceptance tests only"
	@echo "  build     - Build the provider"
	@echo "  install   - Install provider locally"
	@echo "  install-deps - Install test dependencies"
	@echo "  clean     - Clean test artifacts"
	@echo "  help      - Show this help"
	@echo ""
	@echo "Examples:"
	@echo "  make test-unit              # Fast unit tests for development"
	@echo "  source testing.env && make test-acc  # Full acceptance test run"