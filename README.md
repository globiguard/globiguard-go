# globiguard-go

Official dependency-minimal Go SDK for GlobiGuard.

The SDK uses only the Go standard library at runtime. It mirrors the TypeScript/Python SDK contracts for auth headers, governed actions, install bootstrap, trust webhooks, and offline entitlement manifests.

## Install

```bash
go get github.com/globiguard/globiguard-go
```

## Server client

```go
client, err := globiguard.NewServerClient(globiguard.ClientConfig{
    Environment: globiguard.EnvironmentSandbox,
    Services: map[string]string{
        "controlPlane": "https://api.globiguard.com",
    },
    Credential: globiguard.SecretCredential(
        "proj_123",
        "ggsk_test_...",
        globiguard.EnvironmentSandbox,
    ),
})
if err != nil {
    return err
}

decision, err := client.GovernedActions.AuthorizeActionOrThrow(ctx, map[string]any{
    "actionType": "refund",
    "actor": map[string]any{"id": "user_123"},
})
```

## Auth and keys

GlobiGuard project IDs, secret keys, publishable keys, local credentials, and webhook signing secrets are issued by the GlobiGuard app/control plane. SDK credentials use `local`, `sandbox`, or `live` environments and send the same `x-globiguard-*` headers as the TypeScript SDK.

Server clients accept secret or local credentials. Browser-style clients accept publishable or local credentials. Local credentials are limited to localhost/loopback service URLs.

## Webhooks

```go
result := globiguard.VerifyTrustWebhook(globiguard.WebhookVerificationRequest{
    Headers:       r.Header,
    RawBody:       rawBody,
    SigningSecret: "whsec_...",
})
if !result.OK {
    return fmt.Errorf(result.Error["message"].(string))
}
```

Pass the exact raw request body bytes. Do not parse and re-serialize JSON before verification.

## Bootstrap and entitlements

```go
registration, err := globiguard.BuildInstallRegistrationRequest(
    globiguard.BootstrapProfile{
        Environment:      globiguard.EnvironmentSandbox,
        DeploymentMode:   globiguard.DeploymentSelfHosted,
        IssuerMode:       globiguard.IssuerCustomerIssued,
        InstallReporting: globiguard.InstallReportingOptIn,
    },
    "globiguard-go",
    "0.1.0",
    "sdk",
    "go",
    nil,
)
```

Offline entitlement manifests verify compact JWS structure, Ed25519 signatures, schema, timestamps, and optional issuer/workspace/project/environment/deployment expectations using `crypto/ed25519`.

## Security posture

- Runtime dependencies: **zero**.
- HTTPS is required outside local.
- Local credentials require localhost or loopback URLs.
- Reserved GlobiGuard auth headers cannot be overridden by per-request headers.
- Request paths reject absolute URLs, query strings, fragments, backslashes, invalid percent encoding, and dot segments.
- Trust webhooks require raw-body HMAC verification with replay-window checks.

## Development

```bash
go test ./...
go vet ./...
```
