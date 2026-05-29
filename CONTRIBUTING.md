# Contributing

GlobiGuard Go SDK changes should keep the runtime dependency surface at zero unless a security review accepts a specific exception.

## Validate locally

```bash
go test ./...
go vet ./...
```

Before opening a pull request, verify examples use placeholder secrets only and pass raw webhook bodies into verification.

