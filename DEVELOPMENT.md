# GlobiGuard Go SDK - Development Guide

## CI/CD Pipeline Overview

This repository uses GitHub Actions for automated testing, building, and publishing.

### Workflows

#### 1. **Test & Lint** (`test.yml`)
- **Triggers:** Every push to `main`/`develop`, and on all pull requests
- **What it does:**
  - Tests across Go 1.22 and 1.23
  - Runs `go fmt` and `go vet`
  - Executes tests with coverage reporting
- **Status check:** ✅ Must pass before merging to `main`

#### 2. **Build & Package** (`build.yml`)
- **Triggers:** Every push to `main`/`develop`, and on all pull requests
- **What it does:**
  - Cross-compiles for Linux, macOS, and Windows
  - Verifies build artifacts
  - Uploads binaries to GitHub Artifacts
- **Purpose:** Early detection of build issues

#### 3. **Publish** (`publish.yml`)
- **Triggers:** When a git tag matching `v*.*.*` is pushed
- **What it does:**
  - Creates GitHub Release
  - Go module is automatically indexed by pkg.go.dev
- **Usage:**
  ```bash
  git tag v0.1.0
  git push origin v0.1.0
  ```

#### 4. **Security Scan** (`security.yml`)
- **Triggers:** Every push to `main`/`develop`, weekly on Sunday
- **What it does:**
  - Runs `gosec` for security vulnerabilities
  - Runs `go vet` for code issues
- **Purpose:** Continuous security monitoring

### Branch Protection

The `main` branch is protected with:
- ✅ Require 1 pull request review before merging
- ✅ Require all status checks to pass
- ✅ Require branches to be up to date before merging
- ✅ Dismiss stale pull request approvals on new commits
- ✅ Require code owner reviews
- ❌ Force pushes disabled
- ❌ Deletions disabled

### Versioning Strategy

We use **Semantic Versioning** (major.minor.patch):

- **v0.1.0** → Initial release
- **v0.1.1** → Patch fix
- **v0.2.0** → Minor feature
- **v1.0.0** → Major release (breaking changes)

### Publishing Workflow

```bash
# 1. Make changes on a feature branch
git checkout -b feat/new-feature
git commit -m "feat: new feature"
git push origin feat/new-feature

# 2. Create PR, review, merge to main

# 3. Tag release
git tag v0.1.0
git push origin v0.1.0

# 4. Watch CI/CD create release
# Go module automatically available via:
# go get github.com/globiguard/globiguard-go@v0.1.0
```

### Development Cycle

1. **Create feature branch:** `git checkout -b feature/name main`
2. **Make changes:** Edit code, test locally
3. **Run tests locally:** `go test ./...`
4. **Commit:** `git commit -m "feat: description"`
5. **Push:** `git push origin feature/name`
6. **Create PR:** Open GitHub pull request to `main`
7. **Review:** Automated tests and code review
8. **Merge:** Merge PR to `main`
9. **Publish (optional):** Tag release with `git tag v0.X.X`

### Local Testing

```bash
# Run tests
go test -v ./...

# Run tests with coverage
go test -v -cover -coverprofile=coverage.out ./...

# Run linting
go fmt ./...
go vet ./...

# Run security check locally
gosec ./...
```

### Code Owners

Code ownership is defined in `.github/CODEOWNERS`:
- All files: `@globi-explore/maintainers`
- PRs require approval from code owners before merge

### Repository Configuration

- **Default branch:** `main`
- **Discussions:** Enabled (for Q&A)
- **Releases:** Auto-generated from tags
- **Topics:** `globiguard`, `sdk`, `governance`, `go`
- **Visibility:** Public

## Troubleshooting

**Build fails on Windows?**
- Ensure Go 1.22+ is installed
- Check for hardcoded paths (use filepath.Join)

**Tests fail?**
- Run `go clean -testcache && go test ./...`
- Check for race conditions: `go test -race ./...`

**Module not appearing on pkg.go.dev?**
- Wait a few minutes after tagging
- Visit https://pkg.go.dev/github.com/globiguard/globiguard-go

## Questions?

See main repository README or GitHub Discussions for Q&A.
