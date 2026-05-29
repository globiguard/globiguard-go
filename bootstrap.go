package globiguard

type DeploymentMode string
type InstallIssuerMode string
type InstallReportingMode string

const (
	DeploymentHosted     DeploymentMode = "hosted"
	DeploymentSelfHosted DeploymentMode = "self_hosted"
	DeploymentSovereign  DeploymentMode = "sovereign"

	IssuerGlobiguardIssued InstallIssuerMode = "globiguard_issued"
	IssuerCustomerIssued   InstallIssuerMode = "customer_issued"

	InstallReportingDefault  InstallReportingMode = "default"
	InstallReportingOptIn    InstallReportingMode = "opt_in"
	InstallReportingDisabled InstallReportingMode = "disabled"
)

type BootstrapProfile struct {
	Environment        Environment
	DeploymentMode     DeploymentMode
	IssuerMode         InstallIssuerMode
	InstallReporting   InstallReportingMode
	InstallLabel       string
	InstallFingerprint string
}

type ResolvedBootstrapProfile struct {
	BootstrapProfile
	InstallRegistrationAllowed bool
}

func ResolveBootstrapProfile(profile BootstrapProfile) (ResolvedBootstrapProfile, error) {
	if !allowedEnvironment(profile.Environment) {
		return ResolvedBootstrapProfile{}, &ConfigError{Message: "environment must be one of: local, sandbox, live."}
	}
	if profile.DeploymentMode != DeploymentHosted && profile.DeploymentMode != DeploymentSelfHosted && profile.DeploymentMode != DeploymentSovereign {
		return ResolvedBootstrapProfile{}, &ConfigError{Message: "deploymentMode must be one of: hosted, self_hosted, sovereign."}
	}
	if profile.IssuerMode != IssuerGlobiguardIssued && profile.IssuerMode != IssuerCustomerIssued {
		return ResolvedBootstrapProfile{}, &ConfigError{Message: "issuerMode must be one of: globiguard_issued, customer_issued."}
	}
	if profile.InstallReporting != InstallReportingDefault && profile.InstallReporting != InstallReportingOptIn && profile.InstallReporting != InstallReportingDisabled {
		return ResolvedBootstrapProfile{}, &ConfigError{Message: "installReporting must be one of: default, opt_in, disabled."}
	}
	if profile.DeploymentMode == DeploymentHosted && profile.IssuerMode != IssuerGlobiguardIssued {
		return ResolvedBootstrapProfile{}, &ConfigError{Message: "Hosted deployments must use globiguard-issued bootstrap credentials."}
	}
	if profile.DeploymentMode != DeploymentHosted && profile.IssuerMode != IssuerCustomerIssued {
		return ResolvedBootstrapProfile{}, &ConfigError{Message: "Self-hosted and sovereign deployments must use customer-issued bootstrap credentials."}
	}
	if profile.DeploymentMode != DeploymentHosted && profile.InstallReporting == InstallReportingDefault {
		return ResolvedBootstrapProfile{}, &ConfigError{Message: "Self-hosted and sovereign deployments must set installReporting to opt_in or disabled explicitly."}
	}
	return ResolvedBootstrapProfile{
		BootstrapProfile:           profile,
		InstallRegistrationAllowed: profile.InstallReporting != InstallReportingDisabled,
	}, nil
}

func BuildInstallRegistrationRequest(profile BootstrapProfile, packageName, packageVersion, integrationKind, runtimeKind string, metadata map[string]any) (map[string]any, error) {
	resolved, err := ResolveBootstrapProfile(profile)
	if err != nil {
		return nil, err
	}
	if !resolved.InstallRegistrationAllowed {
		return nil, &ConfigError{Message: "Install registration and heartbeat are disabled for this bootstrap profile."}
	}
	return map[string]any{
		"packageName":        packageName,
		"packageVersion":     packageVersion,
		"integrationKind":    integrationKind,
		"runtimeKind":        runtimeKind,
		"environment":        resolved.Environment,
		"deploymentMode":     resolved.DeploymentMode,
		"issuerMode":         resolved.IssuerMode,
		"installReporting":   resolved.InstallReporting,
		"installLabel":       resolved.InstallLabel,
		"installFingerprint": resolved.InstallFingerprint,
		"metadata":           metadata,
	}, nil
}

func BuildInstallHeartbeatRequest(profile BootstrapProfile, packageVersion, runtimeKind string, metadata map[string]any) (map[string]any, error) {
	resolved, err := ResolveBootstrapProfile(profile)
	if err != nil {
		return nil, err
	}
	if !resolved.InstallRegistrationAllowed {
		return nil, &ConfigError{Message: "Install registration and heartbeat are disabled for this bootstrap profile."}
	}
	return map[string]any{
		"packageVersion":     packageVersion,
		"runtimeKind":        runtimeKind,
		"environment":        resolved.Environment,
		"deploymentMode":     resolved.DeploymentMode,
		"issuerMode":         resolved.IssuerMode,
		"installReporting":   resolved.InstallReporting,
		"installLabel":       resolved.InstallLabel,
		"installFingerprint": resolved.InstallFingerprint,
		"metadata":           metadata,
	}, nil
}

func allowedEnvironment(environment Environment) bool {
	return environment == EnvironmentLocal || environment == EnvironmentSandbox || environment == EnvironmentLive
}
