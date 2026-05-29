package globiguard

type Environment string

const (
	EnvironmentLocal   Environment = "local"
	EnvironmentSandbox Environment = "sandbox"
	EnvironmentLive    Environment = "live"
)

type CredentialKind string

const (
	CredentialPublishable CredentialKind = "publishable"
	CredentialSecret      CredentialKind = "secret"
	CredentialLocal       CredentialKind = "local"
)

type Credential struct {
	Kind        CredentialKind
	ProjectID   string
	Token       string
	Environment Environment
}

func PublishableCredential(projectID, token string) Credential {
	return Credential{Kind: CredentialPublishable, ProjectID: projectID, Token: token}
}

func SecretCredential(projectID, token string, environment Environment) Credential {
	return Credential{Kind: CredentialSecret, ProjectID: projectID, Token: token, Environment: environment}
}

func LocalCredential(token string) Credential {
	return Credential{Kind: CredentialLocal, Token: token}
}

func requireNonEmpty(name, value string) error {
	if value == "" {
		return &ConfigError{Message: name + " must be a non-empty string."}
	}
	return nil
}
