package globiguard

import "net/http"

type ActionGatewayMode string

const (
	ActionGatewayControlPlane ActionGatewayMode = "control_plane"
	ActionGatewaySidecar      ActionGatewayMode = "sidecar"
	ActionGatewayGateway      ActionGatewayMode = "gateway"
)

type ActionGatewayConfig struct {
	Mode ActionGatewayMode
}

type ClientConfig struct {
	Environment   Environment
	Services      map[string]string
	Credential    Credential
	ActionGateway ActionGatewayConfig
	ClientName    string
	HTTPClient    *http.Client
}

type ServerClient struct {
	Kind            string
	Environment     Environment
	ActionGateway   ActionGatewayConfig
	ControlPlane    Transport
	Brain           *Transport
	Gateway         *Transport
	Sidecar         *Transport
	Actions         ActionsClient
	Audit           AuditClient
	Installs        InstallsClient
	Orgs            OrgsClient
	Policies        PoliciesClient
	Queue           QueueClient
	Workflows       WorkflowsClient
	GovernedActions GovernedActionsClient
}

type BrowserClient struct {
	Kind        string
	Environment Environment
	Actions     ActionsClient
	Audit       AuditClient
	Installs    InstallsClient
	Policies    PoliciesClient
	Queue       QueueClient
	Workflows   WorkflowsClient
}

func NewServerClient(config ClientConfig) (*ServerClient, error) {
	if config.ClientName == "" {
		config.ClientName = "globiguard-go"
	}
	if config.Services["controlPlane"] == "" {
		return nil, &ConfigError{Message: "controlPlane service URL is required."}
	}
	if err := assertServerCredential(config.Credential, config.Environment); err != nil {
		return nil, err
	}
	requireLocal := config.Credential.Kind == CredentialLocal
	for _, serviceName := range []string{"controlPlane", "brain", "gateway", "sidecar"} {
		if serviceURL := config.Services[serviceName]; serviceURL != "" {
			if err := AssertServiceURL(serviceName, serviceURL, config.Environment, requireLocal); err != nil {
				return nil, err
			}
		}
	}
	controlPlane := newTransport(config, config.Services["controlPlane"])
	brain := optionalTransport(config, config.Services["brain"])
	gateway := optionalTransport(config, config.Services["gateway"])
	sidecar := optionalTransport(config, config.Services["sidecar"])
	actionGateway := config.ActionGateway
	if actionGateway.Mode == "" {
		actionGateway.Mode = ActionGatewayControlPlane
	}
	actionTransport, err := resolveActionTransport(actionGateway, &controlPlane, gateway, sidecar)
	if err != nil {
		return nil, err
	}
	actions := ActionsClient{Transport: *actionTransport}
	audit := AuditClient{Transport: controlPlane}
	queue := QueueClient{Transport: controlPlane}
	return &ServerClient{
		Kind:          "server",
		Environment:   config.Environment,
		ActionGateway: actionGateway,
		ControlPlane:  controlPlane,
		Brain:         brain,
		Gateway:       gateway,
		Sidecar:       sidecar,
		Actions:       actions,
		Audit:         audit,
		Installs:      InstallsClient{Transport: controlPlane},
		Orgs:          OrgsClient{Transport: controlPlane},
		Policies:      PoliciesClient{Transport: controlPlane},
		Queue:         queue,
		Workflows:     WorkflowsClient{Transport: controlPlane},
		GovernedActions: GovernedActionsClient{
			Actions: actions,
			Audit:   audit,
			Queue:   queue,
		},
	}, nil
}

func NewBrowserClient(config ClientConfig) (*BrowserClient, error) {
	if config.ClientName == "" {
		config.ClientName = "globiguard-go"
	}
	if config.Services["controlPlane"] == "" {
		return nil, &ConfigError{Message: "controlPlane service URL is required."}
	}
	if err := assertBrowserCredential(config.Credential, config.Environment); err != nil {
		return nil, err
	}
	if err := AssertServiceURL("controlPlane", config.Services["controlPlane"], config.Environment, config.Credential.Kind == CredentialLocal); err != nil {
		return nil, err
	}
	controlPlane := newTransport(config, config.Services["controlPlane"])
	return &BrowserClient{
		Kind:        "browser",
		Environment: config.Environment,
		Actions:     ActionsClient{Transport: controlPlane, ReadOnly: true},
		Audit:       AuditClient{Transport: controlPlane, ReadOnly: true},
		Installs:    InstallsClient{Transport: controlPlane},
		Policies:    PoliciesClient{Transport: controlPlane, ReadOnly: true},
		Queue:       QueueClient{Transport: controlPlane, ReadOnly: true},
		Workflows:   WorkflowsClient{Transport: controlPlane, ReadOnly: true},
	}, nil
}

func newTransport(config ClientConfig, baseURL string) Transport {
	return Transport{
		BaseURL:     baseURL,
		ClientName:  config.ClientName,
		Credential:  config.Credential,
		Environment: config.Environment,
		HTTPClient:  config.HTTPClient,
	}
}

func optionalTransport(config ClientConfig, baseURL string) *Transport {
	if baseURL == "" {
		return nil
	}
	transport := newTransport(config, baseURL)
	return &transport
}

func resolveActionTransport(config ActionGatewayConfig, controlPlane *Transport, gateway *Transport, sidecar *Transport) (*Transport, error) {
	switch config.Mode {
	case ActionGatewayControlPlane:
		return controlPlane, nil
	case ActionGatewayGateway:
		if gateway == nil {
			return nil, &ConfigError{Message: "Action gateway mode 'gateway' requires services.gateway."}
		}
		return gateway, nil
	case ActionGatewaySidecar:
		if sidecar == nil {
			return nil, &ConfigError{Message: "Action gateway mode 'sidecar' requires services.sidecar."}
		}
		return sidecar, nil
	default:
		return nil, &ConfigError{Message: "Action gateway mode must be control_plane, sidecar, or gateway."}
	}
}

func assertServerCredential(credential Credential, environment Environment) error {
	if credential.Kind == CredentialPublishable {
		return &ConfigError{Message: "Server clients require secret or local credentials."}
	}
	if credential.Kind != CredentialSecret && credential.Kind != CredentialLocal {
		return &ConfigError{Message: "Server clients require a recognized secret or local credential kind."}
	}
	if credential.Kind == CredentialLocal && environment != EnvironmentLocal {
		return &ConfigError{Message: "Local credentials may only be used with the local environment."}
	}
	if credential.Kind == CredentialSecret {
		if err := requireNonEmpty("projectId", credential.ProjectID); err != nil {
			return err
		}
		if err := requireNonEmpty("token", credential.Token); err != nil {
			return err
		}
		if credential.Environment != environment {
			return &ConfigError{Message: "Secret credential environment must match the client environment."}
		}
	}
	return nil
}

func assertBrowserCredential(credential Credential, environment Environment) error {
	if credential.Kind == CredentialSecret {
		return &ConfigError{Message: "Browser clients require publishable or local credentials."}
	}
	if credential.Kind != CredentialPublishable && credential.Kind != CredentialLocal {
		return &ConfigError{Message: "Browser clients require a recognized publishable or local credential kind."}
	}
	if credential.Kind == CredentialLocal && environment != EnvironmentLocal {
		return &ConfigError{Message: "Local credentials may only be used with the local environment."}
	}
	if credential.Kind == CredentialPublishable {
		if err := requireNonEmpty("projectId", credential.ProjectID); err != nil {
			return err
		}
		if err := requireNonEmpty("token", credential.Token); err != nil {
			return err
		}
	}
	return nil
}
