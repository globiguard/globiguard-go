package globiguard

import (
	"context"
	"net/http"
)

type ActionsClient struct {
	Transport Transport
	ReadOnly  bool
}

func (c ActionsClient) GetAuthorization(ctx context.Context, authorizationID string, out any) error {
	return c.Transport.Request(ctx, "/v1/actions/authorizations/"+EncodePathSegment(authorizationID), http.MethodGet, nil, nil, nil, out)
}

func (c ActionsClient) GetApproval(ctx context.Context, approvalID string, out any) error {
	return c.Transport.Request(ctx, "/v1/actions/approvals/"+EncodePathSegment(approvalID), http.MethodGet, nil, nil, nil, out)
}

func (c ActionsClient) ListEvidence(ctx context.Context, query map[string]QueryValue, out any) error {
	return c.Transport.Request(ctx, "/v1/actions/evidence", http.MethodGet, query, nil, nil, out)
}

func (c ActionsClient) GetEvidence(ctx context.Context, evidenceRefID string, out any) error {
	return c.Transport.Request(ctx, "/v1/actions/evidence/"+EncodePathSegment(evidenceRefID), http.MethodGet, nil, nil, nil, out)
}

func (c ActionsClient) Authorize(ctx context.Context, request any, out any) error {
	if c.ReadOnly {
		return &ConfigError{Message: "Authorize requires a server client."}
	}
	return c.Transport.Request(ctx, "/v1/actions/authorize", http.MethodPost, nil, request, nil, out)
}

func (c ActionsClient) CreateApproval(ctx context.Context, request any, out any) error {
	if c.ReadOnly {
		return &ConfigError{Message: "CreateApproval requires a server client."}
	}
	return c.Transport.Request(ctx, "/v1/actions/approvals", http.MethodPost, nil, request, nil, out)
}

type AuditClient struct {
	Transport Transport
	ReadOnly  bool
}

func (c AuditClient) List(ctx context.Context, query map[string]QueryValue, out any) error {
	return c.Transport.Request(ctx, "/v1/audit", http.MethodGet, query, nil, nil, out)
}

func (c AuditClient) Get(ctx context.Context, auditEventID string, out any) error {
	return c.Transport.Request(ctx, "/v1/audit/"+EncodePathSegment(auditEventID), http.MethodGet, nil, nil, nil, out)
}

func (c AuditClient) Export(ctx context.Context, request any, out any) error {
	if c.ReadOnly {
		return &ConfigError{Message: "Export requires a server client."}
	}
	if request == nil {
		request = map[string]any{}
	}
	return c.Transport.Request(ctx, "/v1/audit/export", http.MethodPost, nil, request, nil, out)
}

func (c AuditClient) GetEvidencePackageSummary(ctx context.Context, evidencePackageID string, out any) error {
	return c.Transport.Request(ctx, "/v1/audit/evidence-packages/"+EncodePathSegment(evidencePackageID)+"/summary", http.MethodGet, nil, nil, nil, out)
}

func (c AuditClient) GetIncidentReplay(ctx context.Context, query map[string]QueryValue, out any) error {
	return c.Transport.Request(ctx, "/v1/audit/incident-replay", http.MethodGet, query, nil, nil, out)
}

type InstallsClient struct {
	Transport Transport
}

func (c InstallsClient) Register(ctx context.Context, request any, out any) error {
	return c.Transport.Request(ctx, "/v1/installs", http.MethodPost, nil, request, nil, out)
}

func (c InstallsClient) Heartbeat(ctx context.Context, installID string, request any, out any) error {
	return c.Transport.Request(ctx, "/v1/installs/"+EncodePathSegment(installID)+"/heartbeats", http.MethodPost, nil, request, nil, out)
}

type OrgsClient struct {
	Transport Transport
}

func (c OrgsClient) FindBySlug(ctx context.Context, slug string, out any) error {
	return c.Transport.Request(ctx, "/v1/orgs", http.MethodGet, map[string]QueryValue{"slug": slug}, nil, nil, out)
}

func (c OrgsClient) Create(ctx context.Context, request any, out any) error {
	return c.Transport.Request(ctx, "/v1/orgs", http.MethodPost, nil, request, nil, out)
}

func (c OrgsClient) Get(ctx context.Context, orgID string, out any) error {
	return c.Transport.Request(ctx, "/v1/orgs/"+EncodePathSegment(orgID), http.MethodGet, nil, nil, nil, out)
}

func (c OrgsClient) Update(ctx context.Context, orgID string, request any, out any) error {
	return c.Transport.Request(ctx, "/v1/orgs/"+EncodePathSegment(orgID), http.MethodPatch, nil, request, nil, out)
}

func (c OrgsClient) CreateAPIKey(ctx context.Context, orgID string, request any, out any) error {
	return c.Transport.Request(ctx, "/v1/orgs/"+EncodePathSegment(orgID)+"/api-keys", http.MethodPost, nil, request, nil, out)
}

func (c OrgsClient) ListAPIKeys(ctx context.Context, orgID string, out any) error {
	return c.Transport.Request(ctx, "/v1/orgs/"+EncodePathSegment(orgID)+"/api-keys", http.MethodGet, nil, nil, nil, out)
}

func (c OrgsClient) RevokeAPIKey(ctx context.Context, orgID string, apiKeyID string) error {
	return c.Transport.Request(ctx, "/v1/orgs/"+EncodePathSegment(orgID)+"/api-keys/"+EncodePathSegment(apiKeyID), http.MethodDelete, nil, nil, nil, nil)
}

type PoliciesClient struct {
	Transport Transport
	ReadOnly  bool
}

func (c PoliciesClient) List(ctx context.Context, active bool, industry string, out any) error {
	query := map[string]QueryValue{"active": active}
	if industry != "" {
		query["industry"] = industry
	}
	return c.Transport.Request(ctx, "/v1/policies", http.MethodGet, query, nil, nil, out)
}

func (c PoliciesClient) ListTemplates(ctx context.Context, industry string, out any) error {
	query := map[string]QueryValue{}
	if industry != "" {
		query["industry"] = industry
	}
	return c.Transport.Request(ctx, "/v1/policies/templates", http.MethodGet, query, nil, nil, out)
}

func (c PoliciesClient) Get(ctx context.Context, policyID string, out any) error {
	return c.Transport.Request(ctx, "/v1/policies/"+EncodePathSegment(policyID), http.MethodGet, nil, nil, nil, out)
}

func (c PoliciesClient) Create(ctx context.Context, request any, out any) error {
	if c.ReadOnly {
		return &ConfigError{Message: "Create requires a server client."}
	}
	return c.Transport.Request(ctx, "/v1/policies", http.MethodPost, nil, request, nil, out)
}

func (c PoliciesClient) CreateFromTemplate(ctx context.Context, templateID string, out any) error {
	if c.ReadOnly {
		return &ConfigError{Message: "CreateFromTemplate requires a server client."}
	}
	return c.Transport.Request(ctx, "/v1/policies/from-template/"+EncodePathSegment(templateID), http.MethodPost, nil, nil, nil, out)
}

func (c PoliciesClient) Update(ctx context.Context, policyID string, request any, out any) error {
	if c.ReadOnly {
		return &ConfigError{Message: "Update requires a server client."}
	}
	return c.Transport.Request(ctx, "/v1/policies/"+EncodePathSegment(policyID), http.MethodPut, nil, request, nil, out)
}

func (c PoliciesClient) Remove(ctx context.Context, policyID string) error {
	if c.ReadOnly {
		return &ConfigError{Message: "Remove requires a server client."}
	}
	return c.Transport.Request(ctx, "/v1/policies/"+EncodePathSegment(policyID), http.MethodDelete, nil, nil, nil, nil)
}

func (c PoliciesClient) Activate(ctx context.Context, policyID string, out any) error {
	if c.ReadOnly {
		return &ConfigError{Message: "Activate requires a server client."}
	}
	return c.Transport.Request(ctx, "/v1/policies/"+EncodePathSegment(policyID)+"/activate", http.MethodPost, nil, nil, nil, out)
}

type QueueClient struct {
	Transport Transport
	ReadOnly  bool
}

func (c QueueClient) List(ctx context.Context, status string, out any) error {
	query := map[string]QueryValue{}
	if status != "" {
		query["status"] = status
	}
	return c.Transport.Request(ctx, "/v1/queue", http.MethodGet, query, nil, nil, out)
}

func (c QueueClient) Get(ctx context.Context, queueEntryID string, out any) error {
	return c.Transport.Request(ctx, "/v1/queue/"+EncodePathSegment(queueEntryID), http.MethodGet, nil, nil, nil, out)
}

func (c QueueClient) Decide(ctx context.Context, queueEntryID string, action string, reviewedBy string, notes string, out any) error {
	if c.ReadOnly {
		return &ConfigError{Message: "Decide requires a server client."}
	}
	body := map[string]any{"reviewedBy": reviewedBy, "notes": notes}
	return c.Transport.Request(ctx, "/v1/queue/"+EncodePathSegment(queueEntryID)+"/"+action, http.MethodPost, nil, body, nil, out)
}

type WorkflowsClient struct {
	Transport Transport
	ReadOnly  bool
}

func (c WorkflowsClient) List(ctx context.Context, active bool, out any) error {
	return c.Transport.Request(ctx, "/v1/workflows", http.MethodGet, map[string]QueryValue{"active": active}, nil, nil, out)
}

func (c WorkflowsClient) Get(ctx context.Context, workflowID string, out any) error {
	return c.Transport.Request(ctx, "/v1/workflows/"+EncodePathSegment(workflowID), http.MethodGet, nil, nil, nil, out)
}

func (c WorkflowsClient) Create(ctx context.Context, request any, out any) error {
	if c.ReadOnly {
		return &ConfigError{Message: "Create requires a server client."}
	}
	return c.Transport.Request(ctx, "/v1/workflows", http.MethodPost, nil, request, nil, out)
}

func (c WorkflowsClient) Update(ctx context.Context, workflowID string, request any, out any) error {
	if c.ReadOnly {
		return &ConfigError{Message: "Update requires a server client."}
	}
	return c.Transport.Request(ctx, "/v1/workflows/"+EncodePathSegment(workflowID), http.MethodPut, nil, request, nil, out)
}

func (c WorkflowsClient) Remove(ctx context.Context, workflowID string) error {
	if c.ReadOnly {
		return &ConfigError{Message: "Remove requires a server client."}
	}
	return c.Transport.Request(ctx, "/v1/workflows/"+EncodePathSegment(workflowID), http.MethodDelete, nil, nil, nil, nil)
}

func (c WorkflowsClient) Activate(ctx context.Context, workflowID string, out any) error {
	if c.ReadOnly {
		return &ConfigError{Message: "Activate requires a server client."}
	}
	return c.Transport.Request(ctx, "/v1/workflows/"+EncodePathSegment(workflowID)+"/activate", http.MethodPost, nil, nil, nil, out)
}

func (c WorkflowsClient) Run(ctx context.Context, workflowID string, triggerData any, out any) error {
	if c.ReadOnly {
		return &ConfigError{Message: "Run requires a server client."}
	}
	if triggerData == nil {
		triggerData = map[string]any{}
	}
	return c.Transport.Request(ctx, "/v1/workflows/"+EncodePathSegment(workflowID)+"/run", http.MethodPost, nil, triggerData, nil, out)
}

func (c WorkflowsClient) ListRuns(ctx context.Context, workflowID string, out any) error {
	return c.Transport.Request(ctx, "/v1/workflows/"+EncodePathSegment(workflowID)+"/runs", http.MethodGet, nil, nil, nil, out)
}
