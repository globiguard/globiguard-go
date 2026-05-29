package globiguard

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

type IdempotencyKeyInput struct {
	StableSeed    string
	ActionType    string
	ActorID       string
	PayloadSHA256 string
	WindowBucket  string
}

type GovernedActionsClient struct {
	Actions ActionsClient
	Audit   AuditClient
	Queue   QueueClient
}

func DeriveActionIdempotencyKey(input IdempotencyKeyInput) (string, error) {
	if input.StableSeed == "" {
		return "", &ConfigError{Message: "stableSeed must be a non-empty string."}
	}
	if input.ActionType == "" {
		return "", &ConfigError{Message: "actionType must be a non-empty string."}
	}
	payload, err := json.Marshal(struct {
		StableSeed    string `json:"stableSeed"`
		ActionType    string `json:"actionType"`
		ActorID       any    `json:"actorId"`
		PayloadSHA256 any    `json:"payloadSha256"`
		WindowBucket  any    `json:"windowBucket"`
	}{
		StableSeed:    input.StableSeed,
		ActionType:    input.ActionType,
		ActorID:       nilIfEmpty(input.ActorID),
		PayloadSHA256: nilIfEmpty(input.PayloadSHA256),
		WindowBucket:  nilIfEmpty(input.WindowBucket),
	})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return "gg_idem_" + hex.EncodeToString(digest[:])[:48], nil
}

func GenerateCorrelationID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (c GovernedActionsClient) AuthorizeAction(ctx context.Context, request any, out any) error {
	return c.Actions.Authorize(ctx, request, out)
}

func (c GovernedActionsClient) AuthorizeActionOrThrow(ctx context.Context, request any) (map[string]any, error) {
	var decision map[string]any
	if err := c.Actions.Authorize(ctx, request, &decision); err != nil {
		return nil, err
	}
	switch decision["decision"] {
	case "BLOCK":
		return nil, &AuthorityError{
			Kind:            "POLICY_BLOCKED",
			Message:         "GlobiGuard blocked the governed action.",
			AuthorizationID: stringValue(decision["authorizationId"]),
			QueueEntryID:    stringValue(decision["queueEntryId"]),
			SafeDetails: map[string]any{
				"decision": decision["decision"],
				"reason":   decision["reason"],
			},
		}
	case "QUEUE":
		return nil, &AuthorityError{
			Kind:            "QUEUED_FOR_REVIEW",
			Message:         "GlobiGuard queued the governed action for review; do not perform the downstream business action yet.",
			AuthorizationID: stringValue(decision["authorizationId"]),
			QueueEntryID:    stringValue(decision["queueEntryId"]),
			SafeDetails: map[string]any{
				"decision":      decision["decision"],
				"approvalState": decision["approvalState"],
			},
		}
	}
	return decision, nil
}

func (c GovernedActionsClient) RequestApproval(ctx context.Context, request any, out any) error {
	return c.Actions.CreateApproval(ctx, request, out)
}

func (c GovernedActionsClient) GetApprovalStatus(ctx context.Context, approvalID string, out any) error {
	return c.Actions.GetApproval(ctx, approvalID, out)
}

func (c GovernedActionsClient) GetEvidenceReferences(ctx context.Context, query map[string]QueryValue, out any) error {
	return c.Actions.ListEvidence(ctx, query, out)
}

func (c GovernedActionsClient) ExportEvidencePackage(ctx context.Context, request any, out any) error {
	return c.Audit.Export(ctx, request, out)
}

func (c GovernedActionsClient) GetEvidencePackageSummary(ctx context.Context, evidencePackageID string, out any) error {
	return c.Audit.GetEvidencePackageSummary(ctx, evidencePackageID, out)
}

func (c GovernedActionsClient) GetIncidentReplay(ctx context.Context, query map[string]QueryValue, out any) error {
	return c.Audit.GetIncidentReplay(ctx, query, out)
}

func (c GovernedActionsClient) WaitForApproval(ctx context.Context, queueEntryID string, maxAttempts int, interval time.Duration) (map[string]any, error) {
	if maxAttempts < 1 {
		return nil, &ConfigError{Message: "maxAttempts must be at least 1."}
	}
	if interval == 0 {
		interval = time.Second
	}
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		var entry map[string]any
		if err := c.Queue.Get(ctx, queueEntryID, &entry); err != nil {
			return nil, err
		}
		status := stringValue(entry["status"])
		if status == "APPROVED" || status == "AUTO_APPROVED" {
			return entry, nil
		}
		if status == "REJECTED" || status == "EXPIRED" {
			return nil, &AuthorityError{
				Kind:         "POLICY_BLOCKED",
				Message:      "Queued action resolved as " + status + "; do not perform the downstream business action.",
				QueueEntryID: stringValue(entry["id"]),
				SafeDetails:  map[string]any{"status": status},
			}
		}
		if attempt < maxAttempts {
			select {
			case <-ctx.Done():
				return nil, &AuthorityError{Kind: "QUEUED_FOR_REVIEW", Message: "Approval wait was aborted while the action remained queued.", QueueEntryID: queueEntryID}
			case <-time.After(interval):
			}
		}
	}
	return nil, &AuthorityError{Kind: "QUEUED_FOR_REVIEW", Message: "Queued action is still pending after the configured wait attempts; do not perform the downstream business action yet.", QueueEntryID: queueEntryID}
}

func nilIfEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func stringValue(value any) string {
	if str, ok := value.(string); ok {
		return str
	}
	return ""
}
