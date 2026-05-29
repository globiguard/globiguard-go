package globiguard

import "fmt"

type ConfigError struct {
	Message string
}

func (e *ConfigError) Error() string {
	return e.Message
}

type HTTPError struct {
	Status int
	Body   any
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("GlobiGuard request failed with status %d.", e.Status)
}

type AuthorityError struct {
	Kind              string
	Message           string
	AuthorizationID   string
	QueueEntryID      string
	EvidencePackageID string
	RetryAfterSeconds int
	SafeDetails       map[string]any
}

func (e *AuthorityError) Error() string {
	return e.Message
}
