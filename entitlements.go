package globiguard

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

const EntitlementManifestType = "globiguard.entitlement.v1"
const EntitlementSigningAlgorithm = "EdDSA"
const EntitlementSerialization = "jws-compact"

type VerifyEntitlementOptions struct {
	PublicKeysByID         map[string]string
	ExpectedIssuer         string
	ExpectedOrgID          string
	ExpectedProjectID      string
	ExpectedEnvironment    string
	ExpectedDeploymentMode string
	Now                    time.Time
}

func VerifySignedEntitlementManifest(manifest map[string]any, options VerifyEntitlementOptions) (map[string]any, error) {
	token, _ := manifest["token"].(string)
	decoded, err := decodeManifestToken(token)
	if err != nil {
		return nil, err
	}
	if manifest["serialization"] != EntitlementSerialization {
		return nil, &ConfigError{Message: "Unsupported entitlement manifest serialization."}
	}
	if !jsonEqual(manifest["protected"], decoded.protected) {
		return nil, &ConfigError{Message: "Entitlement manifest protected header does not match the signed token."}
	}
	if !jsonEqual(manifest["payload"], decoded.payload) {
		return nil, &ConfigError{Message: "Entitlement manifest payload does not match the signed token."}
	}
	keyID := stringValue(decoded.protected["kid"])
	rawPublicKey := options.PublicKeysByID[keyID]
	if rawPublicKey == "" {
		return nil, &ConfigError{Message: "Unknown entitlement manifest signing key \"" + keyID + "\"."}
	}
	publicKey, err := decodeBase64URL(rawPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return nil, &ConfigError{Message: "Entitlement manifest public key must be a base64url-encoded Ed25519 key."}
	}
	if !ed25519.Verify(publicKey, []byte(decoded.signingInput), decoded.signature) {
		return nil, &ConfigError{Message: "Entitlement manifest signature verification failed."}
	}
	if err := validateEntitlementPayload(decoded.payload); err != nil {
		return nil, err
	}
	now := options.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	issuedAt, _ := parseManifestTime(decoded.payload["issuedAt"], "issuedAt")
	notBefore, _ := parseManifestTime(decoded.payload["notBefore"], "notBefore")
	expiresAt, _ := parseManifestTime(decoded.payload["expiresAt"], "expiresAt")
	if issuedAt.After(expiresAt) {
		return nil, &ConfigError{Message: "Entitlement manifest timestamps are inconsistent."}
	}
	if notBefore.After(now) {
		return nil, &ConfigError{Message: "Entitlement manifest is not active yet."}
	}
	if !expiresAt.After(now) {
		return nil, &ConfigError{Message: "Entitlement manifest has expired."}
	}
	subject := mapValue(decoded.payload["subject"])
	if options.ExpectedIssuer != "" && decoded.payload["issuer"] != options.ExpectedIssuer {
		return nil, &ConfigError{Message: "Entitlement manifest issuer does not match the expected issuer."}
	}
	if options.ExpectedOrgID != "" && subject["orgId"] != options.ExpectedOrgID {
		return nil, &ConfigError{Message: "Entitlement manifest workspace does not match the expected workspace."}
	}
	if options.ExpectedProjectID != "" && subject["projectId"] != options.ExpectedProjectID {
		return nil, &ConfigError{Message: "Entitlement manifest project does not match the expected project."}
	}
	if options.ExpectedEnvironment != "" && subject["environment"] != options.ExpectedEnvironment {
		return nil, &ConfigError{Message: "Entitlement manifest environment does not match the expected environment."}
	}
	if options.ExpectedDeploymentMode != "" && subject["deploymentMode"] != options.ExpectedDeploymentMode {
		return nil, &ConfigError{Message: "Entitlement manifest deployment mode does not match the expected deployment mode."}
	}
	return decoded.payload, nil
}

type decodedManifest struct {
	protected    map[string]any
	payload      map[string]any
	signature    []byte
	signingInput string
}

func decodeManifestToken(token string) (decodedManifest, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return decodedManifest{}, &ConfigError{Message: "Invalid entitlement manifest token."}
	}
	protected, err := decodeJSONPart(parts[0], "Invalid entitlement manifest protected header.")
	if err != nil {
		return decodedManifest{}, err
	}
	payload, err := decodeJSONPart(parts[1], "Invalid entitlement manifest payload.")
	if err != nil {
		return decodedManifest{}, err
	}
	if protected["alg"] != EntitlementSigningAlgorithm || protected["typ"] != EntitlementManifestType || protected["kid"] == "" {
		return decodedManifest{}, &ConfigError{Message: "Unsupported entitlement manifest protected header."}
	}
	if payload["manifestType"] != EntitlementManifestType || payload["manifestVersion"] != float64(1) {
		return decodedManifest{}, &ConfigError{Message: "Unsupported entitlement manifest payload."}
	}
	signature, err := decodeBase64URL(parts[2])
	if err != nil {
		return decodedManifest{}, &ConfigError{Message: "Invalid entitlement manifest token."}
	}
	return decodedManifest{
		protected:    protected,
		payload:      payload,
		signature:    signature,
		signingInput: parts[0] + "." + parts[1],
	}, nil
}

func validateEntitlementPayload(payload map[string]any) error {
	for _, field := range []string{"manifestId", "issuer", "issuedAt", "notBefore", "expiresAt"} {
		if stringValue(payload[field]) == "" {
			return &ConfigError{Message: "Entitlement manifest field \"" + field + "\" must be a non-empty string."}
		}
	}
	subject := mapValue(payload["subject"])
	commercial := mapValue(payload["commercial"])
	entitlements := mapValue(payload["entitlements"])
	for _, field := range []string{"orgId", "workspaceName", "orgSlug", "projectId", "projectSlug"} {
		if stringValue(subject[field]) == "" {
			return &ConfigError{Message: "Entitlement manifest field \"subject." + field + "\" must be a non-empty string."}
		}
	}
	if subject["environment"] != "sandbox" && subject["environment"] != "live" {
		return &ConfigError{Message: "Entitlement manifest field \"subject.environment\" is invalid."}
	}
	if subject["deploymentMode"] != "self_hosted" && subject["deploymentMode"] != "sovereign" {
		return &ConfigError{Message: "Entitlement manifest field \"subject.deploymentMode\" is invalid."}
	}
	if !containsString([]string{"FREE", "STARTER", "GROWTH", "SCALE", "ENTERPRISE"}, stringValue(commercial["commercialPlan"])) {
		return &ConfigError{Message: "Entitlement manifest field \"commercial.commercialPlan\" is invalid."}
	}
	if !containsString([]string{"FREE", "PILOT", "ACTIVE", "GRACE", "PAST_DUE", "SUSPENDED", "CANCELED"}, stringValue(commercial["billingStatus"])) {
		return &ConfigError{Message: "Entitlement manifest field \"commercial.billingStatus\" is invalid."}
	}
	if _, ok := commercial["pilotActive"].(bool); !ok {
		return &ConfigError{Message: "Entitlement manifest field \"commercial.pilotActive\" is invalid."}
	}
	if err := requireNullableNonNegativeInteger(entitlements["includedQueriesPerMonth"], "entitlements.includedQueriesPerMonth"); err != nil {
		return err
	}
	if err := requireNullableNonNegativeInteger(entitlements["frameworkSlots"], "entitlements.frameworkSlots"); err != nil {
		return err
	}
	if !containsString([]string{"NONE", "METERED", "CONTRACT"}, stringValue(entitlements["overageMode"])) {
		return &ConfigError{Message: "Entitlement manifest field \"entitlements.overageMode\" is invalid."}
	}
	for _, field := range []string{"issuedAt", "notBefore", "expiresAt"} {
		if _, err := parseManifestTime(payload[field], field); err != nil {
			return err
		}
	}
	return nil
}

func decodeJSONPart(value, message string) (map[string]any, error) {
	bytes, err := decodeBase64URL(value)
	if err != nil {
		return nil, &ConfigError{Message: message}
	}
	var decoded map[string]any
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		return nil, &ConfigError{Message: message}
	}
	return decoded, nil
}

func decodeBase64URL(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}

func jsonEqual(left any, right any) bool {
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	return string(leftJSON) == string(rightJSON)
}

func parseManifestTime(value any, fieldName string) (time.Time, error) {
	raw := stringValue(value)
	if raw == "" {
		return time.Time{}, &ConfigError{Message: "Entitlement manifest field \"" + fieldName + "\" must be present."}
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, &ConfigError{Message: "Entitlement manifest field \"" + fieldName + "\" must be a valid ISO timestamp."}
	}
	return parsed, nil
}

func requireNullableNonNegativeInteger(value any, fieldName string) error {
	if value == nil {
		return nil
	}
	number, ok := value.(float64)
	if !ok || number < 0 || number != float64(int64(number)) {
		return &ConfigError{Message: "Entitlement manifest field \"" + fieldName + "\" must be a non-negative integer or null."}
	}
	return nil
}

func mapValue(value any) map[string]any {
	if mapped, ok := value.(map[string]any); ok {
		return mapped
	}
	return map[string]any{}
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
