package globiguard

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

const TrustWebhookContractVersion = "2026-05-trust-webhook-beta"
const TrustWebhookSignatureScheme = "globiguard-hmac-sha256-v1"

var TrustWebhookHeaderNames = map[string]string{
	"deliveryId": "x-globiguard-delivery-id",
	"timestamp":  "x-globiguard-timestamp",
	"eventType":  "x-globiguard-event-type",
	"signature":  "x-globiguard-signature",
}

type WebhookVerificationRequest struct {
	Headers          http.Header
	RawBody          []byte
	SigningSecret    string
	ToleranceSeconds int
	Now              time.Time
	SeenDelivery     func(string) bool
}

type WebhookVerificationResult struct {
	OK                bool
	DeliveryID        string
	EventType         string
	Timestamp         string
	Envelope          map[string]any
	DuplicateDelivery bool
	Error             map[string]any
}

func VerifyTrustWebhook(request WebhookVerificationRequest) WebhookVerificationResult {
	headers := normalizeWebhookHeaders(request.Headers)
	tolerance := request.ToleranceSeconds
	if tolerance == 0 {
		tolerance = 300
	}
	now := request.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if headers["deliveryId"] == "" || headers["timestamp"] == "" || headers["eventType"] == "" || headers["signature"] == "" {
		return webhookFailure("Missing required GlobiGuard webhook headers.", headers)
	}
	parsedTimestamp, err := time.Parse(time.RFC3339, headers["timestamp"])
	if err != nil {
		return webhookFailure("Invalid GlobiGuard webhook timestamp.", headers)
	}
	age := now.Sub(parsedTimestamp)
	if age < 0 {
		age = -age
	}
	if age > time.Duration(tolerance)*time.Second {
		return webhookFailure("GlobiGuard webhook timestamp is outside the accepted replay window.", headers)
	}
	var envelope map[string]any
	bodyText := string(request.RawBody)
	if err := json.Unmarshal(request.RawBody, &envelope); err != nil {
		return webhookFailure("GlobiGuard webhook body is not valid JSON.", headers)
	}
	if stringValue(envelope["id"]) != headers["deliveryId"] || stringValue(envelope["type"]) != headers["eventType"] {
		return webhookFailure("GlobiGuard webhook headers do not match the signed envelope.", headers)
	}
	mac := hmac.New(sha256.New, []byte(request.SigningSecret))
	mac.Write([]byte(BuildSignedWebhookPayload(headers, bodyText)))
	expected := hex.EncodeToString(mac.Sum(nil))
	provided := normalizeSignature(headers["signature"])
	if !hmac.Equal([]byte(expected), []byte(provided)) {
		return webhookFailure("Invalid GlobiGuard webhook signature.", headers)
	}
	duplicate := false
	if request.SeenDelivery != nil {
		duplicate = request.SeenDelivery(headers["deliveryId"])
	}
	return WebhookVerificationResult{
		OK:                true,
		DeliveryID:        headers["deliveryId"],
		EventType:         headers["eventType"],
		Timestamp:         headers["timestamp"],
		Envelope:          envelope,
		DuplicateDelivery: duplicate,
	}
}

func BuildSignedWebhookPayload(headers map[string]string, rawBody string) string {
	return strings.Join([]string{
		TrustWebhookSignatureScheme,
		headers["deliveryId"],
		headers["timestamp"],
		headers["eventType"],
		rawBody,
	}, ".")
}

func normalizeWebhookHeaders(headers http.Header) map[string]string {
	lowerHeaders := map[string]string{}
	for key, values := range headers {
		if len(values) > 0 {
			lowerHeaders[strings.ToLower(key)] = values[0]
		}
	}
	return map[string]string{
		"deliveryId": lowerHeaders[TrustWebhookHeaderNames["deliveryId"]],
		"timestamp":  lowerHeaders[TrustWebhookHeaderNames["timestamp"]],
		"eventType":  lowerHeaders[TrustWebhookHeaderNames["eventType"]],
		"signature":  lowerHeaders[TrustWebhookHeaderNames["signature"]],
	}
}

func normalizeSignature(signature string) string {
	return strings.TrimPrefix(signature, "v1=")
}

func webhookFailure(message string, headers map[string]string) WebhookVerificationResult {
	return WebhookVerificationResult{
		OK:         false,
		DeliveryID: headers["deliveryId"],
		EventType:  headers["eventType"],
		Timestamp:  headers["timestamp"],
		Error: map[string]any{
			"kind":        "WEBHOOK_VERIFICATION_FAILED",
			"message":     message,
			"safeDetails": map[string]any{"boundary": "server"},
		},
	}
}
