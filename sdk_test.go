package globiguard

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestServerClientHeadersAndReservedHeaderProtection(t *testing.T) {
	var captured http.Header
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Header.Clone()
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	client, err := NewServerClient(ClientConfig{
		Environment: EnvironmentSandbox,
		Services:    map[string]string{"controlPlane": server.URL},
		Credential:  SecretCredential("proj_123", "sk_secret", EnvironmentSandbox),
		HTTPClient:  server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.ControlPlane.Request(context.Background(), "/v1/audit", http.MethodGet, nil, nil, map[string]string{
		"x-globiguard-secret-key": "attacker",
		"x-custom":                "ok",
	}, nil); err != nil {
		t.Fatal(err)
	}

	if captured.Get("x-globiguard-secret-key") != "sk_secret" {
		t.Fatalf("secret header mismatch: %q", captured.Get("x-globiguard-secret-key"))
	}
	if captured.Get("x-globiguard-project-id") != "proj_123" {
		t.Fatalf("project header mismatch: %q", captured.Get("x-globiguard-project-id"))
	}
	if captured.Get("x-globiguard-environment") != "sandbox" {
		t.Fatalf("environment header mismatch: %q", captured.Get("x-globiguard-environment"))
	}
	if captured.Get("x-custom") != "ok" {
		t.Fatalf("custom header mismatch: %q", captured.Get("x-custom"))
	}
}

func TestRejectsUnsafeURLsAndPaths(t *testing.T) {
	if err := AssertServiceURL("controlPlane", "http://api.globiguard.com", EnvironmentLive, false); err == nil {
		t.Fatal("expected HTTPS validation error")
	}
	for _, path := range []string{"https://evil.test/v1/audit", "/v1/../admin", "/v1/%2e%2e/admin", "/v1/%ZZ/admin", "/v1/audit?x=1"} {
		if _, err := JoinURL("https://api.globiguard.com", path); err == nil {
			t.Fatalf("expected path validation error for %s", path)
		}
	}
}

func TestWebhookVerification(t *testing.T) {
	rawBody := `{"contractVersion":"2026-05-trust-webhook-beta","id":"del_123","timestamp":"2026-05-29T10:30:00Z","type":"approval.approved","apiFamily":"webhooks.v1","data":{"approvalId":"appr_123"}}`
	headers := map[string]string{
		"deliveryId": "del_123",
		"timestamp":  "2026-05-29T10:30:00Z",
		"eventType":  "approval.approved",
	}
	mac := hmac.New(sha256.New, []byte("whsec_test"))
	mac.Write([]byte(BuildSignedWebhookPayload(headers, rawBody)))
	signature := hex.EncodeToString(mac.Sum(nil))
	httpHeaders := http.Header{
		"x-globiguard-delivery-id": []string{"del_123"},
		"x-globiguard-timestamp":   []string{"2026-05-29T10:30:00Z"},
		"x-globiguard-event-type":  []string{"approval.approved"},
		"x-globiguard-signature":   []string{"v1=" + signature},
	}

	result := VerifyTrustWebhook(WebhookVerificationRequest{
		Headers:       httpHeaders,
		RawBody:       []byte(rawBody),
		SigningSecret: "whsec_test",
		Now:           time.Date(2026, 5, 29, 10, 30, 1, 0, time.UTC),
	})

	if !result.OK || result.DeliveryID != "del_123" {
		t.Fatalf("expected valid webhook, got %#v", result)
	}
}

func TestIdempotencyKeyMatchesTypeScriptShape(t *testing.T) {
	key, err := DeriveActionIdempotencyKey(IdempotencyKeyInput{
		StableSeed:    "order_123",
		ActionType:    "refund",
		ActorID:       "user_123",
		PayloadSHA256: "abc",
		WindowBucket:  "2026-05-29T10",
	})
	if err != nil {
		t.Fatal(err)
	}
	expected := "gg_idem_62a02411844efcd2ea63097b1eed81c7a39d3aba9136a17e"
	if key != expected {
		t.Fatalf("idempotency key mismatch: got %s want %s", key, expected)
	}
}

func TestBootstrapHelpers(t *testing.T) {
	request, err := BuildInstallRegistrationRequest(BootstrapProfile{
		Environment:      EnvironmentSandbox,
		DeploymentMode:   DeploymentSelfHosted,
		IssuerMode:       IssuerCustomerIssued,
		InstallReporting: InstallReportingOptIn,
		InstallLabel:     "Go worker",
	}, "globiguard-go", "0.1.0", "sdk", "go", map[string]any{"go": "1.22"})
	if err != nil {
		t.Fatal(err)
	}
	if request["deploymentMode"] != DeploymentSelfHosted {
		t.Fatalf("deployment mode mismatch: %#v", request)
	}
	if _, err := ResolveBootstrapProfile(BootstrapProfile{
		Environment:      EnvironmentLive,
		DeploymentMode:   DeploymentHosted,
		IssuerMode:       IssuerCustomerIssued,
		InstallReporting: InstallReportingDefault,
	}); err == nil {
		t.Fatal("expected hosted issuer validation error")
	}
}

func TestEntitlementManifestVerification(t *testing.T) {
	publicKey := "0EBi8A20QIJf5lwzzj98ZK1X8EzBJ2nli7rsMM8JXzc"
	rawManifest := `{
	  "serialization": "jws-compact",
	  "token": "eyJhbGciOiJFZERTQSIsImtpZCI6ImtpZF90ZXN0IiwidHlwIjoiZ2xvYmlndWFyZC5lbnRpdGxlbWVudC52MSJ9.eyJtYW5pZmVzdFR5cGUiOiJnbG9iaWd1YXJkLmVudGl0bGVtZW50LnYxIiwibWFuaWZlc3RWZXJzaW9uIjoxLCJtYW5pZmVzdElkIjoibWFuaWZlc3RfMTIzIiwiaXNzdWVyIjoiaHR0cHM6Ly9hcGkuZ2xvYmlndWFyZC5jb20iLCJpc3N1ZWRBdCI6IjIwMjYtMDUtMjlUMTA6MDA6MDBaIiwibm90QmVmb3JlIjoiMjAyNi0wNS0yOVQxMDowMDowMFoiLCJleHBpcmVzQXQiOiIyMDI2LTA1LTMwVDEwOjAwOjAwWiIsInN1YmplY3QiOnsib3JnSWQiOiJvcmdfMTIzIiwid29ya3NwYWNlTmFtZSI6IkFjbWUiLCJvcmdTbHVnIjoiYWNtZSIsInByb2plY3RJZCI6InByb2pfMTIzIiwicHJvamVjdFNsdWciOiJtYWluIiwiZW52aXJvbm1lbnQiOiJzYW5kYm94IiwiZGVwbG95bWVudE1vZGUiOiJzZWxmX2hvc3RlZCJ9LCJjb21tZXJjaWFsIjp7ImNvbW1lcmNpYWxQbGFuIjoiR1JPV1RIIiwiYmlsbGluZ1N0YXR1cyI6IkFDVElWRSIsInBpbG90QWN0aXZlIjpmYWxzZX0sImVudGl0bGVtZW50cyI6eyJpbmNsdWRlZFF1ZXJpZXNQZXJNb250aCI6MTAwMDAsImZyYW1ld29ya1Nsb3RzIjozLCJvdmVyYWdlTW9kZSI6Ik1FVEVSRUQifX0.qJZVmhIyLBsSUmrFlpCzCytt6pUly5CZG7miWgxxZttuqXNnNWfleiSJ7ScK15AVhY0ZnLopSHZg4_uQbSi8CQ",
	  "protected": {"alg":"EdDSA","kid":"kid_test","typ":"globiguard.entitlement.v1"},
	  "payload": {
	    "manifestType":"globiguard.entitlement.v1","manifestVersion":1,"manifestId":"manifest_123","issuer":"https://api.globiguard.com","issuedAt":"2026-05-29T10:00:00Z","notBefore":"2026-05-29T10:00:00Z","expiresAt":"2026-05-30T10:00:00Z",
	    "subject":{"orgId":"org_123","workspaceName":"Acme","orgSlug":"acme","projectId":"proj_123","projectSlug":"main","environment":"sandbox","deploymentMode":"self_hosted"},
	    "commercial":{"commercialPlan":"GROWTH","billingStatus":"ACTIVE","pilotActive":false},
	    "entitlements":{"includedQueriesPerMonth":10000,"frameworkSlots":3,"overageMode":"METERED"}
	  }
	}`
	var manifest map[string]any
	if err := json.Unmarshal([]byte(rawManifest), &manifest); err != nil {
		t.Fatal(err)
	}
	payload, err := VerifySignedEntitlementManifest(manifest, VerifyEntitlementOptions{
		PublicKeysByID:         map[string]string{"kid_test": publicKey},
		ExpectedIssuer:         "https://api.globiguard.com",
		ExpectedOrgID:          "org_123",
		ExpectedProjectID:      "proj_123",
		ExpectedEnvironment:    "sandbox",
		ExpectedDeploymentMode: "self_hosted",
		Now:                    time.Date(2026, 5, 29, 10, 30, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if mapValue(payload["commercial"])["commercialPlan"] != "GROWTH" {
		t.Fatalf("unexpected payload: %#v", payload)
	}
	tampered := cloneMap(manifest)
	tampered["payload"].(map[string]any)["issuer"] = "evil"
	if _, err := VerifySignedEntitlementManifest(tampered, VerifyEntitlementOptions{
		PublicKeysByID: map[string]string{"kid_test": publicKey},
		Now:            time.Date(2026, 5, 29, 10, 30, 0, 0, time.UTC),
	}); err == nil {
		t.Fatal("expected tampered manifest rejection")
	}
}

func cloneMap(value map[string]any) map[string]any {
	payload, _ := json.Marshal(value)
	var cloned map[string]any
	_ = json.Unmarshal(payload, &cloned)
	return cloned
}
