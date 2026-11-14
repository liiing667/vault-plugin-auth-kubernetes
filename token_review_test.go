// Copyright IBM Corp. 2017, 2025
// SPDX-License-Identifier: MPL-2.0

package kubeauth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testTokenReviewSuccessBody = `{
	"kind": "TokenReview",
	"apiVersion": "authentication.k8s.io/v1",
	"status": {
		"authenticated": true,
		"user": {
			"username": "system:serviceaccount:test-namespace:test-name",
			"uid": "test-uid"
		},
		"audiences": ["vault"]
	}
}`

// TestTokenReview_NoReviewerJWT verifies that the TokenReview request fails
// closed when no reviewer token is available, rather than falling back to
// the client-submitted JWT.
func TestTokenReview_NoReviewerJWT(t *testing.T) {
	tr := &tokenReviewAPI{config: &kubeConfig{Host: "https://unused"}}

	_, err := tr.Review(context.Background(), getDefaultHTTPClient(), "client-jwt", nil)
	if err == nil {
		t.Fatal("expected error when no token reviewer JWT is configured")
	}
	if !strings.Contains(err.Error(), "no token reviewer JWT") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestTokenReview_UsesConfiguredReviewerJWT verifies that the configured
// reviewer JWT is used as the bearer token and the client-submitted JWT is
// only sent in the TokenReview spec.
func TestTokenReview_UsesConfiguredReviewerJWT(t *testing.T) {
	var gotAuthorization string
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthorization = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, testTokenReviewSuccessBody)
	}))
	defer server.Close()

	tr := &tokenReviewAPI{config: &kubeConfig{
		Host:             server.URL,
		TokenReviewerJWT: "reviewer-jwt",
	}}

	result, err := tr.Review(context.Background(), server.Client(), "client-jwt", []string{"vault"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotAuthorization != "Bearer reviewer-jwt" {
		t.Fatalf("expected configured reviewer JWT as bearer, got %q", gotAuthorization)
	}
	if strings.Contains(gotAuthorization, "client-jwt") {
		t.Fatal("client-submitted JWT must not be used as the bearer token")
	}
	if !strings.Contains(string(gotBody), "client-jwt") {
		t.Fatal("expected client-submitted JWT in the TokenReview spec")
	}

	if result.Name != "test-name" || result.Namespace != "test-namespace" || result.UID != "test-uid" {
		t.Fatalf("unexpected token review result: %#v", result)
	}
}

// TestTokenReview_AudienceMismatch verifies that audience validation is still
// enforced on the TokenReview response.
func TestTokenReview_AudienceMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, testTokenReviewSuccessBody)
	}))
	defer server.Close()

	tr := &tokenReviewAPI{config: &kubeConfig{
		Host:             server.URL,
		TokenReviewerJWT: "reviewer-jwt",
	}}

	_, err := tr.Review(context.Background(), server.Client(), "client-jwt", []string{"other-audience"})
	if err == nil {
		t.Fatal("expected audience mismatch error")
	}
	if !strings.Contains(err.Error(), "audience") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestParseResponse_BodyTooLarge verifies that response bodies larger than
// maxResponseBodySize are rejected.
func TestParseResponse_BodyTooLarge(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(strings.Repeat("a", maxResponseBodySize+1))),
	}

	_, err := parseResponse(resp)
	if err == nil {
		t.Fatal("expected error for oversized response body")
	}
	if !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestParseResponse_BodyAtLimit verifies that a response body exactly at the
// size limit is still read successfully.
func TestParseResponse_BodyAtLimit(t *testing.T) {
	// Account for the stripped closing brace and the added JSON field so the
	// final body is exactly maxResponseBodySize bytes.
	padding := strings.Repeat("a", maxResponseBodySize-len(testTokenReviewSuccessBody)-13)
	body := testTokenReviewSuccessBody[:len(testTokenReviewSuccessBody)-1] + `,"padding":"` + padding + `"}`

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(body)),
	}

	tr, err := parseResponse(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !tr.Status.Authenticated {
		t.Fatal("expected authenticated token review response")
	}
}
