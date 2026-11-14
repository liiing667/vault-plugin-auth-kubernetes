// Copyright IBM Corp. 2017, 2025
// SPDX-License-Identifier: MPL-2.0

package kubeauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	v1 "k8s.io/api/core/v1"
	kubeerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const annotationKeyPrefix = "vault.hashicorp.com/alias-metadata-"

var errAliasMetadataReservedKeysFound = errors.New("entity alias metadata keys for only internal use found" +
	" from the client token's associated service account annotations")

// serviceAccountGetter defines a namespace validator interface
type serviceAccountGetter interface {
	annotations(context.Context, *http.Client, string, string, string) (map[string]string, error)
}

type serviceAccountGetterFactory func(*kubeConfig) serviceAccountGetter

// serviceAccountGetterWrapper implements the serviceAccountGetter interface
type serviceAccountGetterWrapper struct {
	config *kubeConfig
}

func newServiceAccountGetterWrapper(config *kubeConfig) serviceAccountGetter {
	return &serviceAccountGetterWrapper{
		config: config,
	}
}

func (w *serviceAccountGetterWrapper) annotations(ctx context.Context, client *http.Client, jwtStr, namespace, serviceAccount string) (map[string]string, error) {
	url := fmt.Sprintf("%s/api/v1/namespaces/%s/serviceaccounts/%s",
		strings.TrimSuffix(w.config.Host, "/"), namespace, serviceAccount)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Only ever authenticate with the configured TokenReviewer JWT (which
	// may have been loaded from this pod's local service account token).
	// The client-submitted JWT must never be used as the bearer, so fail
	// closed if no reviewer token is available.
	if w.config.TokenReviewerJWT == "" {
		return nil, errors.New("service account lookup failed: no token reviewer JWT is configured")
	}
	setRequestHeader(req, fmt.Sprintf("Bearer %s", w.config.TokenReviewerJWT))

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseBodySize {
		return nil, fmt.Errorf("service account response body exceeded %d bytes", maxResponseBodySize)
	}
	if resp.StatusCode != http.StatusOK {
		var errStatus metav1.Status
		if err = json.Unmarshal(body, &errStatus); err != nil {
			return nil, fmt.Errorf("failed to parse error status on service account retrieval failure err=%s", err)
		}

		if errStatus.Status != metav1.StatusSuccess {
			return nil, fmt.Errorf("failed to get service account (code %d status %s)",
				resp.StatusCode, kubeerrors.FromObject(runtime.Object(&errStatus)))
		}
	}
	var sa v1.ServiceAccount
	err = json.Unmarshal(body, &sa)
	if err != nil {
		return nil, err
	}

	var found bool
	var foundKeys []string
	annotations := map[string]string{}
	for k, v := range sa.Annotations {
		if strings.HasPrefix(k, annotationKeyPrefix) {
			newK := strings.TrimPrefix(k, annotationKeyPrefix)
			if _, ok := reservedAliasMetadataKeys[newK]; ok {
				foundKeys = append(foundKeys, newK)
				found = true
			} else {
				annotations[newK] = v
			}
		}
	}

	if found {
		errContext := fmt.Sprintf("keys=%+q", foundKeys)
		return nil, fmt.Errorf("%w: %s", errAliasMetadataReservedKeysFound, errContext)
	}

	return annotations, nil
}

type mockServiceAccountGetter struct {
	meta metav1.ObjectMeta
}

func mockServiceAccountGetterFactory(meta metav1.ObjectMeta) serviceAccountGetterFactory {
	return func(config *kubeConfig) serviceAccountGetter {
		return &mockServiceAccountGetter{
			meta: meta,
		}
	}
}

func (v *mockServiceAccountGetter) annotations(context.Context, *http.Client, string, string, string) (map[string]string, error) {
	annotations := map[string]string{}
	for k, v := range v.meta.Annotations {
		if strings.HasPrefix(k, annotationKeyPrefix) {
			newK := strings.TrimPrefix(k, annotationKeyPrefix)
			annotations[newK] = v
		}
	}
	return annotations, nil
}
