package client

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"

	"github.com/Sirupsen/logrus"
	manifesttypes "github.com/docker/cli/cli/manifest/types"
	"github.com/docker/distribution"
	"github.com/docker/distribution/reference"
	"github.com/docker/distribution/registry/api/v2"
	distributionclient "github.com/docker/distribution/registry/client"
	"github.com/docker/docker/api/types"
	registrytypes "github.com/docker/docker/api/types/registry"
	"github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

// RegistryClient is a client used to communicate with a Docker distribution
// registry
type RegistryClient interface {
	GetManifest(ctx context.Context, ref reference.Named) (manifesttypes.ImageManifest, error)
	GetManifestList(ctx context.Context, ref reference.Named) ([]manifesttypes.ImageManifest, error)
	MountBlob(ctx context.Context, source reference.Named, ref reference.Canonical) error
	PutManifest(ctx context.Context, ref reference.Named, manifest PutManifestOptions) (digest.Digest, error)
}

// NewRegistryClient returns a new RegistryClient with a resolver
func NewRegistryClient(resolver AuthConfigResolver, userAgent string) RegistryClient {
	return &client{
		authConfigResolver: resolver,
		userAgent:          userAgent,
	}
}

// AuthConfigResolver returns Auth Configuration for an index
type AuthConfigResolver func(ctx context.Context, index *registrytypes.IndexInfo) types.AuthConfig

// PutManifestOptions is the data sent to push a manifest
type PutManifestOptions struct {
	MediaType string
	Payload   []byte
}

type client struct {
	authConfigResolver AuthConfigResolver
	userAgent          string
}

var _ RegistryClient = &client{}

// MountBlob into the registry, so it can be referenced by a manifest
func (c *client) MountBlob(ctx context.Context, sourceRef reference.Named, targetRef reference.Canonical) error {
	repo, err := c.getRepositoryForReference(ctx, sourceRef)
	if err != nil {
		return err
	}
	lu, err := repo.Blobs(ctx).Create(ctx, distributionclient.WithMountFrom(targetRef))
	if err != nil {
		if _, ok := err.(distribution.ErrBlobMounted); !ok {
			return errors.Wrapf(err, "failed to mount blob %s", targetRef)
		}
	}
	// TODO: why is this cancelling the mount instead of commit?
	// registry treated this as a normal upload
	lu.Cancel(ctx)
	logrus.Debugf("mount of blob %s succeeded", targetRef)
	return nil
}

// PutManifestList sends the manifest to a registry and returns the new digest
func (c *client) PutManifest(ctx context.Context, ref reference.Named, manifest PutManifestOptions) (digest.Digest, error) {
	dgst := digest.Digest("")

	repoEndpoint, err := newRepositoryWithDefaultEndpoint(ref)
	if err != nil {
		return dgst, err
	}

	httpTransport, err := c.getHTTPTransportForRepoEndpoint(ctx, repoEndpoint)
	if err != nil {
		return dgst, errors.Wrap(err, "failed to setup HTTP client")
	}

	// TODO: this needs cleanup
	targetRef, err := getRefWithoutDomain(ref)
	if err != nil {
		return dgst, err
	}

	pushURL, err := buildPutManifestURLFromReference(targetRef, repoEndpoint.BaseURL())
	if err != nil {
		return dgst, err
	}

	putRequest, err := http.NewRequest("PUT", pushURL, bytes.NewReader(manifest.Payload))
	if err != nil {
		return dgst, err
	}
	putRequest.Header.Set("Content-Type", manifest.MediaType)

	httpClient := &http.Client{Transport: httpTransport}
	resp, err := httpClient.Do(putRequest)
	if err != nil {
		return dgst, err
	}
	defer resp.Body.Close()

	if !statusSuccess(resp.StatusCode) {
		return dgst, errors.Wrapf(err, "PutManifestList failed: %s", resp.Status)
	}

	dgst, err = digest.Parse(resp.Header.Get("Docker-Content-Digest"))
	return dgst, errors.Wrap(err, "failed to parse returned digest")
}

func buildPutManifestURLFromReference(targetRef reference.Named, targetURL string) (string, error) {
	urlBuilder, err := v2.NewURLBuilderFromString(targetURL, false)
	if err != nil {
		return "", errors.Wrapf(err, "can't create URL builder from endpoint (%s)", targetURL)
	}
	manifestURL, err := urlBuilder.BuildManifestURL(targetRef)
	if err != nil {
		return "", errors.Wrap(err, "failed to build manifest URL from target reference")
	}
	return manifestURL, nil
}

func (c *client) getRepositoryForReference(ctx context.Context, ref reference.Named) (distribution.Repository, error) {
	repoEndpoint, err := newRepositoryWithDefaultEndpoint(ref)
	if err != nil {
		return nil, err
	}

	httpTransport, err := c.getHTTPTransportForRepoEndpoint(ctx, repoEndpoint)
	if err != nil {
		return nil, errors.Wrap(err, "failed to configure transport")
	}
	return distributionclient.NewRepository(ctx, ref, repoEndpoint.BaseURL(), httpTransport)
}

func (c *client) getHTTPTransportForRepoEndpoint(ctx context.Context, repoEndpoint repositoryEndpoint) (http.RoundTripper, error) {
	httpTransport, err := getHTTPTransport(
		c.authConfigResolver(ctx, repoEndpoint.info.Index),
		repoEndpoint.endpoint,
		repoEndpoint.Name(),
		c.userAgent)
	return httpTransport, errors.Wrap(err, "failed to configure transport")
}

func statusSuccess(status int) bool {
	return status >= 200 && status <= 399
}

func getRefWithoutDomain(fullTargetRef reference.Named) (reference.Named, error) {
	tagIndex := strings.LastIndex(fullTargetRef.String(), ":")
	logrus.Debugf("fullTargetRef. should be complete by now: %s", fullTargetRef.String())
	if tagIndex < 0 {
		return nil, fmt.Errorf("malformed reference")
	}
	// TODO: there must be a more appropriate way to get the tag
	tag := fullTargetRef.String()[tagIndex+1:]

	targetRefNoTag, err := reference.WithName(reference.Path(fullTargetRef))
	logrus.Debugf("targetRefNoTag should have no name and no tag: %s", targetRefNoTag.String())
	if err != nil {
		return nil, err
	}
	targetRefNoDomain, _ := reference.WithTag(targetRefNoTag, tag)
	logrus.Debugf("targetRefNoDomain should have no domain but a tag? %s", targetRefNoDomain.String())

	return targetRefNoDomain, nil
}

// GetManifest returns an ImageManifest for the reference
func (c *client) GetManifest(ctx context.Context, ref reference.Named) (manifesttypes.ImageManifest, error) {
	var result manifesttypes.ImageManifest
	fetch := func(ctx context.Context, repo distribution.Repository, ref reference.Named) (bool, error) {
		var err error
		result, err = fetchManifest(ctx, repo, ref)
		return result.Ref != nil, err
	}

	err := c.iterateEndpoints(ctx, ref, fetch)
	return result, err
}

// GetManifestList returns a list of ImageManifest for the reference
func (c *client) GetManifestList(ctx context.Context, ref reference.Named) ([]manifesttypes.ImageManifest, error) {
	result := []manifesttypes.ImageManifest{}
	fetch := func(ctx context.Context, repo distribution.Repository, ref reference.Named) (bool, error) {
		foundImages, err := fetchList(ctx, repo, ref)
		return len(foundImages) > 0, err
	}

	if err := c.iterateEndpoints(ctx, ref, fetch); err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, errors.Errorf("no endpoints found for %s", ref)
	}
	return result, nil
}
