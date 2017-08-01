package client

import (
	"bytes"
	"net/http"

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
	MountBlob(ctx context.Context, source reference.Canonical, target reference.Named) error
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
func (c *client) MountBlob(ctx context.Context, sourceRef reference.Canonical, targetRef reference.Named) error {
	repo, err := c.getRepositoryForReference(ctx, targetRef)
	if err != nil {
		return err
	}
	lu, err := repo.Blobs(ctx).Create(ctx, distributionclient.WithMountFrom(sourceRef))
	if err != nil {
		if _, ok := err.(distribution.ErrBlobMounted); !ok {
			return errors.Wrapf(err, "failed to mount blob %s to %s", sourceRef, targetRef)
		}
	}
	// TODO: why is this cancelling the mount instead of commit?
	// registry treated this as a normal upload
	lu.Cancel(ctx)
	logrus.Debugf("mount of blob %s succeeded", sourceRef)
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

	pushURL, err := buildPutManifestURLFromReference(ref, repoEndpoint)
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
	logrus.Debugf("Resp: %s\n", resp)
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

func buildPutManifestURLFromReference(targetRef reference.Named, repoEndpoint repositoryEndpoint) (string, error) {
	urlBuilder, err := v2.NewURLBuilderFromString(repoEndpoint.BaseURL(), false)
	if err != nil {
		return "", errors.Wrapf(err, "can't create URL builder from endpoint (%s)", repoEndpoint.BaseURL())
	}

	repoName, err := reference.WithName(repoEndpoint.Name())
	if err != nil {
		return "", errors.Wrapf(err, "failed to parse repo name from %s", targetRef)
	}
	namedTagged, ok := targetRef.(reference.NamedTagged)
	if !ok {
		return "", errors.Errorf("missing tag: %s", targetRef)
	}
	refWithoutDomain, err := reference.WithTag(repoName, namedTagged.Tag())
	if err != nil {
		return "", err
	}

	manifestURL, err := urlBuilder.BuildManifestURL(refWithoutDomain)
	return manifestURL, errors.Wrap(err, "failed to build manifest URL from target reference")
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
	repoName, err := reference.WithName(repoEndpoint.Name())
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse repo name from %s", ref)
	}
	return distributionclient.NewRepository(ctx, repoName, repoEndpoint.BaseURL(), httpTransport)
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
