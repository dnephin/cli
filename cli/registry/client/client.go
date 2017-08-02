package client

import (
	"net/http"

	"github.com/Sirupsen/logrus"
	manifesttypes "github.com/docker/cli/cli/manifest/types"
	"github.com/docker/distribution"
	"github.com/docker/distribution/reference"
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
	PutManifest(ctx context.Context, ref reference.Named, manifest distribution.Manifest) (digest.Digest, error)
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
	repoEndpoint, err := newDefaultRepositoryEndpoint(targetRef)
	if err != nil {
		return err
	}
	repo, err := c.getRepositoryForReference(ctx, targetRef, repoEndpoint)
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
func (c *client) PutManifest(ctx context.Context, ref reference.Named, manifest distribution.Manifest) (digest.Digest, error) {
	repoEndpoint, err := newDefaultRepositoryEndpoint(ref)
	if err != nil {
		return digest.Digest(""), err
	}

	repo, err := c.getRepositoryForReference(ctx, ref, repoEndpoint)
	if err != nil {
		return digest.Digest(""), err
	}

	manifestService, err := repo.Manifests(ctx)
	if err != nil {
		return digest.Digest(""), err
	}

	_, opts, err := getManifestOptionsFromReference(ref)
	if err != nil {
		return digest.Digest(""), err
	}
	dgst, err := manifestService.Put(ctx, manifest, opts...)
	return dgst, errors.Wrapf(err, "failed to put manifest %s", ref)
}

func (c *client) getRepositoryForReference(ctx context.Context, ref reference.Named, repoEndpoint repositoryEndpoint) (distribution.Repository, error) {
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

	err := c.iterateEndpoints(ctx, ref, fetch)
	return result, err
}

func getManifestOptionsFromReference(ref reference.Named) (digest.Digest, []distribution.ManifestServiceOption, error) {
	if tagged, isTagged := ref.(reference.NamedTagged); isTagged {
		tag := tagged.Tag()
		return "", []distribution.ManifestServiceOption{distribution.WithTag(tag)}, nil
	}
	if digested, isDigested := ref.(reference.Canonical); isDigested {
		return digested.Digest(), []distribution.ManifestServiceOption{}, nil
	}
	return "", nil, errors.Errorf("%s no tag or digest", ref)
}
