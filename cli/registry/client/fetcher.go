package client

import (
	"fmt"
	"runtime"

	"github.com/Sirupsen/logrus"
	"github.com/docker/cli/cli/manifest/types"
	"github.com/docker/distribution"
	"github.com/docker/distribution/manifest/manifestlist"
	"github.com/docker/distribution/manifest/schema2"
	"github.com/docker/distribution/reference"
	"github.com/docker/distribution/registry/api/errcode"
	"github.com/docker/distribution/registry/api/v2"
	distclient "github.com/docker/distribution/registry/client"
	authtypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/registry"
	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

type repositoryOptions struct {
	authConfig authtypes.AuthConfig
	userAgent  string
	repoInfo   *registry.RepositoryInfo
}

func (opts repositoryOptions) getRepository(ctx context.Context, endpoint registry.APIEndpoint) (distribution.Repository, error) {
	repoEndpoint := repositoryEndpoint{endpoint: endpoint, info: opts.repoInfo}
	repoNameRef, err := reference.WithName(repoEndpoint.Name())
	if err != nil {
		return nil, err
	}
	httpTransport, err := getHTTPTransport(opts.authConfig, endpoint, repoEndpoint.Name(), opts.userAgent)
	if err != nil {
		return nil, err
	}
	return distclient.NewRepository(ctx, repoNameRef, repoEndpoint.BaseURL(), httpTransport)
}

// fetchManifest pulls a manifest from a registry and returns it. An error
// is returned if no manifest is found matching namedRef.
func fetchManifest(ctx context.Context, repo distribution.Repository, ref reference.Named) (types.ImageManifest, error) {
	manifest, err := getManifest(ctx, repo, ref)
	if err != nil {
		return types.ImageManifest{}, err
	}

	switch v := manifest.(type) {
	// Removed Schema 1 support
	case *schema2.DeserializedManifest:
		imageManifest, err := pullManifestSchemaV2(ctx, ref, repo, *v)
		if err != nil {
			return types.ImageManifest{}, err
		}
		return imageManifest, nil
	}
	return types.ImageManifest{}, errors.Errorf("%s is not a manifest", ref)
}

func fetchList(ctx context.Context, repo distribution.Repository, ref reference.Named) ([]types.ImageManifest, error) {
	manifest, err := getManifest(ctx, repo, ref)
	if err != nil {
		return nil, err
	}

	switch v := manifest.(type) {
	case *manifestlist.DeserializedManifestList:
		imageManifests, err := pullManifestList(ctx, ref, repo, *v)
		if err != nil {
			return nil, err
		}
		return imageManifests, nil
	default:
		return nil, errors.Errorf("unsupported manifest format: %v", v)
	}
}

func getManifest(ctx context.Context, repo distribution.Repository, ref reference.Named) (distribution.Manifest, error) {
	manSvc, err := repo.Manifests(ctx)
	if err != nil {
		return nil, err
	}

	if tagged, isTagged := ref.(reference.NamedTagged); isTagged {
		tag := tagged.Tag()
		manifest, err := manSvc.Get(ctx, "", distribution.WithTag(tag))
		return manifest, err
	}
	if digested, isDigested := ref.(reference.Canonical); isDigested {
		manifest, err := manSvc.Get(ctx, digested.Digest())
		return manifest, err
	}

	return nil, errors.Errorf("image manifest for %q does not exist", ref)
}

func pullManifestSchemaV2(ctx context.Context, ref reference.Named, repo distribution.Repository, mfst schema2.DeserializedManifest) (types.ImageManifest, error) {
	if err := validateManifestDigest(ref, mfst); err != nil {
		return types.ImageManifest{}, err
	}

	configJSON, err := pullManifestSchemaV2ImageConfig(ctx, mfst.Target().Digest, repo)
	if err != nil {
		return types.ImageManifest{}, err
	}

	img, err := types.NewImageFromJSON(configJSON)
	if err != nil {
		return types.ImageManifest{}, err
	}
	if runtime.GOOS == "windows" {
		if img.RootFS == nil {
			return types.ImageManifest{}, errors.New("image config has no rootfs")
		}
	}

	return types.NewImageManifest(ref, *img, &mfst), nil
}

func pullManifestSchemaV2ImageConfig(ctx context.Context, dgst digest.Digest, repo distribution.Repository) ([]byte, error) {
	blobs := repo.Blobs(ctx)
	configJSON, err := blobs.Get(ctx, dgst)
	if err != nil {
		return nil, err
	}

	verifier := dgst.Verifier()
	if err != nil {
		return nil, err
	}
	if _, err := verifier.Write(configJSON); err != nil {
		return nil, err
	}
	if !verifier.Verified() {
		return nil, errors.Errorf("image config verification failed for digest %s", dgst)
	}
	return configJSON, nil
}

// validateManifestDigest computes the manifest digest, and, if pulling by
// digest, ensures that it matches the requested digest.
func validateManifestDigest(ref reference.Named, mfst distribution.Manifest) error {
	_, canonical, err := mfst.Payload()
	if err != nil {
		return err
	}

	// If pull by digest, then verify the manifest digest.
	if digested, isDigested := ref.(reference.Canonical); isDigested {
		verifier := digested.Digest().Verifier()
		if err != nil {
			return err
		}
		if _, err := verifier.Write(canonical); err != nil {
			return err
		}
		if !verifier.Verified() {
			err := fmt.Errorf("manifest verification failed for digest %s", digested.Digest())
			return err
		}
		return nil
	}

	return nil
}

// pullManifestList handles "manifest lists" which point to various
// platform-specific manifests.
func pullManifestList(ctx context.Context, ref reference.Named, repo distribution.Repository, mfstList manifestlist.DeserializedManifestList) ([]types.ImageManifest, error) {
	infos := []types.ImageManifest{}

	if err := validateManifestDigest(ref, mfstList); err != nil {
		return nil, err
	}

	for _, manifestDescriptor := range mfstList.Manifests {
		manSvc, err := repo.Manifests(ctx)
		if err != nil {
			return nil, err
		}
		manifest, err := manSvc.Get(ctx, manifestDescriptor.Digest)
		if err != nil {
			return nil, err
		}
		v, ok := manifest.(*schema2.DeserializedManifest)
		if !ok {
			return nil, fmt.Errorf("unsupported manifest format: %s", v)
		}

		manifestRef, err := reference.WithDigest(ref, manifestDescriptor.Digest)
		if err != nil {
			return nil, err
		}
		imageManifest, err := pullManifestSchemaV2(ctx, manifestRef, repo, *v)
		if err != nil {
			return nil, err
		}
		imageManifest.Platform = manifestDescriptor.Platform
		infos = append(infos, imageManifest)
	}
	return infos, nil
}

func continueOnError(err error) bool {
	switch v := err.(type) {
	case errcode.Errors:
		if len(v) == 0 {
			return true
		}
		return continueOnError(v[0])
	case errcode.Error:
		e := err.(errcode.Error)
		switch e.Code {
		// @TODO: We should try remaning endpoints in these cases?
		case errcode.ErrorCodeUnauthorized, v2.ErrorCodeManifestUnknown, v2.ErrorCodeNameUnknown:
			return true
		}
		return false
	case *distclient.UnexpectedHTTPResponseError:
		return true
	}
	return false
}

func (c *client) iterateEndpoints(ctx context.Context, namedRef reference.Named, each func(context.Context, distribution.Repository, reference.Named) (bool, error)) error {
	endpoints, err := allEndpoints(namedRef)
	if err != nil {
		return err
	}

	opts, err := c.newRepoOptionsForReference(ctx, namedRef)
	if err != nil {
		return err
	}

	confirmedTLSRegistries := make(map[string]bool)
	for _, endpoint := range endpoints {
		if endpoint.Version == registry.APIVersion1 {
			logrus.Debugf("Skipping v1 endpoint %s", endpoint.URL)
			continue
		}

		if endpoint.URL.Scheme != "https" {
			if _, confirmedTLS := confirmedTLSRegistries[endpoint.URL.Host]; confirmedTLS {
				logrus.Debugf("Skipping non-TLS endpoint %s for host/port that appears to use TLS", endpoint.URL)
				continue
			}
		}

		repo, err := opts.getRepository(ctx, endpoint)
		if err != nil {
			return err
		}

		done, err := each(ctx, repo, namedRef)
		if err != nil {
			if continueOnError(err) {
				if endpoint.URL.Scheme == "https" {
					confirmedTLSRegistries[endpoint.URL.Host] = true
				}
				logrus.Debugf("Continuing on error (%T) %s", err, err)
				continue
			}
			return err
		}
		if done {
			return nil
		}
	}
	return nil
}

// allEndpoints returns a list of endpoints ordered by priority (v2, https, v1).
func allEndpoints(namedRef reference.Named) ([]registry.APIEndpoint, error) {
	repoInfo, err := registry.ParseRepositoryInfo(namedRef)
	if err != nil {
		return nil, err
	}
	registryService := registry.NewService(registry.ServiceOptions{})
	endpoints, err := registryService.LookupPullEndpoints(reference.Domain(repoInfo.Name))
	logrus.Debugf("Endpoints for %s: %v", namedRef, endpoints)
	return endpoints, err
}

func (c *client) newRepoOptionsForReference(ctx context.Context, namedRef reference.Named) (repositoryOptions, error) {
	repoInfo, err := registry.ParseRepositoryInfo(namedRef)
	if err != nil {
		return repositoryOptions{}, err
	}
	return repositoryOptions{
		authConfig: c.authConfigResolver(ctx, repoInfo.Index),
		repoInfo:   repoInfo,
		userAgent:  c.userAgent,
	}, nil
}
