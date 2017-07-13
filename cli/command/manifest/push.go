package manifest

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"

	"github.com/Sirupsen/logrus"
	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/config/configfile"
	"github.com/docker/cli/cli/manifest/store"
	"github.com/docker/cli/cli/manifest/types"
	registryclient "github.com/docker/cli/cli/registry/client"
	"github.com/docker/distribution/manifest/manifestlist"
	"github.com/docker/distribution/reference"
	"github.com/docker/docker/pkg/homedir"
	"github.com/docker/docker/registry"
	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
)

type pushOpts struct {
	file   string
	purge  bool
	target string
}

// if we have mounted blobs referenced from manifests from
// outside the target repository namespace we will need to
// push them to our target's repo as they will be references
// from the final manifest list object we push
type manifestPush struct {
	Name      string
	Digest    string
	JSONBytes []byte
	MediaType string
}

type manifestListPush struct {
	targetRef     reference.Named
	list          manifestlist.ManifestList
	mountRequests []manifestPush
	manfiestBlobs []reference.Canonical
}

func newPushListCommand(dockerCli command.Cli) *cobra.Command {
	opts := pushOpts{}

	cmd := &cobra.Command{
		Use:   "push [OPTIONS] MANIFEST_LIST",
		Short: "Push a manifest list to a repository",
		Args:  cli.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.target = args[0]
			return runPush(dockerCli, opts)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&opts.file, "file", "f", "", "Path to a file containing a manifest list and its annotated constituent manifests")
	flags.BoolVarP(&opts.purge, "purge", "p", true, "After pushing, delete the user's locally-stored manifest list info")

	return cmd
}

func runPush(dockerCli command.Cli, opts pushOpts) error {
	targetRef, err := normalizeReference(opts.target)
	if err != nil {
		return err
	}

	listPush, err := listFromTransaction(dockerCli.ManifestStore(), targetRef)
	if err != nil {
		return err
	}

	ctx := context.Background()
	if err := pushList(ctx, dockerCli, listPush, targetRef); err != nil {
		return err
	}
	if opts.purge {
		return dockerCli.ManifestStore().Remove(targetRef)
	}
	return nil
}

func pushList(ctx context.Context, dockerCli command.Cli, listPush manifestListPush, bareRef reference.Named) error {
	// TODO: this should be done somewhere else
	listPush.list.Versioned = manifestlist.SchemaVersion

	rclient := dockerCli.RegistryClient()
	if err := mountBlobs(ctx, rclient, listPush.targetRef, listPush.manfiestBlobs); err != nil {
		return err
	}

	// we also must push any manifests that are referenced in the manifest list into
	// the target namespace
	// Use the untagged target for this so the digest is used
	// *could* i use targetRef instead of bareRef??
	if err := pushReferences(ctx, rclient, bareRef, listPush.mountRequests); err != nil {
		return errors.Wrap(err, "couldn't push manifests referenced in our manifest list")
	}

	request, err := manifestRequestFromManifestList(listPush.list)
	if err != nil {
		return err
	}
	dgst, err := rclient.PutManifest(ctx, listPush.targetRef, request)
	if err != nil {
		return err
	}
	fmt.Fprintln(dockerCli.Out(), dgst.String())
	return nil
}

func listFromTransaction(manifestStore store.Store, targetRef reference.Named) (manifestListPush, error) {
	listPush := manifestListPush{targetRef: targetRef}
	targetRepoInfo, err := registry.ParseRepositoryInfo(targetRef)
	if err != nil {
		return listPush, err
	}
	_, targetRepoName, err := setupRepo(targetRepoInfo)
	if err != nil {
		return listPush, err
	}

	manifests, err := manifestStore.GetList(targetRef)
	if err != nil {
		return listPush, err
	}
	if len(manifests) == 0 {
		return listPush, fmt.Errorf("%s not found", targetRef)
	}
	// manifests is a list of file paths
	for _, imageManifest := range manifests {
		if imageManifest.Platform.Architecture == "" || imageManifest.Platform.OS == "" {
			return listPush, errors.Errorf(
				"manifest %s must have an OS and Architecture to be pushed to a registry", imageManifest.Ref)
		}
		manifest, repoInfo, err := buildManifestDescriptor(targetRepoInfo, imageManifest)
		if err != nil {
			return listPush, err
		}
		listPush.list.Manifests = append(listPush.list.Manifests, manifest)

		// if this image is in a different repo, we need to add the layer/blob digests to the list of
		// requested blob mounts (cross-repository push) before pushing the manifest list
		// @TODO: Test pushing manifest list where targetRepoName == manifestRepoName for all manifests
		manifestRepoName := reference.Path(repoInfo.Name)
		if targetRepoName != manifestRepoName {
			blobs, err := buildBlobRequestList(imageManifest, targetRepoInfo.Name, repoInfo.Name)
			if err != nil {
				return listPush, err
			}
			listPush.manfiestBlobs = append(listPush.manfiestBlobs, blobs...)

			manifestPush, err := buildManifestPush(imageManifest, targetRepoInfo.Name, repoInfo.Name)
			if err != nil {
				return listPush, err
			}
			listPush.mountRequests = append(listPush.mountRequests, manifestPush)
		}
	}
	return listPush, nil
}

func buildManifestDescriptor(targetRepo *registry.RepositoryInfo, imageManifest types.ImageManifest) (manifestlist.ManifestDescriptor, *registry.RepositoryInfo, error) {
	repoInfo, err := registry.ParseRepositoryInfo(imageManifest.Ref)
	if err != nil {
		return manifestlist.ManifestDescriptor{}, nil, err
	}

	manifestRepoHostname := reference.Domain(repoInfo.Name)
	targetRepoHostname := reference.Domain(targetRepo.Name)
	if manifestRepoHostname != targetRepoHostname {
		return manifestlist.ManifestDescriptor{}, nil, fmt.Errorf("cannot use source images from a different registry than the target image: %s != %s", manifestRepoHostname, targetRepoHostname)
	}

	mediaType, raw, err := imageManifest.Payload()
	if err != nil {
		return manifestlist.ManifestDescriptor{}, nil, err
	}

	manifest := manifestlist.ManifestDescriptor{
		Platform: imageManifest.Platform,
	}
	manifest.Descriptor.Digest = digest.FromBytes(raw)
	manifest.Size = int64(len(raw))
	manifest.MediaType = mediaType

	if err = manifest.Descriptor.Digest.Validate(); err != nil {
		return manifestlist.ManifestDescriptor{}, nil, errors.Wrapf(err,
			"digest parse of image %q failed with error: %v", imageManifest.Ref)
	}

	return manifest, repoInfo, nil
}

func buildBlobRequestList(imageManifest types.ImageManifest, targetRepoName, mfRepoName reference.Named) ([]reference.Canonical, error) {
	logrus.Debugf("adding manifest references of %q to blob mount requests to %s", mfRepoName, targetRepoName)

	var blobReferences []reference.Canonical
	for _, blobDigest := range imageManifest.Blobs() {
		canonical, err := reference.WithDigest(targetRepoName, blobDigest)
		if err != nil {
			return nil, err
		}
		blobReferences = append(blobReferences, canonical)
	}
	return blobReferences, nil
}

func buildManifestPush(imageManifest types.ImageManifest, targetRepoName, mfRepoName reference.Named) (manifestPush, error) {
	logrus.Debugf("adding manifest %q -> to be pushed to %q as a manifest reference", mfRepoName, targetRepoName)

	mediaType, raw, err := imageManifest.Payload()
	if err != nil {
		return manifestPush{}, err
	}

	return manifestPush{
		Name:      mfRepoName.String(),
		Digest:    digest.FromBytes(raw).String(), // TODO: is this right?
		JSONBytes: raw,
		MediaType: mediaType,
	}, nil
}

// TODO: look into duplicated with client
func setupRepo(repoInfo *registry.RepositoryInfo) (registry.APIEndpoint, string, error) {
	endpoint, err := selectPushEndpoint(repoInfo)
	if err != nil {
		return endpoint, "", err
	}
	repoName := repoInfo.Name.Name()
	// If endpoint does not support CanonicalName, use the RemoteName instead
	if endpoint.TrimHostname {
		repoName = reference.Path(repoInfo.Name)
	}
	return endpoint, repoName, nil
}

func selectPushEndpoint(repoInfo *registry.RepositoryInfo) (registry.APIEndpoint, error) {
	var err error

	options := registry.ServiceOptions{}
	// By default (unless deprecated), loopback (IPv4 at least...) is automatically added as an insecure registry.
	options.InsecureRegistries, err = loadLocalInsecureRegistries()
	if err != nil {
		return registry.APIEndpoint{}, err
	}
	registryService := registry.NewService(options)
	endpoints, err := registryService.LookupPushEndpoints(reference.Domain(repoInfo.Name))
	if err != nil {
		return registry.APIEndpoint{}, err
	}
	// Default to the highest priority endpoint to return
	endpoint := endpoints[0]
	if !repoInfo.Index.Secure {
		for _, ep := range endpoints {
			if ep.URL.Scheme == "http" {
				endpoint = ep
			}
		}
	}
	return endpoint, nil
}

func loadLocalInsecureRegistries() ([]string, error) {
	insecureRegistries := []string{}
	// Check $HOME/.docker/config.json. There may be mismatches between what the user has in their
	// local config and what the daemon they're talking to allows, but we can be okay with that.
	userHome, err := homedir.GetStatic()
	if err != nil {
		return []string{}, fmt.Errorf("manifest create: lookup local insecure registries: Unable to retrieve $HOME")
	}

	jsonData, err := ioutil.ReadFile(filepath.Join(userHome, ".docker/config.json"))
	if err != nil {
		if !os.IsNotExist(err) {
			return []string{}, errors.Wrap(err, "manifest create:")
		}
		// If the file just doesn't exist, no insecure registries were specified.
		logrus.Debug("manifest: no insecure registries were specified via $HOME/.docker/config.json")
		return []string{}, nil
	}

	if jsonData != nil {
		cf := configfile.ConfigFile{}
		if err := json.Unmarshal(jsonData, &cf); err != nil {
			logrus.Debugf("manifest create: unable to unmarshal insecure registries from $HOME/.docker/config.json: %s", err)
			return []string{}, nil
		}
		if cf.InsecureRegistries == nil {
			return []string{}, nil
		}
		// @TODO: Add tests for a) specifying in config.json, b) invalid entries
		for _, reg := range cf.InsecureRegistries {
			if err := net.ParseIP(reg); err == nil {
				insecureRegistries = append(insecureRegistries, reg)
			} else if _, _, err := net.ParseCIDR(reg); err == nil {
				insecureRegistries = append(insecureRegistries, reg)
			} else if ips, err := net.LookupHost(reg); err == nil {
				insecureRegistries = append(insecureRegistries, ips...)
			} else {
				return []string{}, errors.Wrapf(err, "manifest create: Invalid registry (%s) specified in ~/.docker/config.json: %s", reg)
			}
		}
	}

	return insecureRegistries, nil
}

func pushReferences(ctx context.Context, client registryclient.RegistryClient, ref reference.Named, manifests []manifestPush) error {
	for _, manifest := range manifests {
		dgst, err := digest.Parse(manifest.Digest)
		if err != nil {
			return errors.Wrapf(err, "error parsing manifest digest (%s) for referenced manifest %q", manifest.Digest, manifest.Name)
		}
		targetRef, err := reference.WithDigest(ref, dgst)
		if err != nil {
			return err
		}

		// TODO: build manifestRequest before this function and pass them in
		newDigest, err := client.PutManifest(ctx, targetRef, registryclient.PutManifestOptions{
			MediaType: manifest.MediaType,
			Payload:   manifest.JSONBytes,
		})
		if err != nil {
			return err
		}
		logrus.Infof("Pushed manifest %s with digest: %s", manifest.Name, newDigest)
	}
	return nil
}

func mountBlobs(ctx context.Context, client registryclient.RegistryClient, ref reference.Named, blobs []reference.Canonical) error {
	for _, blob := range blobs {
		if err := client.MountBlob(ctx, ref, blob); err != nil {
			return errors.Wrapf(err, "failed to mount blob %s", blob)
		}
	}
	return nil
}

func manifestRequestFromManifestList(list manifestlist.ManifestList) (registryclient.PutManifestOptions, error) {
	deserializedManifestList, err := manifestlist.FromDescriptors(list.Manifests)
	if err != nil {
		return registryclient.PutManifestOptions{}, errors.Wrap(err, "failed to deserialize manifest list")
	}
	mediaType, rawBytes, _ := deserializedManifestList.Payload()
	return registryclient.PutManifestOptions{
		MediaType: mediaType,
		Payload:   rawBytes,
	}, nil
}
