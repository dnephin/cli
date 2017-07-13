package manifest

import (
	"github.com/Sirupsen/logrus"
	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
)

type annotateOptions struct {
	target     string // the target manifest list name (also transaction ID)
	image      string // the manifest to annotate within the list
	variant    string // an architecture variant
	os         string
	arch       string
	osFeatures []string
}

// NewAnnotateCommand creates a new `docker manifest annotate` command
func newAnnotateCommand(dockerCli command.Cli) *cobra.Command {
	var opts annotateOptions

	cmd := &cobra.Command{
		Use:   "annotate NAME[:TAG] [OPTIONS]",
		Short: "Add additional information to a local image manifest",
		Args:  cli.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.target = args[0]
			opts.image = args[1]
			return runManifestAnnotate(dockerCli, opts)
		},
	}

	flags := cmd.Flags()

	flags.StringVar(&opts.os, "os", "", "Add os info to a manifest before pushing it.")
	flags.StringVar(&opts.arch, "arch", "", "Add arch info to a manifest before pushing it.")
	flags.StringSliceVar(&opts.osFeatures, "os-features", []string{}, "Add feature info to a manifest before pushing it.")
	flags.StringVar(&opts.variant, "variant", "", "Add arch variant to a manifest before pushing it.")

	return cmd
}

func runManifestAnnotate(dockerCli command.Cli, opts annotateOptions) error {
	targetRef, err := normalizeReference(opts.target)
	if err != nil {
		return errors.Wrapf(err, "annotate: Error parsing name for manifest list (%s): %s", opts.target)
	}
	imgRef, err := normalizeReference(opts.image)
	if err != nil {
		return errors.Wrapf(err, "annotate: Error parsing name for manifest (%s): %s:", opts.image)
	}

	logrus.Debugf("beginning annotate for %s/%s", targetRef, imgRef)

	ctx := context.Background()
	manifestStore := dockerCli.ManifestStore()
	imageManfiest, err := manifestStore.Get(targetRef, imgRef)
	switch {
	case err != nil:
		return err
	case imageManfiest == nil:
		remoteManifest, err := getManifest(ctx, dockerCli, targetRef, imgRef)
		if err != nil {
			return err
		}
		if err := manifestStore.Save(targetRef, imgRef, remoteManifest); err != nil {
			return err
		}
		imageManfiest = &remoteManifest
	}

	// Update the mf
	if opts.os != "" {
		imageManfiest.Platform.OS = opts.os
	}
	if opts.arch != "" {
		imageManfiest.Platform.Architecture = opts.arch
	}
	for _, osFeature := range opts.osFeatures {
		imageManfiest.Platform.OSFeatures = appendIfUnique(imageManfiest.Platform.OSFeatures, osFeature)
	}
	if opts.variant != "" {
		imageManfiest.Platform.Variant = opts.variant
	}

	if !isValidOSArch(imageManfiest.Platform.OS, imageManfiest.Platform.Architecture) {
		return errors.Errorf("manifest entry for image has unsupported os/arch combination: %s/%s", opts.os, opts.arch)
	}
	return manifestStore.Save(targetRef, imgRef, *imageManfiest)
}

func appendIfUnique(list []string, str string) []string {
	for _, s := range list {
		if s == str {
			return list
		}
	}
	return append(list, str)
}
