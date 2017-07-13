package types

import (
	"encoding/json"
	"time"

	"github.com/docker/distribution/manifest/manifestlist"
	"github.com/docker/distribution/manifest/schema2"
	"github.com/docker/distribution/reference"
	"github.com/docker/docker/api/types/container"
	"github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
)

// ImageManifest contains info to output for a manifest object.
type ImageManifest struct {
	Ref              *SerializableNamed
	Image            Image
	SchemaV2Manifest *schema2.DeserializedManifest `json:",omitempty"`
	Platform         manifestlist.PlatformSpec
}

// Blobs returns the digests for all the blobs referenced by this manifest
func (i ImageManifest) Blobs() []digest.Digest {
	digests := []digest.Digest{}
	for _, descriptor := range i.SchemaV2Manifest.References() {
		digests = append(digests, descriptor.Digest)
	}
	return digests
}

// Layers returns the digests for all the layers referenced by this manifest
func (i ImageManifest) Layers() []digest.Digest {
	digests := []digest.Digest{}
	for _, layer := range i.SchemaV2Manifest.Layers {
		digests = append(digests, layer.Digest)
	}
	return digests
}

// Payload returns the media type and bytes for the manifest
func (i ImageManifest) Payload() (string, []byte, error) {
	return i.SchemaV2Manifest.Payload()
}

// NewImageManifest returns a new ImageManifest object. The values for Platform
// are initialized from those in the image
func NewImageManifest(ref reference.Named, img Image, manifest *schema2.DeserializedManifest) ImageManifest {
	platform := manifestlist.PlatformSpec{
		OS:           img.OS,
		Architecture: img.Architecture,
		OSVersion:    img.OSVersion,
		OSFeatures:   img.OSFeatures,
	}
	return ImageManifest{
		Ref:              &SerializableNamed{Named: ref},
		Image:            img,
		SchemaV2Manifest: manifest,
		Platform:         platform,
	}
}

// SerializableNamed is a reference.Named that can be serialzied and deserialized
// from JSON
type SerializableNamed struct {
	reference.Named
}

// UnmarshalJSON loads the Named reference from JSON bytes
func (s *SerializableNamed) UnmarshalJSON(b []byte) error {
	var raw string
	if err := json.Unmarshal(b, &raw); err != nil {
		return errors.Wrapf(err, "invalid named reference bytes: %s", b)
	}
	var err error
	s.Named, err = reference.ParseNamed(raw)
	return err
}

// MarshalJSON returns the JSON bytes representation
func (s *SerializableNamed) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// The following mirror data structures from docker/docker/image to avoid
// importing all of distribtion/. Replace these with imported types when the
// dependency graph is cleaned up.

// RootFS describes images root filesystem
type RootFS struct {
	Type    string          `json:"type"`
	DiffIDs []digest.Digest `json:"diff_ids,omitempty"`
}

// History stores build commands that were used to create an image
type History struct {
	// Created is the timestamp at which the image was created
	Created time.Time `json:"created"`
	// Author is the name of the author that was specified when committing the image
	Author string `json:"author,omitempty"`
	// CreatedBy keeps the Dockerfile command used while building the image
	CreatedBy string `json:"created_by,omitempty"`
	// Comment is the commit message that was set when committing the image
	Comment string `json:"comment,omitempty"`
	// EmptyLayer is set to true if this history item did not generate a
	// layer. Otherwise, the history item is associated with the next
	// layer in the RootFS section.
	EmptyLayer bool `json:"empty_layer,omitempty"`
}

// Image stores the image configuration
// It contains docker's v1Image fields for simplicity
type Image struct {
	// ID is a unique 64 character identifier of the image
	ID string `json:"id,omitempty"`
	// Parent is the ID of the parent image
	OldParent string `json:"oldparent,omitempty"`
	// Comment is the commit message that was set when committing the image
	Comment string `json:"comment,omitempty"`
	// Created is the timestamp at which the image was created
	Created time.Time `json:"created"`
	// Container is the id of the container used to commit
	Container string `json:"container,omitempty"`
	// ContainerConfig is the configuration of the container that is committed into the image
	ContainerConfig container.Config `json:"container_config,omitempty"`
	// DockerVersion specifies the version of Docker that was used to build the image
	DockerVersion string `json:"docker_version,omitempty"`
	// Author is the name of the author that was specified when committing the image
	Author string `json:"author,omitempty"`
	// Config is the configuration of the container received from the client
	Config *container.Config `json:"config,omitempty"`
	// Architecture is the hardware that the image is built and runs on
	Architecture string `json:"architecture,omitempty"`
	// OS is the operating system used to build and run the image
	OS string `json:"os,omitempty"`
	// Size is the total size of the image including all layers it is composed of
	Size       int64         `json:",omitempty"`
	Parent     digest.Digest `json:"parent,omitempty"`
	RootFS     *RootFS       `json:"rootfs,omitempty"`
	History    []History     `json:"history,omitempty"`
	OSVersion  string        `json:"os.version,omitempty"`
	OSFeatures []string      `json:"os.features,omitempty"`
}

// NewImageFromJSON creates an Image configuration from json.
func NewImageFromJSON(src []byte) (*Image, error) {
	img := &Image{}
	if err := json.Unmarshal(src, img); err != nil {
		return nil, err
	}
	return img, nil
}
