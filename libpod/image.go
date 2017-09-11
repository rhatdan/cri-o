package libpod

import (
	"fmt"
	"io"
	"strings"
	"syscall"
	"time"

	cp "github.com/containers/image/copy"
	"github.com/containers/image/docker/tarfile"
	"github.com/containers/image/manifest"
	"github.com/containers/image/signature"
	is "github.com/containers/image/storage"
	"github.com/containers/image/transports/alltransports"
	"github.com/containers/image/types"
	"github.com/containers/storage"
	"github.com/containers/storage/pkg/archive"
	"github.com/kubernetes-incubator/cri-o/libpod/common"
	"github.com/kubernetes-incubator/cri-o/libpod/ctr"
	digest "github.com/opencontainers/go-digest"
	ociv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

// Runtime API

const (
	// DefaultRegistry is a prefix that we apply to an image name
	// to check docker hub first for the image
	DefaultRegistry = "docker://"
)

// CopyOptions contains the options given when pushing or pulling images
type CopyOptions struct {
	// Compression specifies the type of compression which is applied to
	// layer blobs.  The default is to not use compression, but
	// archive.Gzip is recommended.
	Compression archive.Compression
	// DockerRegistryOptions encapsulates settings that affect how we
	// connect or authenticate to a remote registry to which we want to
	// push the image.
	common.DockerRegistryOptions
	// SigningOptions encapsulates settings that control whether or not we
	// strip or add signatures to the image when pushing (uploading) the
	// image to a registry.
	common.SigningOptions

	// SigningPolicyPath this points to a alternative signature policy file, used mainly for testing
	SignaturePolicyPath string
}

// Image API

// ImageFilter is a function to determine whether an image is included in
// command output. Images to be outputted are tested using the function. A true
// return will include the image, a false return will exclude it.
type ImageFilter func(*storage.Image) bool

// PullImage pulls an image from configured registries
// By default, only the latest tag (or a specific tag if requested) will be
// pulled. If allTags is true, all tags for the requested image will be pulled.
// Signature validation will be performed if the Runtime has been appropriately
// configured
func (r *Runtime) PullImage(imgName string, allTags bool, reportWriter io.Writer) error {
	// PullImage copies the image from the source to the destination
	var (
		images []string
	)

	srcRef, err := alltransports.ParseImageName(imgName)
	if err != nil {
		defaultName := DefaultRegistry + imgName
		srcRef2, err2 := alltransports.ParseImageName(defaultName)
		if err2 != nil {
			return errors.Errorf("error parsing image name %q: %v", defaultName, err2)
		}
		srcRef = srcRef2
	}

	splitArr := strings.Split(imgName, ":")

	// supports pulling from docker-archive, oci, and registries
	if splitArr[0] == "docker-archive" {
		tarSource := tarfile.NewSource(splitArr[len(splitArr)-1])
		manifest, err := tarSource.LoadTarManifest()
		if err != nil {
			return errors.Errorf("error retrieving manifest.json: %v", err)
		}
		// to pull all the images stored in one tar file
		for i := range manifest {
			if manifest[i].RepoTags != nil {
				images = append(images, manifest[i].RepoTags[0])
			} else {
				// create an image object and use the hex value of the digest as the image ID
				// for parsing the store reference
				newImg, err := srcRef.NewImage(r.imageContext)
				if err != nil {
					return err
				}
				defer newImg.Close()
				digest := newImg.ConfigInfo().Digest
				if err := digest.Validate(); err == nil {
					images = append(images, "@"+digest.Hex())
				} else {
					return errors.Wrapf(err, "error getting config info")
				}
			}
		}
	} else if splitArr[0] == "oci" {
		// needs to be implemented in future
		return errors.Errorf("oci not supported")
	} else {
		images = append(images, imgName)
	}

	policy, err := signature.DefaultPolicy(r.imageContext)
	if err != nil {
		return err
	}

	policyContext, err := signature.NewPolicyContext(policy)
	if err != nil {
		return err
	}
	defer policyContext.Destroy()

	copyOptions := common.GetCopyOptions(reportWriter, "", nil, nil, common.SigningOptions{})

	for _, image := range images {
		destRef, err := is.Transport.ParseStoreReference(r.store, image)
		if err != nil {
			return errors.Errorf("error parsing dest reference name: %v", err)
		}
		if err = cp.Image(policyContext, destRef, srcRef, copyOptions); err != nil {
			return errors.Errorf("error loading image %q: %v", image, err)
		}
	}
	return nil
}

// PushImage pushes the given image to a location described by the given path
func (r *Runtime) PushImage(source string, destination string, options CopyOptions, reportWriter io.Writer) error {
	// PushImage pushes the src image to the destination
	//func PushImage(source, destination string, options CopyOptions) error {
	if source == "" || destination == "" {
		return errors.Wrapf(syscall.EINVAL, "source and destination image names must be specified")
	}

	// Get the destination Image Reference
	dest, err := alltransports.ParseImageName(destination)
	if err != nil {
		return errors.Wrapf(err, "error getting destination imageReference for %q", destination)
	}

	policyContext, err := common.GetPolicyContext(r.GetConfig().SignaturePolicyPath)
	if err != nil {
		return errors.Wrapf(err, "Could not get default policy context for signature policy path %q", r.GetConfig().SignaturePolicyPath)
	}
	defer policyContext.Destroy()
	// Look up the image name and its layer, then build the imagePushData from
	// the image
	img, err := r.GetImage(source)
	if err != nil {
		return errors.Wrapf(err, "error locating image %q for importing settings", source)
	}
	cd, err := r.ImportCopyDataFromImage(r.imageContext, img.ID, "", "")
	if err != nil {
		return err
	}
	// Give the image we're producing the same ancestors as its source image
	cd.FromImage = cd.Docker.ContainerConfig.Image
	cd.FromImageID = string(cd.Docker.Parent)

	// Prep the layers and manifest for export
	src, err := cd.MakeImageRef(manifest.GuessMIMEType(cd.Manifest), options.Compression, img.Names, img.TopLayer, nil)
	if err != nil {
		return errors.Wrapf(err, "error copying layers and metadata")
	}

	copyOptions := common.GetCopyOptions(reportWriter, r.GetConfig().SignaturePolicyPath, nil, &options.DockerRegistryOptions, options.SigningOptions)

	// Copy the image to the remote destination
	err = cp.Image(policyContext, dest, src, copyOptions)
	if err != nil {
		return errors.Wrapf(err, "Error copying image to the remote destination")
	}
	return nil
}

// TagImage adds a tag to the given image
func (r *Runtime) TagImage(image *storage.Image, tag string) error {
	tags, err := r.store.Names(image.ID)
	if err != nil {
		return err
	}
	for _, key := range tags {
		if key == tag {
			return nil
		}
	}
	tags = append(tags, tag)
	return r.store.SetNames(image.ID, tags)
}

// UntagImage removes a tag from the given image
func (r *Runtime) UntagImage(image *storage.Image, tag string) error {
	tags, err := r.store.Names(image.ID)
	if err != nil {
		return err
	}
	for i, key := range tags {
		if key == tag {
			tags[i] = tags[len(tags)-1]
			tags = tags[:len(tags)-1]
			break
		}
	}
	return r.store.SetNames(image.ID, tags)
}

// RemoveImage deletes an image from local storage
// Images being used by running containers cannot be removed
func (r *Runtime) RemoveImage(image *storage.Image) error {
	_, err := r.store.DeleteImage(image.ID, false)
	return err
}

// GetImage retrieves an image matching the given name or hash from system
// storage
// If no matching image can be found, an error is returned
func (r *Runtime) GetImage(image string) (*storage.Image, error) {
	var img *storage.Image
	ref, err := is.Transport.ParseStoreReference(r.store, image)
	if err == nil {
		img, err = is.Transport.GetStoreImage(r.store, ref)
	}
	if err != nil {
		img2, err2 := r.store.Image(image)
		if err2 != nil {
			if ref == nil {
				return nil, errors.Wrapf(err, "error parsing reference to image %q", image)
			}
			return nil, errors.Wrapf(err, "unable to locate image %q", image)
		}
		img = img2
	}
	return img, nil
}

// GetImageRef searches for and returns a new types.Image matching the given name or ID in the given store.
func (r *Runtime) GetImageRef(image string) (types.Image, error) {
	img, err := r.GetImage(image)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to locate image %q", image)
	}
	ref, err := is.Transport.ParseStoreReference(r.store, "@"+img.ID)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing reference to image %q", img.ID)
	}
	imgRef, err := ref.NewImage(nil)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading image %q", img.ID)
	}
	return imgRef, nil
}

// GetImages retrieves all images present in storage
// Filters can be provided which will determine which images are included in the
// output. Multiple filters are handled by ANDing their output, so only images
// matching all filters are included
func (r *Runtime) GetImages(filter ...ImageFilter) ([]*storage.Image, error) {
	return nil, ctr.ErrNotImplemented
}

// ImportImage imports an OCI format image archive into storage as an image
func (r *Runtime) ImportImage(path string) (*storage.Image, error) {
	return nil, ctr.ErrNotImplemented
}

// FilterParams contains the filter options that may be given when outputting images
type FilterParams struct {
	dangling         string
	label            string
	beforeImage      time.Time
	sinceImage       time.Time
	referencePattern string
}

func matchesFilter(image storage.Image, name string, params *FilterParams) bool {
	if params == nil {
		return true
	}

	info, err := r.getImageInspectInfo(image)
	if err != nil {
		return false
	}
	if params.dangling != "" && !matchesDangling(name, params.dangling) {
		return false
	} else if params.label != "" && !matchesLabel(info, params.label) {
		return false
	} else if !params.beforeImage.IsZero() && !matchesBeforeImage(info, name, params) {
		return false
	} else if !params.sinceImage.IsZero() && !matchesSinceImage(info, name, params) {
		return false
	} else if params.referencePattern != "" && !MatchesReference(name, params.referencePattern) {
		return false
	}
	return true
}

// GetImagesMatchingFilter returns a slice of all images in the store that match the provided FilterParams.
// Images with more than one name matching the filter will be in the slice once for each name
func (r *Runtime) GetImagesMatchingFilter(filter *FilterParams, argName string) ([]storage.Image, error) {
	images, err := r.store.Images()
	filteredImages := []storage.Image{}
	if err != nil {
		return nil, err
	}
	for _, image := range images {
		names := []string{}
		if len(image.Names) > 0 {
			names = image.Names
		} else {
			names = append(names, "<none>")
		}
		for _, name := range names {
			if (filter == nil && argName == "") || (filter != nil && matchesFilter(image, name, filter)) || MatchesReference(name, argName) {
				newImage := image
				newImage.Names = []string{name}
				filteredImages = append(filteredImages, newImage)
			}
		}
	}
	return filteredImages, nil
}

func (r *Runtime) getImageInspectInfo(image storage.Image) (*types.ImageInspectInfo, error) {
	storeRef, err := is.Transport.ParseStoreReference(r.store, "@"+image.ID)
	if err != nil {
		return nil, err
	}
	img, err := storeRef.NewImage(nil)
	if err != nil {
		return nil, err
	}
	defer img.Close()
	return img.Inspect()
}

func matchesDangling(name string, dangling string) bool {
	if common.IsFalse(dangling) && name != "<none>" {
		return true
	} else if common.IsTrue(dangling) && name == "<none>" {
		return true
	}
	return false
}

func matchesLabel(info *types.ImageInspectInfo, label string) bool {
	pair := strings.SplitN(label, "=", 2)
	for key, value := range info.Labels {
		if key == pair[0] {
			if len(pair) == 2 {
				if value == pair[1] {
					return true
				}
			} else {
				return false
			}
		}
	}
	return false
}

// Returns true if the image was created since the filter image.  Returns
// false otherwise
func matchesBeforeImage(info *types.ImageInspectInfo, name string, params *FilterParams) bool {
	return info.Created.Before(params.beforeImage)
}

// Returns true if the image was created since the filter image.  Returns
// false otherwise
func matchesSinceImage(info *types.ImageInspectInfo, name string, params *FilterParams) bool {
	return info.Created.After(params.sinceImage)
}

func findImageInSlice(images []storage.Image, ref string) (storage.Image, error) {
	for _, image := range images {
		if MatchesID(image.ID, ref) {
			return image, nil
		}
		for _, name := range image.Names {
			if MatchesReference(name, ref) {
				return image, nil
			}
		}
	}
	return storage.Image{}, errors.New("could not find image")
}

// ParseFilter takes a set of images and a filter string as input, and returns the
func (r *Runtime) ParseFilter(filter string) (*FilterParams, error) {
	images, err := r.store.Images()
	if err != nil {
		return nil, err
	}
	params := new(FilterParams)
	filterStrings := strings.Split(filter, ",")
	for _, param := range filterStrings {
		pair := strings.SplitN(param, "=", 2)
		switch strings.TrimSpace(pair[0]) {
		case "dangling":
			if common.IsValidBool(pair[1]) {
				params.dangling = pair[1]
			} else {
				return nil, fmt.Errorf("invalid filter: '%s=[%s]'", pair[0], pair[1])
			}
		case "label":
			params.label = pair[1]
		case "before":
			if img, err := findImageInSlice(images, pair[1]); err == nil {
				info, err := r.getImageInspectInfo(img)
				if err != nil {
					return nil, err
				}
				params.beforeImage = info.Created
			} else {
				return nil, fmt.Errorf("no such id: %s", pair[0])
			}
		case "since":
			if img, err := findImageInSlice(images, pair[1]); err == nil {
				info, err := r.getImageInspectInfo(img)
				if err != nil {
					return nil, err
				}
				params.sinceImage = info.Created
			} else {
				return nil, fmt.Errorf("no such id: %s``", pair[0])
			}
		case "reference":
			params.referencePattern = pair[1]
		default:
			return nil, fmt.Errorf("invalid filter: '%s'", pair[0])
		}
	}
	return params, nil
}

// InfoAndDigestAndSize returns the inspection info and size of the image in the given
// store and the digest of its manifest, if it has one, or "" if it doesn't.
func (r *Runtime) InfoAndDigestAndSize(img storage.Image) (*types.ImageInspectInfo, digest.Digest, int64, error) {
	imgRef, err := r.GetImageRef("@" + img.ID)
	if err != nil {
		return nil, "", -1, errors.Wrapf(err, "error reading image %q", img.ID)
	}
	defer imgRef.Close()
	return infoAndDigestAndSize(imgRef)
}

func infoAndDigestAndSize(imgRef types.Image) (*types.ImageInspectInfo, digest.Digest, int64, error) {
	imgSize, err := imgRef.Size()
	if err != nil {
		return nil, "", -1, errors.Wrapf(err, "error reading size of image %q", transports.ImageName(imgRef.Reference()))
	}
	manifest, _, err := imgRef.Manifest()
	if err != nil {
		return nil, "", -1, errors.Wrapf(err, "error reading manifest for image %q", transports.ImageName(imgRef.Reference()))
	}
	manifestDigest := digest.Digest("")
	if len(manifest) > 0 {
		manifestDigest = digest.Canonical.FromBytes(manifest)
	}
	info, err := imgRef.Inspect()
	if err != nil {
		return nil, "", -1, errors.Wrapf(err, "error inspecting image %q", transports.ImageName(imgRef.Reference()))
	}
	return info, manifestDigest, imgSize, nil
}

// MatchesID returns true if argID is a full or partial match for id
func MatchesID(id, argID string) bool {
	return strings.HasPrefix(argID, id)
}

// MatchesReference returns true if argName is a full or partial match for name
// Partial matches will register only if they match the most specific part of the name available
// For example, take the image docker.io/library/redis:latest
// redis, library,redis, docker.io/library/redis, redis:latest, etc. will match
// But redis:alpine, ry/redis, library, and io/library/redis will not
func MatchesReference(name, argName string) bool {
	if argName == "" {
		return false
	}
	splitName := strings.Split(name, ":")
	// If the arg contains a tag, we handle it differently than if it does not
	if strings.Contains(argName, ":") {
		splitArg := strings.Split(argName, ":")
		return strings.HasSuffix(splitName[0], splitArg[0]) && (splitName[1] == splitArg[1])
	}
	return strings.HasSuffix(splitName[0], argName)
}

// FormattedSize returns a human-readable formatted size for the image
func FormattedSize(size float64) string {
	suffixes := [5]string{"B", "KB", "MB", "GB", "TB"}

	count := 0
	for size >= 1024 && count < 4 {
		size /= 1024
		count++
	}
	return fmt.Sprintf("%.4g %s", size, suffixes[count])
}

// ParseImageNames parses the names we've stored with an image into a list of
// tagged references and a list of references which contain digests.
func ParseImageNames(names []string) (tags, digests []string, err error) {
	for _, name := range names {
		if named, err := reference.ParseNamed(name); err == nil {
			if digested, ok := named.(reference.Digested); ok {
				canonical, err := reference.WithDigest(named, digested.Digest())
				if err == nil {
					digests = append(digests, canonical.String())
				}
			} else {
				if reference.IsNameOnly(named) {
					named = reference.TagNameOnly(named)
				}
				if tagged, ok := named.(reference.Tagged); ok {
					namedTagged, err := reference.WithTag(named, tagged.Tag())
					if err == nil {
						tags = append(tags, namedTagged.String())
					}
				}
			}
		}
	}
	return tags, digests, nil
}

func annotations(manifest []byte, manifestType string) map[string]string {
	annotations := make(map[string]string)
	switch manifestType {
	case ociv1.MediaTypeImageManifest:
		var m ociv1.Manifest
		if err := json.Unmarshal(manifest, &m); err == nil {
			for k, v := range m.Annotations {
				annotations[k] = v
			}
		}
	}
	return annotations
}
