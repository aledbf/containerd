/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package walking

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/diff"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/pkg/archive"
	"github.com/containerd/containerd/v2/pkg/archive/compression"
	"github.com/containerd/containerd/v2/pkg/epoch"
	"github.com/containerd/containerd/v2/pkg/labels"
)

type walkingDiff struct {
	store content.Store
	mm    mount.Manager
}

var emptyDesc = ocispec.Descriptor{}

// Option configures the walking differ.
type Option func(*walkingDiff)

// WithMountManager sets the mount manager used to resolve formatted mounts.
func WithMountManager(mm mount.Manager) Option {
	return func(d *walkingDiff) {
		d.mm = mm
	}
}

// NewWalkingDiff is a generic implementation of diff.Comparer.  The diff is
// calculated by mounting both the upper and lower mount sets and walking the
// mounted directories concurrently. Changes are calculated by comparing files
// against each other or by comparing file existence between directories.
// NewWalkingDiff uses no special characteristics of the mount sets and is
// expected to work with any filesystem.
func NewWalkingDiff(store content.Store, opts ...Option) diff.Comparer {
	d := &walkingDiff{
		store: store,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// Compare creates a diff between the given mounts and uploads the result
// to the content store.
func (s *walkingDiff) Compare(ctx context.Context, lower, upper []mount.Mount, opts ...diff.Opt) (d ocispec.Descriptor, err error) {
	var config diff.Config
	for _, opt := range opts {
		if err := opt(&config); err != nil {
			return emptyDesc, err
		}
	}
	if tm := epoch.FromContext(ctx); tm != nil && config.SourceDateEpoch == nil {
		config.SourceDateEpoch = tm
	}

	var writeDiffOpts []archive.WriteDiffOpt
	if config.SourceDateEpoch != nil {
		writeDiffOpts = append(writeDiffOpts, archive.WithSourceDateEpoch(config.SourceDateEpoch))
	}

	compressionType := compression.Uncompressed
	if config.Compressor != nil {
		if config.MediaType == "" {
			return emptyDesc, errors.New("media type must be explicitly specified when using custom compressor")
		}
		compressionType = compression.Unknown
	} else {
		if config.MediaType == "" {
			config.MediaType = ocispec.MediaTypeImageLayerGzip
		}

		switch config.MediaType {
		case ocispec.MediaTypeImageLayer:
		case ocispec.MediaTypeImageLayerGzip:
			compressionType = compression.Gzip
		case ocispec.MediaTypeImageLayerZstd:
			compressionType = compression.Zstd
		default:
			return emptyDesc, fmt.Errorf("unsupported diff media type: %v: %w", config.MediaType, errdefs.ErrNotImplemented)
		}
	}

	var ocidesc ocispec.Descriptor
	if err := s.withLowerMount(ctx, lower, func(lowerRoot string) error {
		return s.withUpperMount(ctx, upper, func(upperRoot string) error {
			var newReference bool
			if config.Reference == "" {
				newReference = true
				config.Reference = uniqueRef()
			}

			cw, err := s.store.Writer(ctx,
				content.WithRef(config.Reference),
				content.WithDescriptor(ocispec.Descriptor{
					MediaType: config.MediaType, // most contentstore implementations just ignore this
				}))
			if err != nil {
				return fmt.Errorf("failed to open writer: %w", err)
			}

			// errOpen is set when an error occurs while the content writer has not been
			// committed or closed yet to force a cleanup
			var errOpen error
			defer func() {
				if errOpen != nil {
					cw.Close()
					if newReference {
						if abortErr := s.store.Abort(ctx, config.Reference); abortErr != nil {
							log.G(ctx).WithError(abortErr).WithField("ref", config.Reference).Warnf("failed to delete diff upload")
						}
					}
				}
			}()
			if !newReference {
				if errOpen = cw.Truncate(0); errOpen != nil {
					return errOpen
				}
			}

			if compressionType != compression.Uncompressed {
				dgstr := digest.SHA256.Digester()
				var compressed io.WriteCloser
				if config.Compressor != nil {
					compressed, errOpen = config.Compressor(cw, config.MediaType)
					if errOpen != nil {
						return fmt.Errorf("failed to get compressed stream: %w", errOpen)
					}
				} else {
					compressed, errOpen = compression.CompressStream(cw, compressionType)
					if errOpen != nil {
						return fmt.Errorf("failed to get compressed stream: %w", errOpen)
					}
				}
				errOpen = archive.WriteDiff(ctx, io.MultiWriter(compressed, dgstr.Hash()), lowerRoot, upperRoot, writeDiffOpts...)
				compressed.Close()
				if errOpen != nil {
					return fmt.Errorf("failed to write compressed diff: %w", errOpen)
				}

				if config.Labels == nil {
					config.Labels = map[string]string{}
				}
				config.Labels[labels.LabelUncompressed] = dgstr.Digest().String()
			} else {
				if errOpen = archive.WriteDiff(ctx, cw, lowerRoot, upperRoot, writeDiffOpts...); errOpen != nil {
					return fmt.Errorf("failed to write diff: %w", errOpen)
				}
			}

			var commitopts []content.Opt
			if config.Labels != nil {
				commitopts = append(commitopts, content.WithLabels(config.Labels))
			}

			dgst := cw.Digest()
			if errOpen = cw.Commit(ctx, 0, dgst, commitopts...); errOpen != nil {
				if !errdefs.IsAlreadyExists(errOpen) {
					return fmt.Errorf("failed to commit: %w", errOpen)
				}
				errOpen = nil
			}

			info, err := s.store.Info(ctx, dgst)
			if err != nil {
				return fmt.Errorf("failed to get info from content store: %w", err)
			}
			if info.Labels == nil {
				info.Labels = make(map[string]string)
			}
			// Set "containerd.io/uncompressed" label if digest already existed without label
			if _, ok := info.Labels[labels.LabelUncompressed]; !ok {
				info.Labels[labels.LabelUncompressed] = config.Labels[labels.LabelUncompressed]
				if _, err := s.store.Update(ctx, info, "labels."+labels.LabelUncompressed); err != nil {
					return fmt.Errorf("error setting uncompressed label: %w", err)
				}
			}

			ocidesc = ocispec.Descriptor{
				MediaType: config.MediaType,
				Size:      info.Size,
				Digest:    info.Digest,
			}
			return nil
		})
	}); err != nil {
		return emptyDesc, err
	}

	return ocidesc, nil
}

func (s *walkingDiff) withLowerMount(ctx context.Context, mounts []mount.Mount, f func(root string) error) error {
	return s.withResolvedMount(ctx, "walking-diff-lower", mounts, false, f)
}

func (s *walkingDiff) withUpperMount(ctx context.Context, mounts []mount.Mount, f func(root string) error) error {
	return s.withResolvedMount(ctx, "walking-diff-upper", mounts, true, f)
}

func (s *walkingDiff) withResolvedMount(ctx context.Context, prefix string, mounts []mount.Mount, readonly bool, f func(root string) error) error {
	if needsMountManager(mounts) {
		if s.mm == nil {
			return fmt.Errorf("mount manager is required to resolve formatted mounts: %w", errdefs.ErrNotImplemented)
		}
		name := prefix + "-" + uniqueRef()
		temporary := !needsNonTemporaryMountManager(mounts)
		// Clone the mounts slice to avoid modifying the caller's slice
		// during activation (template resolution modifies options in place).
		mountsCopy := slices.Clone(mounts)
		var info mount.ActivationInfo
		var err error
		if temporary {
			info, err = s.mm.Activate(ctx, name, mountsCopy, mount.WithTemporary)
		} else {
			info, err = s.mm.Activate(ctx, name, mountsCopy)
		}
		if err != nil {
			return err
		}
		defer func() {
			// Use a detached context for cleanup to ensure deactivation succeeds
			// even if the parent context is cancelled.
			cleanupCtx := context.WithoutCancel(ctx)
			if derr := s.mm.Deactivate(cleanupCtx, name); derr != nil {
				log.G(ctx).WithError(derr).Warnf("failed to deactivate mount %s", name)
			}
		}()
		// Shortcut: if the result is a single bind mount, use the source directly
		if len(info.System) == 1 && mountTypeSuffix(info.System[0].Type) == "bind" && info.System[0].Source != "" {
			return f(info.System[0].Source)
		}
		if readonly {
			return mount.WithReadonlyTempMount(ctx, info.System, f)
		}
		return mount.WithTempMount(ctx, info.System, f)
	}
	if readonly {
		return mount.WithReadonlyTempMount(ctx, mounts, f)
	}
	return mount.WithTempMount(ctx, mounts, f)
}

// needsMountManager returns true if any mount requires the mount manager to resolve.
// This includes mounts with template syntax (e.g., "{{ mount 0 }}"), formatted mounts
// (format/, mkfs/, mkdir/), or EROFS mounts that need multi-device resolution.
func needsMountManager(mounts []mount.Mount) bool {
	for _, m := range mounts {
		if hasTemplate(m) {
			return true
		}
		mt := mountTypeBase(m.Type)
		if mt == "format" || mt == "mkfs" || mt == "mkdir" {
			return true
		}
		if mountTypeSuffix(m.Type) == "erofs" {
			return true
		}
	}
	return false
}

// needsNonTemporaryMountManager returns true if mounts require non-temporary
// activation. Format, mkfs, and mkdir mounts may create persistent state that
// should not be cleaned up immediately.
func needsNonTemporaryMountManager(mounts []mount.Mount) bool {
	for _, m := range mounts {
		if strings.HasPrefix(m.Type, "format/") || strings.HasPrefix(m.Type, "mkfs/") || strings.HasPrefix(m.Type, "mkdir/") {
			return true
		}
	}
	return false
}

// hasTemplate returns true if the mount contains template syntax (e.g., "{{ mount 0 }}")
// in its source, target, or options. Such mounts require resolution by the mount manager.
func hasTemplate(m mount.Mount) bool {
	if strings.Contains(m.Source, "{{") || strings.Contains(m.Target, "{{") {
		return true
	}
	for _, opt := range m.Options {
		if strings.Contains(opt, "{{") {
			return true
		}
	}
	return false
}

// mountTypeBase returns the base component of a mount type.
// For "format/mkdir/overlay", it returns "format".
// For simple types like "bind", it returns "bind".
func mountTypeBase(t string) string {
	if t == "" {
		return ""
	}
	parts := strings.Split(t, "/")
	if len(parts) == 1 {
		return t
	}
	return parts[0]
}

// mountTypeSuffix returns the final component of a mount type.
// For "format/mkdir/overlay", it returns "overlay".
// For simple types like "bind", it returns "bind".
func mountTypeSuffix(t string) string {
	if t == "" {
		return ""
	}
	parts := strings.Split(t, "/")
	return parts[len(parts)-1]
}

func uniqueRef() string {
	t := time.Now()
	var b [3]byte
	// Ignore read failures, just decreases uniqueness
	rand.Read(b[:])
	return fmt.Sprintf("%d-%s", t.UnixNano(), base64.URLEncoding.EncodeToString(b[:]))
}
