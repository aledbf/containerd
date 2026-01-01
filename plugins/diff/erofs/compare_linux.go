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

package erofs

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/containerd/continuity/fs"
	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/diff"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/internal/erofsutils"
	"github.com/containerd/containerd/v2/pkg/archive"
	"github.com/containerd/containerd/v2/pkg/archive/compression"
	"github.com/containerd/containerd/v2/pkg/epoch"
	"github.com/containerd/containerd/v2/pkg/labels"
)

// diffWriteFunc is a function that writes diff content to the provided writer.
type diffWriteFunc func(ctx context.Context, w io.Writer) error

func writeDiff(ctx context.Context, w io.Writer, lower []mount.Mount, upperRoot string, mm mount.Manager) error {
	var opts []archive.ChangeWriterOpt

	return withLowerMount(ctx, lower, mm, func(lowerRoot string) error {
		cw := archive.NewChangeWriter(w, upperRoot, opts...)
		err := fs.DiffDirChanges(ctx, lowerRoot, upperRoot, fs.DiffSourceOverlayFS, cw.HandleChange)
		if err != nil {
			return fmt.Errorf("failed to create diff tar stream: %w", err)
		}
		return cw.Close()
	})
}

func writeDiffFromMounts(ctx context.Context, w io.Writer, lower, upper []mount.Mount, mm mount.Manager) error {
	return withLowerMount(ctx, lower, mm, func(lowerRoot string) error {
		return withUpperMount(ctx, upper, mm, func(upperRoot string) error {
			if err := archive.WriteDiff(ctx, w, lowerRoot, upperRoot); err != nil {
				return fmt.Errorf("failed to write diff: %w", err)
			}
			return nil
		})
	})
}

// Compare creates a diff between the given mounts and uploads the result
// to the content store.
func (s erofsDiff) Compare(ctx context.Context, lower, upper []mount.Mount, opts ...diff.Opt) (d ocispec.Descriptor, err error) {
	var config diff.Config
	for _, opt := range opts {
		if err := opt(&config); err != nil {
			return emptyDesc, err
		}
	}
	if tm := epoch.FromContext(ctx); tm != nil && config.SourceDateEpoch == nil {
		config.SourceDateEpoch = tm
	}

	if config.MediaType == "" {
		config.MediaType = ocispec.MediaTypeImageLayerGzip
	}

	// Check if mount manager path is needed before trying to resolve the layer.
	// Formatted mounts (format/, mkfs/, mkdir/), templates, and EROFS mounts
	// require the mount manager to resolve them.
	if needsWalkingDiff(upper) || needsMountManager(lower) || needsMountManager(upper) {
		return s.writeAndCommitDiff(ctx, config, func(ctx context.Context, w io.Writer) error {
			return writeDiffFromMounts(ctx, w, lower, upper, s.mm)
		})
	}

	// For direct overlay diff, resolve the layer path from mounts.
	layer, err := erofsutils.MountsToLayer(upper)
	if err != nil {
		return emptyDesc, fmt.Errorf("unsupported layer for erofsDiff Compare method: %w", err)
	}

	upperRoot := filepath.Join(layer, "fs")
	return s.writeAndCommitDiff(ctx, config, func(ctx context.Context, w io.Writer) error {
		return writeDiff(ctx, w, lower, upperRoot, s.mm)
	})
}

// writeAndCommitDiff handles the common logic for writing a diff to the content store.
// It manages compression, content writer lifecycle, and label updates.
func (s erofsDiff) writeAndCommitDiff(ctx context.Context, config diff.Config, writeFn diffWriteFunc) (ocispec.Descriptor, error) {
	var compressionType compression.Compression
	switch config.MediaType {
	case ocispec.MediaTypeImageLayer:
		compressionType = compression.Uncompressed
	case ocispec.MediaTypeImageLayerGzip:
		compressionType = compression.Gzip
	case ocispec.MediaTypeImageLayerZstd:
		compressionType = compression.Zstd
	default:
		return emptyDesc, fmt.Errorf("unsupported diff media type: %v: %w", config.MediaType, errdefs.ErrNotImplemented)
	}

	var newReference bool
	if config.Reference == "" {
		newReference = true
		config.Reference = uniqueRef()
	}

	cw, err := s.store.Writer(ctx,
		content.WithRef(config.Reference),
		content.WithDescriptor(ocispec.Descriptor{
			MediaType: config.MediaType,
		}))
	if err != nil {
		return emptyDesc, fmt.Errorf("failed to open writer: %w", err)
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
			return emptyDesc, errOpen
		}
	}

	if compressionType != compression.Uncompressed {
		dgstr := digest.SHA256.Digester()
		var compressed io.WriteCloser
		if config.Compressor != nil {
			compressed, errOpen = config.Compressor(cw, config.MediaType)
			if errOpen != nil {
				return emptyDesc, fmt.Errorf("failed to get compressed stream: %w", errOpen)
			}
		} else {
			compressed, errOpen = compression.CompressStream(cw, compressionType)
			if errOpen != nil {
				return emptyDesc, fmt.Errorf("failed to get compressed stream: %w", errOpen)
			}
		}
		errOpen = writeFn(ctx, io.MultiWriter(compressed, dgstr.Hash()))
		compressed.Close()
		if errOpen != nil {
			return emptyDesc, fmt.Errorf("failed to write compressed diff: %w", errOpen)
		}

		if config.Labels == nil {
			config.Labels = map[string]string{}
		}
		config.Labels[labels.LabelUncompressed] = dgstr.Digest().String()
	} else {
		if errOpen = writeFn(ctx, cw); errOpen != nil {
			return emptyDesc, fmt.Errorf("failed to write diff: %w", errOpen)
		}
	}

	var commitopts []content.Opt
	if config.Labels != nil {
		commitopts = append(commitopts, content.WithLabels(config.Labels))
	}

	dgst := cw.Digest()
	if errOpen = cw.Commit(ctx, 0, dgst, commitopts...); errOpen != nil {
		if !errdefs.IsAlreadyExists(errOpen) {
			return emptyDesc, fmt.Errorf("failed to commit: %w", errOpen)
		}
		errOpen = nil
	}

	info, err := s.store.Info(ctx, dgst)
	if err != nil {
		return emptyDesc, fmt.Errorf("failed to get info from content store: %w", err)
	}
	if info.Labels == nil {
		info.Labels = make(map[string]string)
	}
	// Set "containerd.io/uncompressed" label if digest already existed without label
	if _, ok := info.Labels[labels.LabelUncompressed]; !ok {
		info.Labels[labels.LabelUncompressed] = config.Labels[labels.LabelUncompressed]
		if _, err := s.store.Update(ctx, info, "labels."+labels.LabelUncompressed); err != nil {
			return emptyDesc, fmt.Errorf("error setting uncompressed label: %w", err)
		}
	}

	return ocispec.Descriptor{
		MediaType: config.MediaType,
		Size:      info.Size,
		Digest:    info.Digest,
	}, nil
}

// withLowerMount resolves lower mounts and calls f with the resulting root path.
// If mounts require the mount manager (formatted mounts, templates, or EROFS),
// it activates them through the mount manager first.
func withLowerMount(ctx context.Context, lower []mount.Mount, mm mount.Manager, f func(root string) error) error {
	if needsMountManager(lower) {
		if mm == nil {
			return fmt.Errorf("mount manager is required to resolve formatted mounts: %w", errdefs.ErrNotImplemented)
		}
		name := "erofs-diff-lower-" + uniqueRef()
		temporary := !needsNonTemporaryMountManager(lower)
		var info mount.ActivationInfo
		var err error
		// Clone the mounts slice to avoid modifying the caller's slice
		// during activation (template resolution modifies options in place).
		lowerCopy := slices.Clone(lower)
		if temporary {
			info, err = mm.Activate(ctx, name, lowerCopy, mount.WithTemporary)
		} else {
			info, err = mm.Activate(ctx, name, lowerCopy)
		}
		if err != nil {
			return err
		}
		defer func() {
			if derr := mm.Deactivate(ctx, name); derr != nil {
				log.G(ctx).WithError(derr).Warnf("failed to deactivate lower mount %s", name)
			}
		}()
		// Shortcut: if the result is a single bind mount, use the source directly
		if len(info.System) == 1 && mountTypeSuffix(info.System[0].Type) == "bind" && info.System[0].Source != "" {
			return f(info.System[0].Source)
		}
		// Shortcut: if we have a merged EROFS and a lower-only overlay, use the EROFS mount point
		if root, ok := mergedLowerFromActive(info.Active); ok && lowerOverlayOnly(info.System) {
			return f(root)
		}
		return mount.WithTempMount(ctx, info.System, f)
	}
	return mount.WithTempMount(ctx, lower, f)
}

// withUpperMount resolves upper mounts and calls f with the resulting root path.
// If mounts require the mount manager (formatted mounts, templates, or EROFS),
// it activates them through the mount manager first.
func withUpperMount(ctx context.Context, upper []mount.Mount, mm mount.Manager, f func(root string) error) error {
	if needsMountManager(upper) {
		if mm == nil {
			return fmt.Errorf("mount manager is required to resolve formatted mounts: %w", errdefs.ErrNotImplemented)
		}
		name := "erofs-diff-upper-" + uniqueRef()
		temporary := !needsNonTemporaryMountManager(upper)
		// Clone the mounts slice to avoid modifying the caller's slice
		// during activation (template resolution modifies options in place).
		upperCopy := slices.Clone(upper)
		var info mount.ActivationInfo
		var err error
		if temporary {
			info, err = mm.Activate(ctx, name, upperCopy, mount.WithTemporary)
		} else {
			info, err = mm.Activate(ctx, name, upperCopy)
		}
		if err != nil {
			return err
		}
		defer func() {
			if derr := mm.Deactivate(ctx, name); derr != nil {
				log.G(ctx).WithError(derr).Warnf("failed to deactivate upper mount %s", name)
			}
		}()
		// Shortcut: if the result is a single bind mount, use the source directly
		if len(info.System) == 1 && mountTypeSuffix(info.System[0].Type) == "bind" && info.System[0].Source != "" {
			return f(info.System[0].Source)
		}
		return mount.WithReadonlyTempMount(ctx, info.System, f)
	}
	return mount.WithReadonlyTempMount(ctx, upper, f)
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

// needsWalkingDiff returns true if the mounts require a walking diff instead of
// the optimized overlayfs diff. This is needed for mkfs/* mounts where the
// filesystem content is generated at mount time.
func needsWalkingDiff(mounts []mount.Mount) bool {
	for _, m := range mounts {
		if strings.HasPrefix(m.Type, "mkfs/") {
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

// lowerOverlayOnly returns true if the mounts represent an overlay with only
// lower directories (no upperdir). This indicates a read-only overlay that
// can be accessed directly through its lower mount point.
func lowerOverlayOnly(mounts []mount.Mount) bool {
	if len(mounts) != 1 {
		return false
	}
	if mountTypeSuffix(mounts[0].Type) != "overlay" {
		return false
	}
	hasLower := false
	for _, opt := range mounts[0].Options {
		if strings.HasPrefix(opt, "upperdir=") {
			return false
		}
		if strings.HasPrefix(opt, "lowerdir=") {
			hasLower = true
		}
	}
	return hasLower
}

// mergedLowerFromActive finds the mount point of a merged EROFS filesystem
// from the list of active mounts. It searches backwards since the merged
// fsmeta mount is typically the last EROFS mount in the activation chain.
// Returns the mount point if an fsmeta.erofs source or a multi-device EROFS
// mount (with device= option) is found.
func mergedLowerFromActive(active []mount.ActiveMount) (string, bool) {
	for i := len(active) - 1; i >= 0; i-- {
		if mountTypeSuffix(active[i].Type) != "erofs" {
			continue
		}
		if strings.HasSuffix(active[i].Source, "fsmeta.erofs") {
			return active[i].MountPoint, true
		}
		for _, opt := range active[i].Options {
			if strings.HasPrefix(opt, "device=") {
				return active[i].MountPoint, true
			}
		}
	}
	return "", false
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
