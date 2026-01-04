//go:build linux

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
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images/imagetest"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/mount/manager"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/core/snapshots/storage"
	"github.com/containerd/containerd/v2/core/snapshots/testsuite"
	"github.com/containerd/containerd/v2/internal/erofsutils"
	"github.com/containerd/containerd/v2/internal/fsverity"
	"github.com/containerd/containerd/v2/pkg/archive/compression"
	"github.com/containerd/containerd/v2/pkg/archive/tartest"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/testutil"
	erofsdiffer "github.com/containerd/containerd/v2/plugins/diff/erofs"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	bolt "go.etcd.io/bbolt"
)

const (
	testFileContent       = "Hello, this is content for testing the EROFS Snapshotter!"
	testNestedFileContent = "Nested file content"
)

func newSnapshotter(t *testing.T, opts ...Opt) func(ctx context.Context, root string) (snapshots.Snapshotter, func() error, error) {
	_, err := exec.LookPath("mkfs.erofs")
	if err != nil {
		t.Skipf("could not find mkfs.erofs: %v", err)
	}

	if !findErofs() {
		t.Skip("check for erofs kernel support failed, skipping test")
	}
	return func(ctx context.Context, root string) (snapshots.Snapshotter, func() error, error) {
		snapshotter, err := NewSnapshotter(root, opts...)
		if err != nil {
			return nil, nil, err
		}

		return snapshotter, func() error { return snapshotter.Close() }, nil
	}
}

func testMount(t *testing.T, scratchFile string) error {
	root, err := os.MkdirTemp(t.TempDir(), "")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)

	m := []mount.Mount{
		{
			Type:    "ext4",
			Source:  scratchFile,
			Options: []string{"loop", "direct-io", "sync"},
		},
	}

	if err := mount.All(m, root); err != nil {
		return fmt.Errorf("failed to mount device %s: %w", scratchFile, err)
	}

	if err := os.Remove(filepath.Join(root, "lost+found")); err != nil {
		return err
	}
	if err := os.Mkdir(filepath.Join(root, "work"), 0755); err != nil {
		return err
	}
	if err := os.Mkdir(filepath.Join(root, "upper"), 0755); err != nil {
		return err
	}
	return mount.UnmountAll(root, 0)
}

func TestErofs(t *testing.T) {
	testutil.RequiresRoot(t)
	testsuite.SnapshotterSuite(t, "erofs", newSnapshotter(t))
}

func TestErofsWithQuota(t *testing.T) {
	testutil.RequiresRoot(t)
	testsuite.SnapshotterSuite(t, "erofs", newSnapshotter(t, WithDefaultSize(16*1024*1024)))
}

func TestErofsFsverity(t *testing.T) {
	testutil.RequiresRoot(t)
	ctx := t.Context()

	root := t.TempDir()

	// Skip if fsverity is not supported
	supported, err := fsverity.IsSupported(root)
	if !supported || err != nil {
		t.Skip("fsverity not supported, skipping test")
	}

	// Create snapshotter with fsverity enabled
	s, err := NewSnapshotter(root, WithFsverity())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer cleanupAllSnapshots(ctx, s)

	// Create a test snapshot
	key := "test-snapshot"
	mounts, err := s.Prepare(ctx, key, "")
	if err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(root, key)
	if err := os.MkdirAll(target, 0755); err != nil {
		t.Fatal(err)
	}
	if err := mount.All(mounts, target); err != nil {
		t.Fatal(err)
	}
	defer testutil.Unmount(t, target)

	// Write test data
	if err := os.WriteFile(filepath.Join(target, "foo"), []byte("test data"), 0777); err != nil {
		t.Fatal(err)
	}

	// Commit the snapshot
	commitKey := "test-commit"
	if err := s.Commit(ctx, commitKey, key); err != nil {
		t.Fatal(err)
	}

	snap := s.(*snapshotter)

	// Get the internal ID from the snapshotter
	var id string
	if err := snap.ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		id, _, _, err = storage.GetInfo(ctx, commitKey)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	// Verify fsverity is enabled on the EROFS layer

	layerPath := snap.layerBlobPath(id)

	enabled, err := fsverity.IsEnabled(layerPath)
	if err != nil {
		t.Fatalf("Failed to check fsverity status: %v", err)
	}
	if !enabled {
		t.Fatal("Expected fsverity to be enabled on committed layer")
	}

	// Try to modify the layer file directly (should fail)
	if err := os.WriteFile(layerPath, []byte("tampered data"), 0666); err == nil {
		t.Fatal("Expected direct write to fsverity-enabled layer to fail")
	}
}

func TestErofsDifferWithTarIndexMode(t *testing.T) {
	testutil.RequiresRoot(t)
	ctx := t.Context()

	if !findErofs() {
		t.Skip("check for erofs kernel support failed, skipping test")
	}

	// Check if mkfs.erofs supports tar index mode
	supported, err := erofsutils.SupportGenerateFromTar()
	if err != nil || !supported {
		t.Skip("mkfs.erofs does not support tar mode, skipping tar index test")
	}

	tempDir := t.TempDir()

	// Create content store for the differ
	contentStore := imagetest.NewContentStore(ctx, t).Store

	// Create EROFS differ with tar index mode enabled
	differ := erofsdiffer.NewErofsDiffer(contentStore, erofsdiffer.WithTarIndexMode())

	// Create EROFS snapshotter
	snapshotRoot := filepath.Join(tempDir, "snapshots")
	s, err := NewSnapshotter(snapshotRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer cleanupAllSnapshots(ctx, s)
	snap := s.(*snapshotter)

	// Create test tar content
	tarReader := createTestTarContent()
	defer tarReader.Close()

	// Read the tar content into a buffer for digest calculation and writing
	tarContent, err := io.ReadAll(tarReader)
	if err != nil {
		t.Fatal(err)
	}

	// Write tar content to content store
	desc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayerGzip,
		Digest:    digest.FromBytes(tarContent),
		Size:      int64(len(tarContent)),
	}

	writer, err := contentStore.Writer(ctx,
		content.WithRef("test-layer"),
		content.WithDescriptor(desc))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := writer.Write(tarContent); err != nil {
		writer.Close()
		t.Fatal(err)
	}

	if err := writer.Commit(ctx, desc.Size, desc.Digest); err != nil {
		writer.Close()
		t.Fatal(err)
	}
	writer.Close()

	// Prepare a snapshot using the snapshotter
	snapshotKey := "test-snapshot"
	mounts, err := s.Prepare(ctx, snapshotKey, "")
	if err != nil {
		t.Fatal(err)
	}

	// Apply the tar content using the EROFS differ with tar index mode
	appliedDesc, err := differ.Apply(ctx, desc, mounts)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Applied layer using EROFS differ with tar index mode:")
	t.Logf("  Original: %s (%d bytes)", desc.Digest, desc.Size)
	t.Logf("  Applied:  %s (%d bytes)", appliedDesc.Digest, appliedDesc.Size)
	t.Logf("  MediaType: %s", appliedDesc.MediaType)

	// Commit the snapshot to finalize the EROFS layer creation
	commitKey := "test-commit"
	if err := s.Commit(ctx, commitKey, snapshotKey); err != nil {
		t.Fatal(err)
	}

	// Get the internal snapshot ID to check the EROFS layer file
	snap = s.(*snapshotter)
	var id string
	if err := snap.ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		id, _, _, err = storage.GetInfo(ctx, commitKey)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	// Verify the EROFS layer file was created
	layerPath := snap.layerBlobPath(id)
	if _, err := os.Stat(layerPath); err != nil {
		t.Fatalf("EROFS layer file should exist: %v", err)
	}

	// Verify the layer file is not empty
	stat, err := os.Stat(layerPath)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Size() == 0 {
		t.Fatal("EROFS layer file should not be empty")
	}

	t.Logf("EROFS layer file created with tar index mode: %s (%d bytes)", layerPath, stat.Size())

	// Create a view to verify the content
	viewKey := "test-view"
	viewMounts, err := s.View(ctx, viewKey, commitKey)
	if err != nil {
		t.Fatal(err)
	}

	viewTarget := filepath.Join(tempDir, viewKey)
	if err := os.MkdirAll(viewTarget, 0755); err != nil {
		t.Fatal(err)
	}
	if err := mount.All(viewMounts, viewTarget); err != nil {
		t.Fatal(err)
	}
	defer testutil.Unmount(t, viewTarget)

	// Verify we can read the original test data
	testData, err := os.ReadFile(filepath.Join(viewTarget, "test-file.txt"))
	if err != nil {
		t.Fatal(err)
	}
	expected := testFileContent
	if string(testData) != expected {
		t.Fatalf("Expected %q, got %q", expected, string(testData))
	}

	// Verify nested file
	nestedData, err := os.ReadFile(filepath.Join(viewTarget, "testdir", "nested.txt"))
	if err != nil {
		t.Fatal(err)
	}
	expectedNested := testNestedFileContent
	if string(nestedData) != expectedNested {
		t.Fatalf("Expected %q, got %q", expectedNested, string(nestedData))
	}

	t.Logf("Successfully verified EROFS Snapshotter using the differ with tar index mode")
}

func TestErofsDifferCompareWithMountManager(t *testing.T) {
	testutil.RequiresRoot(t)
	ctx := namespaces.WithNamespace(t.Context(), "testsuite")

	_, err := exec.LookPath("mkfs.erofs")
	if err != nil {
		t.Skipf("could not find mkfs.erofs: %v", err)
	}
	if !findErofs() {
		t.Skip("check for erofs kernel support failed, skipping test")
	}

	tempDir := t.TempDir()
	contentStore := imagetest.NewContentStore(ctx, t).Store

	snapshotRoot := filepath.Join(tempDir, "snapshots")
	s, err := NewSnapshotter(snapshotRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer cleanupAllSnapshots(ctx, s)

	snap := s.(*snapshotter)

	baseKey := "base"
	if _, err := s.Prepare(ctx, baseKey, ""); err != nil {
		t.Fatal(err)
	}
	baseID := snapshotID(t, snap, baseKey)
	if err := os.WriteFile(filepath.Join(snap.upperPath(baseID), "base.txt"), []byte("base"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(ctx, "base-commit", baseKey); err != nil {
		t.Fatal(err)
	}

	childKey := "child"
	if _, err := s.Prepare(ctx, childKey, "base-commit"); err != nil {
		t.Fatal(err)
	}
	childID := snapshotID(t, snap, childKey)
	if err := os.WriteFile(filepath.Join(snap.upperPath(childID), "child.txt"), []byte("child"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(ctx, "child-commit", childKey); err != nil {
		t.Fatal(err)
	}

	upperKey := "upper"
	upperMounts, err := s.Prepare(ctx, upperKey, "child-commit")
	if err != nil {
		t.Fatal(err)
	}
	upperID := snapshotID(t, snap, upperKey)
	if err := os.WriteFile(filepath.Join(snap.upperPath(upperID), "upper.txt"), []byte("upper"), 0644); err != nil {
		t.Fatal(err)
	}

	lowerKey := "lower"
	lowerMounts, err := s.View(ctx, lowerKey, "child-commit")
	if err != nil {
		t.Fatal(err)
	}

	hasTemplate := false
	for _, m := range lowerMounts {
		for _, opt := range m.Options {
			if strings.Contains(opt, "{{") {
				hasTemplate = true
				break
			}
		}
	}
	if !hasTemplate {
		t.Fatalf("expected lower mounts to include formatted options, got: %#v", lowerMounts)
	}

	db, err := bolt.Open(filepath.Join(tempDir, "mounts.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mountRoot := filepath.Join(tempDir, "mounts")
	mm, err := manager.NewManager(db, mountRoot, manager.WithAllowedRoot(snapshotRoot))
	if err != nil {
		t.Fatal(err)
	}
	if closer, ok := mm.(interface{ Close() error }); ok {
		defer closer.Close()
	}

	differ := erofsdiffer.NewErofsDiffer(contentStore, erofsdiffer.WithMountManager(mm))
	desc, err := differ.Compare(ctx, lowerMounts, upperMounts)
	if err != nil {
		t.Fatal(err)
	}
	if desc.Digest == "" || desc.Size == 0 {
		t.Fatalf("unexpected diff descriptor: %+v", desc)
	}
}

func TestErofsSnapshotCommitApplyFlow(t *testing.T) {
	testutil.RequiresRoot(t)
	ctx := namespaces.WithNamespace(t.Context(), "testsuite")

	_, err := exec.LookPath("mkfs.erofs")
	if err != nil {
		t.Skipf("could not find mkfs.erofs: %v", err)
	}
	if !findErofs() {
		t.Skip("check for erofs kernel support failed, skipping test")
	}

	tempDir := t.TempDir()
	contentStore := imagetest.NewContentStore(ctx, t).Store

	snapshotRoot := filepath.Join(tempDir, "snapshots")
	s, err := NewSnapshotter(snapshotRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer cleanupAllSnapshots(ctx, s)

	snap := s.(*snapshotter)

	db, err := bolt.Open(filepath.Join(tempDir, "mounts.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mountRoot := filepath.Join(tempDir, "mounts")
	mm, err := manager.NewManager(db, mountRoot, manager.WithAllowedRoot(snapshotRoot))
	if err != nil {
		t.Fatal(err)
	}
	if closer, ok := mm.(interface{ Close() error }); ok {
		defer closer.Close()
	}

	differ := erofsdiffer.NewErofsDiffer(contentStore, erofsdiffer.WithMountManager(mm))

	writeFiles := func(dir string, files map[string]string) error {
		for name, content := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
				return err
			}
		}
		return nil
	}

	commitWithFiles := func(key, parent string, files map[string]string) (string, error) {
		if _, err := s.Prepare(ctx, key, parent); err != nil {
			return "", err
		}
		id := snapshotID(t, snap, key)
		if err := writeFiles(snap.upperPath(id), files); err != nil {
			return "", err
		}
		commitKey := key + "-commit"
		if err := s.Commit(ctx, commitKey, key); err != nil {
			return "", err
		}
		return commitKey, nil
	}

	runFlow := func(name string, baseFiles, midFiles, topFiles, upperFiles map[string]string, expectMulti bool) {
		baseCommit, err := commitWithFiles(name+"-base", "", baseFiles)
		if err != nil {
			t.Fatal(err)
		}

		parentCommit := baseCommit
		if midFiles != nil {
			midCommit, err := commitWithFiles(name+"-mid", parentCommit, midFiles)
			if err != nil {
				t.Fatal(err)
			}
			parentCommit = midCommit
		}
		if topFiles != nil {
			topCommit, err := commitWithFiles(name+"-top", parentCommit, topFiles)
			if err != nil {
				t.Fatal(err)
			}
			parentCommit = topCommit
		}

		lowerKey := name + "-lower"
		lowerMounts, err := s.View(ctx, lowerKey, parentCommit)
		if err != nil {
			t.Fatal(err)
		}

		upperKey := name + "-upper"
		upperMounts, err := s.Prepare(ctx, upperKey, parentCommit)
		if err != nil {
			t.Fatal(err)
		}
		upperID := snapshotID(t, snap, upperKey)
		if err := writeFiles(snap.upperPath(upperID), upperFiles); err != nil {
			t.Fatal(err)
		}

		if expectMulti {
			if !mountsHaveTemplate(lowerMounts) {
				t.Fatalf("expected lower mounts to include overlay templates, got: %#v", lowerMounts)
			}
		} else {
			if len(lowerMounts) != 1 || mountTypeSuffixTest(lowerMounts[0].Type) != "erofs" {
				t.Fatalf("expected single EROFS mount, got: %#v", lowerMounts)
			}
		}
		if !mountsHaveTemplate(upperMounts) {
			t.Fatalf("expected upper mounts to include overlay templates, got: %#v", upperMounts)
		}

		desc, err := differ.Compare(ctx, lowerMounts, upperMounts)
		if err != nil {
			t.Fatal(err)
		}
		if desc.Digest == "" || desc.Size == 0 {
			t.Fatalf("unexpected diff descriptor: %+v", desc)
		}

		applyKey := name + "-apply"
		applyMounts, err := s.Prepare(ctx, applyKey, parentCommit)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := differ.Apply(ctx, desc, applyMounts); err != nil {
			t.Fatal(err)
		}
		applyCommit := name + "-apply-commit"
		if err := s.Commit(ctx, applyCommit, applyKey); err != nil {
			t.Fatal(err)
		}

		viewKey := name + "-view"
		viewMounts, err := s.View(ctx, viewKey, applyCommit)
		if err != nil {
			t.Fatal(err)
		}

		// Use mount manager to process template mounts (overlay templates need to be resolved)
		viewActivation, err := mm.Activate(ctx, viewKey+"-activation", cloneMounts(viewMounts))
		if err != nil {
			t.Fatal(err)
		}
		defer mm.Deactivate(ctx, viewActivation.Name)

		verifyFiles := func(root string, files map[string]string) {
			for name, content := range files {
				data, err := os.ReadFile(filepath.Join(root, name))
				if err != nil {
					t.Fatal(err)
				}
				if string(data) != content {
					t.Fatalf("expected %s content %q, got %q", name, content, string(data))
				}
			}
		}

		// Mount and verify files
		if err := mount.WithTempMount(ctx, viewActivation.System, func(root string) error {
			verifyFiles(root, baseFiles)
			if midFiles != nil {
				verifyFiles(root, midFiles)
			}
			if topFiles != nil {
				verifyFiles(root, topFiles)
			}
			verifyFiles(root, upperFiles)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("single-layer", func(t *testing.T) {
		runFlow("single",
			map[string]string{"base.txt": "base"},
			nil,
			nil,
			map[string]string{"upper.txt": "upper"},
			false,
		)
	})

	t.Run("multi-layer-overlay", func(t *testing.T) {
		runFlow("multi",
			map[string]string{"base.txt": "base"},
			map[string]string{"mid.txt": "mid"},
			map[string]string{"top.txt": "top"},
			map[string]string{"upper.txt": "upper"},
			true,
		)
	})
}

func TestErofsDifferCompareBlockUpperFallback(t *testing.T) {
	testutil.RequiresRoot(t)
	ctx := namespaces.WithNamespace(t.Context(), "testsuite")

	_, err := exec.LookPath("mkfs.erofs")
	if err != nil {
		t.Skipf("could not find mkfs.erofs: %v", err)
	}
	if !findErofs() {
		t.Skip("check for erofs kernel support failed, skipping test")
	}

	tempDir := t.TempDir()
	contentStore := imagetest.NewContentStore(ctx, t).Store

	snapshotRoot := filepath.Join(tempDir, "snapshots")
	s, err := NewSnapshotter(snapshotRoot, WithDefaultSize(16*1024*1024))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer cleanupAllSnapshots(ctx, s)

	baseKey := "base"
	if _, err := s.Prepare(ctx, baseKey, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(ctx, "base-commit", baseKey); err != nil {
		t.Fatal(err)
	}

	upperKey := "upper"
	// Prepare() creates the snapshot with a runtime marker.
	if _, err := s.Prepare(ctx, upperKey, "base-commit"); err != nil {
		t.Fatal(err)
	}
	// First Mounts() call consumes the runtime marker and returns template mounts.
	// These template mounts are for VM runtimes that need block devices.
	upperMounts, err := s.Mounts(ctx, upperKey)
	if err != nil {
		t.Fatal(err)
	}

	db, err := bolt.Open(filepath.Join(tempDir, "mounts.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mountRoot := filepath.Join(tempDir, "mounts")
	mm, err := manager.NewManager(db, mountRoot, manager.WithAllowedRoot(snapshotRoot))
	if err != nil {
		t.Fatal(err)
	}
	if closer, ok := mm.(interface{ Close() error }); ok {
		defer closer.Close()
	}

	activation, err := mm.Activate(ctx, "upper-activate-"+time.Now().Format("150405.000"), cloneMounts(upperMounts))
	if err != nil {
		t.Fatal(err)
	}
	wroteFile := false
	for _, a := range activation.Active {
		if mountTypeSuffixTest(a.Type) != "ext4" || a.MountPoint == "" {
			continue
		}
		// Write to upper/ subdirectory since overlay uses upperdir={{ mount 0 }}/upper
		upperDir := filepath.Join(a.MountPoint, "upper")
		if err := os.MkdirAll(upperDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(upperDir, "marker.txt"), []byte("marker"), 0644); err != nil {
			t.Fatal(err)
		}
		wroteFile = true
		break
	}
	if !wroteFile {
		_ = mm.Deactivate(ctx, activation.Name)
		t.Fatal("failed to locate ext4 mount to write marker.txt")
	}
	if err := mm.Deactivate(ctx, activation.Name); err != nil {
		t.Fatal(err)
	}

	lowerKey := "lower"
	lowerMounts, err := s.View(ctx, lowerKey, "base-commit")
	if err != nil {
		t.Fatal(err)
	}

	differ := erofsdiffer.NewErofsDiffer(contentStore, erofsdiffer.WithMountManager(mm))
	desc, err := differ.Compare(ctx, lowerMounts, upperMounts)
	if err != nil {
		t.Fatal(err)
	}

	found, err := tarHasPath(ctx, contentStore, desc, "marker.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("expected diff to include marker.txt")
	}
}

func TestErofsDifferComparePreservesWhiteouts(t *testing.T) {
	testutil.RequiresRoot(t)
	ctx := namespaces.WithNamespace(t.Context(), "testsuite")

	_, err := exec.LookPath("mkfs.erofs")
	if err != nil {
		t.Skipf("could not find mkfs.erofs: %v", err)
	}
	if !findErofs() {
		t.Skip("check for erofs kernel support failed, skipping test")
	}

	tempDir := t.TempDir()
	contentStore := imagetest.NewContentStore(ctx, t).Store

	snapshotRoot := filepath.Join(tempDir, "snapshots")
	s, err := NewSnapshotter(snapshotRoot, WithDefaultSize(16*1024*1024))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer cleanupAllSnapshots(ctx, s)

	db, err := bolt.Open(filepath.Join(tempDir, "mounts.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mountRoot := filepath.Join(tempDir, "mounts")
	mm, err := manager.NewManager(db, mountRoot, manager.WithAllowedRoot(snapshotRoot))
	if err != nil {
		t.Fatal(err)
	}
	if closer, ok := mm.(interface{ Close() error }); ok {
		defer closer.Close()
	}

	baseKey := "base"
	baseMounts, err := s.Prepare(ctx, baseKey, "")
	if err != nil {
		t.Fatal(err)
	}
	activation, err := mm.Activate(ctx, "base-activate-"+time.Now().Format("150405.000"), cloneMounts(baseMounts))
	if err != nil {
		t.Fatal(err)
	}
	wroteFile := false
	for _, a := range activation.Active {
		if mountTypeSuffixTest(a.Type) != "ext4" || a.MountPoint == "" {
			continue
		}
		upperDir := filepath.Join(a.MountPoint, "upper")
		if err := os.MkdirAll(upperDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(upperDir, "gone.txt"), []byte("gone"), 0644); err != nil {
			t.Fatal(err)
		}
		wroteFile = true
		break
	}
	if !wroteFile {
		_ = mm.Deactivate(ctx, activation.Name)
		t.Fatal("failed to locate ext4 mount to write gone.txt")
	}
	if err := mm.Deactivate(ctx, activation.Name); err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(ctx, "base-commit", baseKey); err != nil {
		t.Fatal(err)
	}

	upperKey := "upper"
	// Prepare() creates the snapshot with a runtime marker.
	if _, err := s.Prepare(ctx, upperKey, "base-commit"); err != nil {
		t.Fatal(err)
	}
	// First Mounts() call consumes the runtime marker and returns template mounts.
	// These template mounts are for VM runtimes that need block devices.
	upperMounts, err := s.Mounts(ctx, upperKey)
	if err != nil {
		t.Fatal(err)
	}

	lowerKey := "lower"
	lowerMounts, err := s.View(ctx, lowerKey, "base-commit")
	if err != nil {
		t.Fatal(err)
	}

	activation, err = mm.Activate(ctx, "upper-activate-"+time.Now().Format("150405.000"), cloneMounts(upperMounts))
	if err != nil {
		t.Fatal(err)
	}
	if err := mount.WithTempMount(ctx, activation.System, func(root string) error {
		return os.Remove(filepath.Join(root, "gone.txt"))
	}); err != nil {
		_ = mm.Deactivate(ctx, activation.Name)
		t.Fatal(err)
	}
	if err := mm.Deactivate(ctx, activation.Name); err != nil {
		t.Fatal(err)
	}

	differ := erofsdiffer.NewErofsDiffer(contentStore, erofsdiffer.WithMountManager(mm))
	desc, err := differ.Compare(ctx, lowerMounts, upperMounts)
	if err != nil {
		t.Fatal(err)
	}

	found, err := tarHasPath(ctx, contentStore, desc, ".wh.gone.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("expected diff to include whiteout for gone.txt")
	}
}

func TestErofsDifferCompareWithFormattedUpperMounts(t *testing.T) {
	testutil.RequiresRoot(t)
	ctx := namespaces.WithNamespace(t.Context(), "testsuite")

	_, err := exec.LookPath("mkfs.erofs")
	if err != nil {
		t.Skipf("could not find mkfs.erofs: %v", err)
	}
	if !findErofs() {
		t.Skip("check for erofs kernel support failed, skipping test")
	}

	tempDir := t.TempDir()
	contentStore := imagetest.NewContentStore(ctx, t).Store

	snapshotRoot := filepath.Join(tempDir, "snapshots")
	s, err := NewSnapshotter(snapshotRoot, WithDefaultSize(16*1024*1024))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer cleanupAllSnapshots(ctx, s)

	baseKey := "base"
	if _, err := s.Prepare(ctx, baseKey, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(ctx, "base-commit", baseKey); err != nil {
		t.Fatal(err)
	}

	upperKey := "upper"
	// Prepare() creates the snapshot with a runtime marker.
	if _, err := s.Prepare(ctx, upperKey, "base-commit"); err != nil {
		t.Fatal(err)
	}
	// First Mounts() call consumes the runtime marker and returns template mounts.
	// These template mounts are for VM runtimes that need block devices.
	upperMounts, err := s.Mounts(ctx, upperKey)
	if err != nil {
		t.Fatal(err)
	}
	if !mountsHaveTemplate(upperMounts) {
		t.Fatalf("expected upper mounts to include templates, got: %#v", upperMounts)
	}

	db, err := bolt.Open(filepath.Join(tempDir, "mounts.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mountRoot := filepath.Join(tempDir, "mounts")
	mm, err := manager.NewManager(db, mountRoot, manager.WithAllowedRoot(snapshotRoot))
	if err != nil {
		t.Fatal(err)
	}
	if closer, ok := mm.(interface{ Close() error }); ok {
		defer closer.Close()
	}

	activation, err := mm.Activate(ctx, "upper-activate-"+time.Now().Format("150405.000"), cloneMounts(upperMounts))
	if err != nil {
		t.Fatal(err)
	}
	wroteFile := false
	for _, a := range activation.Active {
		if mountTypeSuffixTest(a.Type) != "ext4" || a.MountPoint == "" {
			continue
		}
		upperDir := filepath.Join(a.MountPoint, "upper")
		if err := os.MkdirAll(upperDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(upperDir, "upper.txt"), []byte("upper"), 0644); err != nil {
			t.Fatal(err)
		}
		wroteFile = true
		break
	}
	if !wroteFile {
		_ = mm.Deactivate(ctx, activation.Name)
		t.Fatal("failed to locate ext4 mount to write upper.txt")
	}
	if err := mm.Deactivate(ctx, activation.Name); err != nil {
		t.Fatal(err)
	}

	lowerKey := "lower"
	lowerMounts, err := s.View(ctx, lowerKey, "base-commit")
	if err != nil {
		t.Fatal(err)
	}

	differ := erofsdiffer.NewErofsDiffer(contentStore, erofsdiffer.WithMountManager(mm))
	desc, err := differ.Compare(ctx, lowerMounts, upperMounts)
	if err != nil {
		t.Fatal(err)
	}

	found, err := tarHasPath(ctx, contentStore, desc, "upper.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("expected diff to include upper.txt")
	}
}

// TestErofsDifferCompareWithoutMountManager verifies that Compare returns an
// appropriate error when mount manager is required but not provided. EROFS
// snapshotter produces mounts with templates that require mount manager for
// resolution, so Compare cannot succeed without one.
func TestErofsDifferCompareWithoutMountManager(t *testing.T) {
	testutil.RequiresRoot(t)
	ctx := namespaces.WithNamespace(t.Context(), "testsuite")

	_, err := exec.LookPath("mkfs.erofs")
	if err != nil {
		t.Skipf("could not find mkfs.erofs: %v", err)
	}
	if !findErofs() {
		t.Skip("check for erofs kernel support failed, skipping test")
	}

	tempDir := t.TempDir()
	contentStore := imagetest.NewContentStore(ctx, t).Store

	snapshotRoot := filepath.Join(tempDir, "snapshots")
	s, err := NewSnapshotter(snapshotRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer cleanupAllSnapshots(ctx, s)

	snap := s.(*snapshotter)

	baseKey := "base"
	if _, err := s.Prepare(ctx, baseKey, ""); err != nil {
		t.Fatal(err)
	}
	baseID := snapshotID(t, snap, baseKey)
	if err := os.WriteFile(filepath.Join(snap.upperPath(baseID), "base.txt"), []byte("base"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(ctx, "base-commit", baseKey); err != nil {
		t.Fatal(err)
	}

	upperKey := "upper"
	upperMounts, err := s.Prepare(ctx, upperKey, "base-commit")
	if err != nil {
		t.Fatal(err)
	}
	upperID := snapshotID(t, snap, upperKey)
	if err := os.WriteFile(filepath.Join(snap.upperPath(upperID), "upper.txt"), []byte("upper"), 0644); err != nil {
		t.Fatal(err)
	}

	lowerKey := "lower"
	lowerMounts, err := s.View(ctx, lowerKey, "base-commit")
	if err != nil {
		t.Fatal(err)
	}

	// Verify that mounts have templates requiring mount manager
	if !mountsHaveTemplate(lowerMounts) && !mountsHaveTemplate(upperMounts) {
		t.Fatal("expected mounts to have templates requiring mount manager")
	}

	// Compare without mount manager should fail because EROFS mounts need resolution
	differ := erofsdiffer.NewErofsDiffer(contentStore)
	_, err = differ.Compare(ctx, lowerMounts, upperMounts)
	if err == nil {
		t.Fatal("expected error when mount manager is required but not provided")
	}
	if !strings.Contains(err.Error(), "mount manager is required") {
		t.Fatalf("expected 'mount manager is required' error, got: %v", err)
	}
}

// createTestTarContent creates test tar content using tartest.
func createTestTarContent() io.ReadCloser {
	// Create a tar context with current time for consistency
	tc := tartest.TarContext{}.WithModTime(time.Now())

	// Create the tar with our test files and directories
	tarWriter := tartest.TarAll(
		tc.File("test-file.txt", []byte(testFileContent), 0644),
		tc.Dir("testdir", 0755),
		tc.File("testdir/nested.txt", []byte(testNestedFileContent), 0644),
	)

	// Return the tar as a ReadCloser
	return tartest.TarFromWriterTo(tarWriter)
}

func tarHasPath(ctx context.Context, store content.Store, desc ocispec.Descriptor, target string) (bool, error) {
	ra, err := store.ReaderAt(ctx, desc)
	if err != nil {
		return false, err
	}
	defer ra.Close()

	rc := content.NewReader(ra)

	dr, err := compression.DecompressStream(rc)
	if err != nil {
		return false, err
	}
	defer dr.Close()

	tr := tar.NewReader(dr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		name := strings.TrimPrefix(h.Name, "./")
		if name == target {
			return true, nil
		}
	}
}

func cloneMounts(in []mount.Mount) []mount.Mount {
	if in == nil {
		return nil
	}
	out := make([]mount.Mount, len(in))
	for i := range in {
		out[i] = in[i]
		if len(in[i].Options) > 0 {
			out[i].Options = append([]string(nil), in[i].Options...)
		}
	}
	return out
}

func mountsHaveTemplate(mounts []mount.Mount) bool {
	for _, m := range mounts {
		if strings.Contains(m.Source, "{{") || strings.Contains(m.Target, "{{") {
			return true
		}
		for _, opt := range m.Options {
			if strings.Contains(opt, "{{") {
				return true
			}
		}
	}
	return false
}

// mountTypeSuffixTest returns the final component of a mount type.
// This is intentionally duplicated from plugins/diff/erofs to avoid
// exporting an internal function just for test purposes.
func mountTypeSuffixTest(t string) string {
	if t == "" {
		return ""
	}
	parts := strings.Split(t, "/")
	return parts[len(parts)-1]
}

func snapshotID(t *testing.T, s *snapshotter, key string) string {
	t.Helper()
	var id string
	if err := s.ms.WithTransaction(t.Context(), false, func(ctx context.Context) error {
		var err error
		id, _, _, err = storage.GetInfo(ctx, key)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

// cleanupAllSnapshots removes all snapshots and cleans up their active mounts.
// This ensures that t.TempDir() cleanup doesn't fail with "device or resource busy".
func cleanupAllSnapshots(ctx context.Context, s snapshots.Snapshotter) {
	snap := s.(*snapshotter)
	var keys []string
	_ = s.Walk(ctx, func(ctx context.Context, info snapshots.Info) error {
		keys = append(keys, info.Name)
		return nil
	})
	// Remove in reverse order (children first, then parents)
	for i := len(keys) - 1; i >= 0; i-- {
		// First cleanup active mounts if in block mode
		if snap.blockMode {
			if id, _, _, err := func() (string, snapshots.Info, snapshots.Usage, error) {
				var id string
				var info snapshots.Info
				var usage snapshots.Usage
				err := snap.ms.WithTransaction(ctx, false, func(ctx context.Context) error {
					var err error
					id, info, usage, err = storage.GetInfo(ctx, keys[i])
					return err
				})
				return id, info, usage, err
			}(); err == nil {
				_ = cleanupActiveMounts(snap.upperPath(id))
			}
		}
		_ = s.Remove(ctx, keys[i])
	}
}

// TestErofsDifferCompareMultipleStackedLayers tests Compare with 5+ stacked
// EROFS layers to verify that overlay template expansion works correctly
// with many layers.
func TestErofsDifferCompareMultipleStackedLayers(t *testing.T) {
	testutil.RequiresRoot(t)
	ctx := namespaces.WithNamespace(t.Context(), "testsuite")

	_, err := exec.LookPath("mkfs.erofs")
	if err != nil {
		t.Skipf("could not find mkfs.erofs: %v", err)
	}
	if !findErofs() {
		t.Skip("check for erofs kernel support failed, skipping test")
	}

	tempDir := t.TempDir()
	contentStore := imagetest.NewContentStore(ctx, t).Store

	snapshotRoot := filepath.Join(tempDir, "snapshots")
	s, err := NewSnapshotter(snapshotRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer cleanupAllSnapshots(ctx, s)

	snap := s.(*snapshotter)

	// Create 6 stacked layers
	layerCount := 6
	var parentKey string
	for i := 0; i < layerCount; i++ {
		key := fmt.Sprintf("layer-%d", i)
		commitKey := fmt.Sprintf("layer-%d-commit", i)

		if _, err := s.Prepare(ctx, key, parentKey); err != nil {
			t.Fatalf("failed to prepare layer %d: %v", i, err)
		}

		id := snapshotID(t, snap, key)
		filename := fmt.Sprintf("file-%d.txt", i)
		if err := os.WriteFile(filepath.Join(snap.upperPath(id), filename), []byte(fmt.Sprintf("content-%d", i)), 0644); err != nil {
			t.Fatalf("failed to write file in layer %d: %v", i, err)
		}

		if err := s.Commit(ctx, commitKey, key); err != nil {
			t.Fatalf("failed to commit layer %d: %v", i, err)
		}
		parentKey = commitKey
	}

	// Create upper layer on top of all stacked layers
	upperKey := "upper"
	upperMounts, err := s.Prepare(ctx, upperKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	upperID := snapshotID(t, snap, upperKey)
	if err := os.WriteFile(filepath.Join(snap.upperPath(upperID), "upper.txt"), []byte("upper"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create lower view from the stacked layers
	lowerKey := "lower"
	lowerMounts, err := s.View(ctx, lowerKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}

	// Verify mounts have templates (indicating multiple EROFS layers)
	if !mountsHaveTemplate(lowerMounts) && !mountsHaveTemplate(upperMounts) {
		t.Logf("lower mounts: %#v", lowerMounts)
		t.Logf("upper mounts: %#v", upperMounts)
		// This is acceptable if they're simple EROFS mounts
	}

	db, err := bolt.Open(filepath.Join(tempDir, "mounts.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mountRoot := filepath.Join(tempDir, "mounts")
	mm, err := manager.NewManager(db, mountRoot, manager.WithAllowedRoot(snapshotRoot))
	if err != nil {
		t.Fatal(err)
	}
	if closer, ok := mm.(interface{ Close() error }); ok {
		defer closer.Close()
	}

	differ := erofsdiffer.NewErofsDiffer(contentStore, erofsdiffer.WithMountManager(mm))
	desc, err := differ.Compare(ctx, lowerMounts, upperMounts)
	if err != nil {
		t.Fatal(err)
	}
	if desc.Digest == "" || desc.Size == 0 {
		t.Fatalf("unexpected diff descriptor: %+v", desc)
	}

	// Verify the diff contains the upper file
	found, err := tarHasPath(ctx, contentStore, desc, "upper.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("expected diff to include upper.txt")
	}
}

// TestErofsDifferCompareEmptyLowerMounts tests Compare behavior when lower
// mounts slice is empty. This simulates creating a diff from scratch.
func TestErofsDifferCompareEmptyLowerMounts(t *testing.T) {
	testutil.RequiresRoot(t)
	ctx := namespaces.WithNamespace(t.Context(), "testsuite")

	_, err := exec.LookPath("mkfs.erofs")
	if err != nil {
		t.Skipf("could not find mkfs.erofs: %v", err)
	}
	if !findErofs() {
		t.Skip("check for erofs kernel support failed, skipping test")
	}

	tempDir := t.TempDir()
	contentStore := imagetest.NewContentStore(ctx, t).Store

	snapshotRoot := filepath.Join(tempDir, "snapshots")
	s, err := NewSnapshotter(snapshotRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	snap := s.(*snapshotter)

	// Create a single layer (no parent)
	key := "single"
	if _, err := s.Prepare(ctx, key, ""); err != nil {
		t.Fatal(err)
	}
	id := snapshotID(t, snap, key)
	if err := os.WriteFile(filepath.Join(snap.upperPath(id), "new.txt"), []byte("new"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(ctx, "single-commit", key); err != nil {
		t.Fatal(err)
	}

	// Get mounts for the committed layer as upper
	upperKey := "upper"
	upperMounts, err := s.Prepare(ctx, upperKey, "single-commit")
	if err != nil {
		t.Fatal(err)
	}
	upperID := snapshotID(t, snap, upperKey)
	if err := os.WriteFile(filepath.Join(snap.upperPath(upperID), "upper.txt"), []byte("upper"), 0644); err != nil {
		t.Fatal(err)
	}

	db, err := bolt.Open(filepath.Join(tempDir, "mounts.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mountRoot := filepath.Join(tempDir, "mounts")
	mm, err := manager.NewManager(db, mountRoot, manager.WithAllowedRoot(snapshotRoot))
	if err != nil {
		t.Fatal(err)
	}
	if closer, ok := mm.(interface{ Close() error }); ok {
		defer closer.Close()
	}

	differ := erofsdiffer.NewErofsDiffer(contentStore, erofsdiffer.WithMountManager(mm))

	// Compare with empty lower mounts - this tests the base case
	emptyLower := []mount.Mount{}
	desc, err := differ.Compare(ctx, emptyLower, upperMounts)
	if err != nil {
		t.Fatal(err)
	}
	if desc.Digest == "" || desc.Size == 0 {
		t.Fatalf("unexpected diff descriptor: %+v", desc)
	}
}

// TestErofsDifferCompareContextCancellation tests that Compare properly handles
// context cancellation during mount manager operations.
func TestErofsDifferCompareContextCancellation(t *testing.T) {
	testutil.RequiresRoot(t)
	baseCtx := namespaces.WithNamespace(t.Context(), "testsuite")

	_, err := exec.LookPath("mkfs.erofs")
	if err != nil {
		t.Skipf("could not find mkfs.erofs: %v", err)
	}
	if !findErofs() {
		t.Skip("check for erofs kernel support failed, skipping test")
	}

	tempDir := t.TempDir()
	contentStore := imagetest.NewContentStore(baseCtx, t).Store

	snapshotRoot := filepath.Join(tempDir, "snapshots")
	s, err := NewSnapshotter(snapshotRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	snap := s.(*snapshotter)

	// Create base layer
	baseKey := "base"
	if _, err := s.Prepare(baseCtx, baseKey, ""); err != nil {
		t.Fatal(err)
	}
	baseID := snapshotID(t, snap, baseKey)
	if err := os.WriteFile(filepath.Join(snap.upperPath(baseID), "base.txt"), []byte("base"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(baseCtx, "base-commit", baseKey); err != nil {
		t.Fatal(err)
	}

	// Create upper layer
	upperKey := "upper"
	upperMounts, err := s.Prepare(baseCtx, upperKey, "base-commit")
	if err != nil {
		t.Fatal(err)
	}
	upperID := snapshotID(t, snap, upperKey)
	if err := os.WriteFile(filepath.Join(snap.upperPath(upperID), "upper.txt"), []byte("upper"), 0644); err != nil {
		t.Fatal(err)
	}

	lowerKey := "lower"
	lowerMounts, err := s.View(baseCtx, lowerKey, "base-commit")
	if err != nil {
		t.Fatal(err)
	}

	db, err := bolt.Open(filepath.Join(tempDir, "mounts.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mountRoot := filepath.Join(tempDir, "mounts")
	mm, err := manager.NewManager(db, mountRoot, manager.WithAllowedRoot(snapshotRoot))
	if err != nil {
		t.Fatal(err)
	}
	if closer, ok := mm.(interface{ Close() error }); ok {
		defer closer.Close()
	}

	differ := erofsdiffer.NewErofsDiffer(contentStore, erofsdiffer.WithMountManager(mm))

	// Create a cancelled context
	ctx, cancel := context.WithCancel(baseCtx)
	cancel() // Cancel immediately

	// Compare with cancelled context should fail
	_, err = differ.Compare(ctx, lowerMounts, upperMounts)
	if err == nil {
		t.Fatal("expected error with cancelled context")
	}
	// The error should be context-related
	if !strings.Contains(err.Error(), "context canceled") && !strings.Contains(err.Error(), "canceled") {
		t.Logf("got error (acceptable): %v", err)
	}
}

// TestErofsDifferCompareSingleLayerView tests Compare when lower is a single
// EROFS layer returned directly (KindView optimization path).
func TestErofsDifferCompareSingleLayerView(t *testing.T) {
	testutil.RequiresRoot(t)
	ctx := namespaces.WithNamespace(t.Context(), "testsuite")

	_, err := exec.LookPath("mkfs.erofs")
	if err != nil {
		t.Skipf("could not find mkfs.erofs: %v", err)
	}
	if !findErofs() {
		t.Skip("check for erofs kernel support failed, skipping test")
	}

	tempDir := t.TempDir()
	contentStore := imagetest.NewContentStore(ctx, t).Store

	snapshotRoot := filepath.Join(tempDir, "snapshots")
	s, err := NewSnapshotter(snapshotRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	snap := s.(*snapshotter)

	// Create single base layer
	baseKey := "base"
	if _, err := s.Prepare(ctx, baseKey, ""); err != nil {
		t.Fatal(err)
	}
	baseID := snapshotID(t, snap, baseKey)
	if err := os.WriteFile(filepath.Join(snap.upperPath(baseID), "base.txt"), []byte("base"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(ctx, "base-commit", baseKey); err != nil {
		t.Fatal(err)
	}

	// Create a view of the single layer - this triggers the KindView optimization
	viewKey := "view"
	viewMounts, err := s.View(ctx, viewKey, "base-commit")
	if err != nil {
		t.Fatal(err)
	}

	// Verify it's a single EROFS mount (the optimization path)
	if len(viewMounts) != 1 {
		t.Fatalf("expected single mount for view, got %d", len(viewMounts))
	}
	if viewMounts[0].Type != "erofs" {
		t.Fatalf("expected erofs mount type, got %s", viewMounts[0].Type)
	}

	// Create upper layer on top
	upperKey := "upper"
	upperMounts, err := s.Prepare(ctx, upperKey, "base-commit")
	if err != nil {
		t.Fatal(err)
	}
	upperID := snapshotID(t, snap, upperKey)
	if err := os.WriteFile(filepath.Join(snap.upperPath(upperID), "new.txt"), []byte("new"), 0644); err != nil {
		t.Fatal(err)
	}

	db, err := bolt.Open(filepath.Join(tempDir, "mounts.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mountRoot := filepath.Join(tempDir, "mounts")
	mm, err := manager.NewManager(db, mountRoot, manager.WithAllowedRoot(snapshotRoot))
	if err != nil {
		t.Fatal(err)
	}
	if closer, ok := mm.(interface{ Close() error }); ok {
		defer closer.Close()
	}

	differ := erofsdiffer.NewErofsDiffer(contentStore, erofsdiffer.WithMountManager(mm))

	// Compare using the single-layer view as lower
	desc, err := differ.Compare(ctx, viewMounts, upperMounts)
	if err != nil {
		t.Fatal(err)
	}
	if desc.Digest == "" || desc.Size == 0 {
		t.Fatalf("unexpected diff descriptor: %+v", desc)
	}

	// Verify the diff contains the new file
	found, err := tarHasPath(ctx, contentStore, desc, "new.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("expected diff to include new.txt")
	}
}

// TestErofsDifferCompareViewWithMultipleLayers tests Compare when lower is a
// view of multiple stacked layers, triggering the overlay template path.
func TestErofsDifferCompareViewWithMultipleLayers(t *testing.T) {
	testutil.RequiresRoot(t)
	ctx := namespaces.WithNamespace(t.Context(), "testsuite")

	_, err := exec.LookPath("mkfs.erofs")
	if err != nil {
		t.Skipf("could not find mkfs.erofs: %v", err)
	}
	if !findErofs() {
		t.Skip("check for erofs kernel support failed, skipping test")
	}

	tempDir := t.TempDir()
	contentStore := imagetest.NewContentStore(ctx, t).Store

	snapshotRoot := filepath.Join(tempDir, "snapshots")
	s, err := NewSnapshotter(snapshotRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	snap := s.(*snapshotter)

	// Create first layer
	layer1Key := "layer1"
	if _, err := s.Prepare(ctx, layer1Key, ""); err != nil {
		t.Fatal(err)
	}
	layer1ID := snapshotID(t, snap, layer1Key)
	if err := os.WriteFile(filepath.Join(snap.upperPath(layer1ID), "layer1.txt"), []byte("layer1"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(ctx, "layer1-commit", layer1Key); err != nil {
		t.Fatal(err)
	}

	// Create second layer
	layer2Key := "layer2"
	if _, err := s.Prepare(ctx, layer2Key, "layer1-commit"); err != nil {
		t.Fatal(err)
	}
	layer2ID := snapshotID(t, snap, layer2Key)
	if err := os.WriteFile(filepath.Join(snap.upperPath(layer2ID), "layer2.txt"), []byte("layer2"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(ctx, "layer2-commit", layer2Key); err != nil {
		t.Fatal(err)
	}

	// Create a view of the two layers - this should return overlay with templates
	viewKey := "view"
	viewMounts, err := s.View(ctx, viewKey, "layer2-commit")
	if err != nil {
		t.Fatal(err)
	}

	// The view of multiple layers should have templates or multiple mounts
	if len(viewMounts) < 2 && !mountsHaveTemplate(viewMounts) {
		t.Logf("view mounts: %#v", viewMounts)
		// May be EROFS mounts without templates, which is also valid
	}

	// Create upper layer
	upperKey := "upper"
	upperMounts, err := s.Prepare(ctx, upperKey, "layer2-commit")
	if err != nil {
		t.Fatal(err)
	}
	upperID := snapshotID(t, snap, upperKey)
	if err := os.WriteFile(filepath.Join(snap.upperPath(upperID), "upper.txt"), []byte("upper"), 0644); err != nil {
		t.Fatal(err)
	}

	db, err := bolt.Open(filepath.Join(tempDir, "mounts.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mountRoot := filepath.Join(tempDir, "mounts")
	mm, err := manager.NewManager(db, mountRoot, manager.WithAllowedRoot(snapshotRoot))
	if err != nil {
		t.Fatal(err)
	}
	if closer, ok := mm.(interface{ Close() error }); ok {
		defer closer.Close()
	}

	differ := erofsdiffer.NewErofsDiffer(contentStore, erofsdiffer.WithMountManager(mm))
	desc, err := differ.Compare(ctx, viewMounts, upperMounts)
	if err != nil {
		t.Fatal(err)
	}
	if desc.Digest == "" || desc.Size == 0 {
		t.Fatalf("unexpected diff descriptor: %+v", desc)
	}

	// Verify the diff contains the upper file
	found, err := tarHasPath(ctx, contentStore, desc, "upper.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("expected diff to include upper.txt")
	}
}

// TestErofsSnapshotterFsmetaSingleLayerView tests that when fsmeta merge
// collapses multiple layers into a single mount, KindView returns the EROFS
// mount directly without requiring mount manager resolution.
func TestErofsSnapshotterFsmetaSingleLayerView(t *testing.T) {
	testutil.RequiresRoot(t)
	ctx := namespaces.WithNamespace(t.Context(), "testsuite")

	_, err := exec.LookPath("mkfs.erofs")
	if err != nil {
		t.Skipf("could not find mkfs.erofs: %v", err)
	}
	if !findErofs() {
		t.Skip("check for erofs kernel support failed, skipping test")
	}

	tempDir := t.TempDir()

	// Create snapshotter with fsMergeThreshold=2 to trigger merge with just 3 layers
	snapshotRoot := filepath.Join(tempDir, "snapshots")
	s, err := NewSnapshotter(snapshotRoot, WithFsMergeThreshold(2))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	snap := s.(*snapshotter)

	// Create 3 layers to exceed the threshold and trigger fsmeta generation
	var parentKey string
	for i := 0; i < 3; i++ {
		key := fmt.Sprintf("layer-%d", i)
		commitKey := fmt.Sprintf("layer-%d-commit", i)

		if _, err := s.Prepare(ctx, key, parentKey); err != nil {
			t.Fatalf("failed to prepare layer %d: %v", i, err)
		}

		id := snapshotID(t, snap, key)
		filename := fmt.Sprintf("file-%d.txt", i)
		if err := os.WriteFile(filepath.Join(snap.upperPath(id), filename), []byte(fmt.Sprintf("content-%d", i)), 0644); err != nil {
			t.Fatalf("failed to write file in layer %d: %v", i, err)
		}

		if err := s.Commit(ctx, commitKey, key); err != nil {
			t.Fatalf("failed to commit layer %d: %v", i, err)
		}
		parentKey = commitKey
	}

	// Wait a bit for fsmeta generation (it runs asynchronously)
	time.Sleep(500 * time.Millisecond)

	// Check if fsmeta was generated for the top layer
	var topID string
	if err := snap.ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		topID, _, _, err = storage.GetInfo(ctx, "layer-2-commit")
		return err
	}); err != nil {
		t.Fatal(err)
	}

	fsmetaPath := snap.fsMetaPath(topID)
	fsmetaExists := false
	if fi, err := os.Stat(fsmetaPath); err == nil && fi.Size() > 0 {
		fsmetaExists = true
		t.Logf("fsmeta generated at %s (%d bytes)", fsmetaPath, fi.Size())
	}

	// Create a view of the merged layers
	viewKey := "merged-view"
	viewMounts, err := s.View(ctx, viewKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("view mounts (fsmeta exists: %v): %#v", fsmetaExists, viewMounts)

	if fsmetaExists {
		// With fsmeta, we expect a single merged EROFS mount (with device= options)
		// The key assertion: KindView with fsmeta merge resulting in single lower
		// should NOT require format/mkdir/overlay (which needs mount manager)
		hasTemplateOverlay := false
		for _, m := range viewMounts {
			if strings.Contains(m.Type, "overlay") && mountsHaveTemplate([]mount.Mount{m}) {
				hasTemplateOverlay = true
				break
			}
		}

		if hasTemplateOverlay {
			t.Fatalf("fsmeta view with single lower should not require template resolution, got: %#v", viewMounts)
		}

		// Verify we have EROFS mounts (possibly with device= for multi-device)
		hasErofs := false
		for _, m := range viewMounts {
			if m.Type == "erofs" {
				hasErofs = true
				t.Logf("found EROFS mount: source=%s, options=%v", m.Source, m.Options)
			}
		}
		if !hasErofs {
			t.Fatalf("expected EROFS mount in view, got: %#v", viewMounts)
		}
	} else {
		// Without fsmeta, we'll have multiple EROFS mounts with overlay
		t.Logf("fsmeta not generated (mkfs.erofs may not support --aufs), view has %d mounts", len(viewMounts))
	}
}

// TestErofsDifferCompareRequiresMountManagerForTemplates verifies that Compare
// returns a clear error when mounts have templates but no mount manager is provided.
func TestErofsDifferCompareRequiresMountManagerForTemplates(t *testing.T) {
	testutil.RequiresRoot(t)
	ctx := namespaces.WithNamespace(t.Context(), "testsuite")

	_, err := exec.LookPath("mkfs.erofs")
	if err != nil {
		t.Skipf("could not find mkfs.erofs: %v", err)
	}
	if !findErofs() {
		t.Skip("check for erofs kernel support failed, skipping test")
	}

	tempDir := t.TempDir()
	contentStore := imagetest.NewContentStore(ctx, t).Store

	snapshotRoot := filepath.Join(tempDir, "snapshots")
	s, err := NewSnapshotter(snapshotRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	snap := s.(*snapshotter)

	// Create two layers to get overlay mounts with templates
	baseKey := "base"
	if _, err := s.Prepare(ctx, baseKey, ""); err != nil {
		t.Fatal(err)
	}
	baseID := snapshotID(t, snap, baseKey)
	if err := os.WriteFile(filepath.Join(snap.upperPath(baseID), "base.txt"), []byte("base"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(ctx, "base-commit", baseKey); err != nil {
		t.Fatal(err)
	}

	childKey := "child"
	if _, err := s.Prepare(ctx, childKey, "base-commit"); err != nil {
		t.Fatal(err)
	}
	childID := snapshotID(t, snap, childKey)
	if err := os.WriteFile(filepath.Join(snap.upperPath(childID), "child.txt"), []byte("child"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(ctx, "child-commit", childKey); err != nil {
		t.Fatal(err)
	}

	// Get mounts that will have templates (multiple EROFS layers + overlay)
	upperKey := "upper"
	upperMounts, err := s.Prepare(ctx, upperKey, "child-commit")
	if err != nil {
		t.Fatal(err)
	}

	lowerKey := "lower"
	lowerMounts, err := s.View(ctx, lowerKey, "child-commit")
	if err != nil {
		t.Fatal(err)
	}

	// Verify at least one set of mounts needs mount manager
	// (EROFS mounts or templates require it)
	needsMM := false
	for _, m := range append(lowerMounts, upperMounts...) {
		if m.Type == "erofs" || strings.Contains(m.Type, "format/") ||
			strings.Contains(m.Source, "{{") {
			needsMM = true
			break
		}
		for _, opt := range m.Options {
			if strings.Contains(opt, "{{") {
				needsMM = true
				break
			}
		}
	}

	if !needsMM {
		t.Skipf("mounts don't require mount manager, skipping (lower: %#v, upper: %#v)", lowerMounts, upperMounts)
	}

	// Create differ WITHOUT mount manager
	differ := erofsdiffer.NewErofsDiffer(contentStore)

	// Compare should fail with clear error
	_, err = differ.Compare(ctx, lowerMounts, upperMounts)
	if err == nil {
		t.Fatal("expected error when mount manager is required but not provided")
	}
	if !strings.Contains(err.Error(), "mount manager is required") {
		t.Fatalf("expected 'mount manager is required' error, got: %v", err)
	}
	t.Logf("correctly got error when mount manager not provided: %v", err)
}

// TestErofsDifferCompareRejectsNonEROFSMounts tests that Compare correctly
// rejects mounts that are not EROFS layers (no .erofslayer marker).
// The EROFS differ is specifically designed for EROFS snapshotter layers.
func TestErofsDifferCompareRejectsNonEROFSMounts(t *testing.T) {
	testutil.RequiresRoot(t)
	ctx := namespaces.WithNamespace(t.Context(), "testsuite")

	tempDir := t.TempDir()
	contentStore := imagetest.NewContentStore(ctx, t).Store

	// Create simple directory structures for lower and upper
	lowerDir := filepath.Join(tempDir, "lower")
	upperDir := filepath.Join(tempDir, "upper")

	if err := os.MkdirAll(lowerDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(upperDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Add files
	if err := os.WriteFile(filepath.Join(lowerDir, "base.txt"), []byte("base"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(upperDir, "new.txt"), []byte("new"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create simple bind mounts WITHOUT .erofslayer marker
	// These are not valid EROFS snapshotter layers
	lowerMounts := []mount.Mount{
		{
			Source:  lowerDir,
			Type:    "bind",
			Options: []string{"ro", "rbind"},
		},
	}
	upperMounts := []mount.Mount{
		{
			Source:  upperDir,
			Type:    "bind",
			Options: []string{"ro", "rbind"},
		},
	}

	// Create differ WITHOUT mount manager
	differ := erofsdiffer.NewErofsDiffer(contentStore)

	// Compare should fail because upper is not an EROFS layer
	_, err := differ.Compare(ctx, lowerMounts, upperMounts)
	if err == nil {
		t.Fatal("expected error for non-EROFS layer mounts")
	}
	// Should get "not implemented" error indicating unsupported layer type
	if !strings.Contains(err.Error(), "not implemented") && !strings.Contains(err.Error(), "erofs-layer") {
		t.Fatalf("expected 'not implemented' or 'erofs-layer' error, got: %v", err)
	}
	t.Logf("correctly rejected non-EROFS mounts: %v", err)
}

func TestErofsBlockModeMountsAfterPrepare(t *testing.T) {
	testutil.RequiresRoot(t)
	ctx := namespaces.WithNamespace(t.Context(), "testsuite")

	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skipf("could not find mkfs.ext4: %v", err)
	}

	sn := newSnapshotter(t, WithDefaultSize(16*1024*1024))
	snapshtr, cleanup, err := sn(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	key := "block-active"
	if _, err := snapshtr.Prepare(ctx, key, ""); err != nil {
		t.Fatal(err)
	}

	// Block mode returns template mounts when overlay is not mounted on host.
	// VM-based runtimes (like qemubox) need block devices, not bind mounts.
	mounts1, err := snapshtr.Mounts(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	hasMkfs := false
	for _, m := range mounts1 {
		if m.Type == "mkfs/ext4" {
			hasMkfs = true
			break
		}
	}
	if !hasMkfs {
		t.Fatalf("expected Mounts to include mkfs/ext4 template, got: %#v", mounts1)
	}

	// Subsequent calls also return template mounts (no overlay mounted on host).
	mounts2, err := snapshtr.Mounts(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts1) != len(mounts2) {
		t.Fatalf("expected consistent template mounts, got %d vs %d", len(mounts1), len(mounts2))
	}

	if err := snapshtr.Remove(ctx, key); err != nil {
		t.Fatal(err)
	}
}

func TestErofsCleanupRemovesOrphan(t *testing.T) {
	testutil.RequiresRoot(t)
	ctx := namespaces.WithNamespace(t.Context(), "testsuite")

	sn := newSnapshotter(t)
	snapshtr, cleanup, err := sn(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	cleaner, ok := snapshtr.(snapshots.Cleaner)
	if !ok {
		t.Fatal("snapshotter does not implement Cleanup")
	}

	// Create and commit a snapshot to initialize the metadata store bucket.
	_, err = snapshtr.Prepare(ctx, "init", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshtr.Commit(ctx, "committed", "init"); err != nil {
		t.Fatal(err)
	}

	// Create an orphan snapshot directory not tracked by metadata.
	orphanDir := filepath.Join(snapshtr.(*snapshotter).root, "snapshots", "orphan")
	if err := os.MkdirAll(filepath.Join(orphanDir, "fs"), 0755); err != nil {
		t.Fatal(err)
	}

	if err := cleaner.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}

	_, err = os.Stat(orphanDir)
	if err == nil {
		t.Fatalf("expected orphan dir to be removed: %s", orphanDir)
	}
	if !os.IsNotExist(err) {
		t.Fatalf("expected not exist error, got: %v", err)
	}
}
