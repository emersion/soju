package msgstore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDeleteMessagesBefore(t *testing.T) {
	root := t.TempDir()
	entityDir := filepath.Join(root, "testuser", "testnet", "testchan")
	if err := os.MkdirAll(entityDir, 0o750); err != nil {
		t.Fatal(err)
	}

	// Add a log file older than the cutoff which should be deleted
	beforeFile := filepath.Join(entityDir, "2020-01-01.log")
	if err := os.WriteFile(beforeFile, []byte("test"), 0o640); err != nil {
		t.Fatal(err)
	}

	// Add a log file on the cutoff date which should be kept
	cutoffFile := filepath.Join(entityDir, "2026-01-15.log")
	if err := os.WriteFile(cutoffFile, []byte("test"), 0o640); err != nil {
		t.Fatal(err)
	}

	// Add a newer log file after the cutoff which should be kept
	afterFile := filepath.Join(entityDir, "2026-01-16.log")
	if err := os.WriteFile(afterFile, []byte("test"), 0o640); err != nil {
		t.Fatal(err)
	}

	// Add a future log file which should also be kept
	futureFile := filepath.Join(entityDir, "2030-12-31.log")
	if err := os.WriteFile(futureFile, []byte("test"), 0o640); err != nil {
		t.Fatal(err)
	}

	// Add a non-log file to ensure only log files are considered
	nonLogFile := filepath.Join(entityDir, "2020-01-01.txt")
	if err := os.WriteFile(nonLogFile, []byte("test"), 0o640); err != nil {
		t.Fatal(err)
	}

	// Delete files before the cutoff date
	before := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	if err := DeleteMessagesBefore(root, before); err != nil {
		t.Fatal(err)
	}

	// Verify the old log file was removed
	if _, err := os.Stat(beforeFile); !os.IsNotExist(err) {
		t.Error("expected old file to be deleted")
	}

	// Verify the cutoff-date log file was kept
	if _, err := os.Stat(cutoffFile); err != nil {
		t.Error("expected cutoff date file to still exist")
	}

	// Verify the newer log file was kept
	if _, err := os.Stat(afterFile); err != nil {
		t.Error("expected recent file to still exist")
	}

	// Verify the future log file was kept
	if _, err := os.Stat(futureFile); err != nil {
		t.Error("expected future file to still exist")
	}

	// Verify non-log files were kept
	if _, err := os.Stat(nonLogFile); err != nil {
		t.Error("expected non-log file to still exist")
	}

	// Verify the directory remains because it still contains files
	if _, err := os.Stat(entityDir); err != nil {
		t.Error("expected directory with remaining files to still exist")
	}
}

func TestDeleteMessagesBeforeCleansUpEmptyDirs(t *testing.T) {
	root := t.TempDir()
	emptyDir := filepath.Join(root, "user1", "network1", "channel")
	if err := os.MkdirAll(emptyDir, 0o750); err != nil {
		t.Fatal(err)
	}

	// Add an expired log file so the directory becomes empty after deletion
	expiredFile := filepath.Join(emptyDir, "2020-01-01.log")
	if err := os.WriteFile(expiredFile, []byte("test"), 0o640); err != nil {
		t.Fatal(err)
	}

	// Create another directory with a newer log file that should be kept
	nonEmptyDir := filepath.Join(root, "user2", "network2", "channel")
	if err := os.MkdirAll(nonEmptyDir, 0o750); err != nil {
		t.Fatal(err)
	}
	keepFile := filepath.Join(nonEmptyDir, "2026-01-16.log")
	if err := os.WriteFile(keepFile, []byte("test"), 0o640); err != nil {
		t.Fatal(err)
	}

	// Delete files before the cutoff date
	before := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	if err := DeleteMessagesBefore(root, before); err != nil {
		t.Fatal(err)
	}

	// Verify the expired file was removed
	if _, err := os.Stat(expiredFile); !os.IsNotExist(err) {
		t.Error("expected expired file to be deleted")
	}

	// Verify the directory with expired file was removed once it became empty
	if _, err := os.Stat(emptyDir); !os.IsNotExist(err) {
		t.Error("expected empty nested directory to be removed")
	}

	// Verify empty parent directories are also removed
	if _, err := os.Stat(filepath.Join(root, "user1")); !os.IsNotExist(err) {
		t.Error("expected empty parent directory to be removed")
	}

	// Verify the directory with a remaining log file still exists
	if _, err := os.Stat(nonEmptyDir); err != nil {
		t.Error("expected non-empty directory to still exist")
	}

	// Verify the non-expired log file still exists
	if _, err := os.Stat(keepFile); err != nil {
		t.Error("expected file in non-empty directory to still exist")
	}

	// Verify the root directory itself is never removed
	if _, err := os.Stat(root); err != nil {
		t.Error("expected root directory to still exist")
	}
}

func TestDeleteMessagesBeforeReportsCleanupErrors(t *testing.T) {
	root := t.TempDir()
	emptyDir := filepath.Join(root, "user1", "network1", "channel")
	if err := os.MkdirAll(emptyDir, 0o750); err != nil {
		t.Fatal(err)
	}

	expiredFile := filepath.Join(emptyDir, "2020-01-01.log")
	if err := os.WriteFile(expiredFile, []byte("test"), 0o640); err != nil {
		t.Fatal(err)
	}

	blockedDir := filepath.Join(root, "user1", "network1")
	if err := os.Chmod(blockedDir, 0o550); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(blockedDir, 0o750)

	before := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	err := DeleteMessagesBefore(root, before)
	if err == nil {
		t.Fatal("expected cleanup error")
	}

	if !errors.Is(err, ErrCleanup) {
		t.Fatalf("expected cleanup error, got %v", err)
	}

	if _, err := os.Stat(expiredFile); !os.IsNotExist(err) {
		t.Error("expected expired file to be deleted")
	}

	if _, err := os.Stat(emptyDir); err != nil {
		t.Error("expected empty directory to remain when cleanup fails")
	}
}
