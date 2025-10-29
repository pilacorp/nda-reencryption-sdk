//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

func main() {
	// Get the directory of this file
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filename)

	// Change to the parent directory (rust-umbral root)
	parentDir := filepath.Dir(dir)
	if err := os.Chdir(parentDir); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Building Rust library...")

	// Build Rust library
	cmd := exec.Command("cargo", "build", "--release", "--features", "bindings-c")
	cmd.Dir = filepath.Join(parentDir, "umbral-pre")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		log.Fatal("Failed to build Rust library:", err)
	}

	// Copy library to lib directory
	libDir := filepath.Join(dir, "lib")
	if err := os.MkdirAll(libDir, 0755); err != nil {
		log.Fatal("Failed to create lib directory:", err)
	}

	// Copy the built library
	srcLib := filepath.Join(parentDir, "target", "release", "libumbral_pre.dylib")
	dstLib := filepath.Join(libDir, "libumbral_pre.dylib")

	if err := exec.Command("cp", srcLib, dstLib).Run(); err != nil {
		log.Printf("Warning: Failed to copy library: %v", err)
	} else {
		fmt.Printf("Copied library to %s\n", dstLib)
	}

	fmt.Println("Rust library built and copied successfully!")
}
