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

	fmt.Println("Installing Rust (if not already installed)...")

	// Check if Rust is installed
	if _, err := exec.LookPath("cargo"); err != nil {
		fmt.Println("Rust not found. Please install Rust first:")
		fmt.Println("curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh")
		fmt.Println("Then run: source ~/.cargo/env")
		os.Exit(1)
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

	fmt.Println("Rust library built successfully!")
	fmt.Println("Umbral Pre-Go v0.12.0-go is ready!")
	fmt.Println("You can now use the library with:")
	fmt.Println("go get github.com/vlsilver/umbral/umbral-pre-cgo")
}
