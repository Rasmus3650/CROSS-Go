#!/bin/bash

# Define build directory
BUILD_DIR="build"

# Remove and recreate the build directory
echo "Cleaning build directory..."
rm -rf "$BUILD_DIR"
mkdir "$BUILD_DIR"

# Navigate into build directory
cd "$BUILD_DIR" || exit 1

# Run CMake
echo "Running CMake..."
cmake ..

# Run Make
echo "Building project..."
make -j$(nproc)  # Use all available CPU cores for faster compilation

echo "Build complete!"

