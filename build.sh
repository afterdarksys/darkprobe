#!/bin/bash

# DarkProbe Build Script
set -e

BINARY_NAME="darkprobe"
INSTALL_PATH="/usr/local/bin/$BINARY_NAME"

function usage() {
    echo "Usage: $0 [build|clean|install|all]"
    exit 1
}

if [ $# -eq 0 ]; then
    usage
fi

export PATH="/opt/homebrew/bin:/usr/local/go/bin:/usr/local/bin:$PATH"

function do_build() {
    echo "==> Resolving dependencies..."
    go mod tidy
    echo "==> Building $BINARY_NAME ..."
    go build -o $BINARY_NAME
    echo "==> Build complete."
}

function do_clean() {
    echo "==> Cleaning up..."
    if [ -f "$BINARY_NAME" ]; then
        rm "$BINARY_NAME"
        echo "==> Removed $BINARY_NAME."
    else
        echo "==> Nothing to clean."
    fi
}

function do_install() {
    echo "==> Installing $BINARY_NAME to $INSTALL_PATH ..."
    if [ ! -f "$BINARY_NAME" ]; then
        echo "==> Binary not found! Please build first or use 'all'."
        exit 1
    fi
    
    # Needs sudo for /usr/local/bin on macOS generally
    if [ -w "$(dirname "$INSTALL_PATH")" ]; then
        cp "$BINARY_NAME" "$INSTALL_PATH"
    else
        echo "==> Requesting sudo privileges to install to $INSTALL_PATH"
        sudo cp "$BINARY_NAME" "$INSTALL_PATH"
    fi
    echo "==> Installation complete. Try running '$BINARY_NAME'"
}

case "$1" in
    "build")
        do_build
        ;;
    "clean")
        do_clean
        ;;
    "install")
        do_install
        ;;
    "all")
        do_clean
        do_build
        do_install
        ;;
    *)
        usage
        ;;
esac
