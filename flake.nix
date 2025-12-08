{
  description = "qsh - QUIC shell with cross-compilation support";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
    android-nixpkgs = {
      url = "github:tadfisher/android-nixpkgs";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      fenix,
      flake-utils,
      android-nixpkgs,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ fenix.overlays.default ];
        };

        # Rust toolchain with all cross-compilation targets
        rustToolchain = pkgs.fenix.stable.withComponents [
          "cargo"
          "clippy"
          "rust-src"
          "rust-std"
          "rustc"
          "rustfmt"
        ];

        # Cross-compilation targets
        crossTargets = [
          # Linux musl targets
          "x86_64-unknown-linux-musl"
          "aarch64-unknown-linux-musl"
          "armv7-unknown-linux-musleabihf"
          # Windows targets
          "x86_64-pc-windows-gnu"
          "i686-pc-windows-gnu"
          # macOS targets
          "x86_64-apple-darwin"
          "aarch64-apple-darwin"
          # Android targets
          "aarch64-linux-android"
          "armv7-linux-androideabi"
          "x86_64-linux-android"
          "i686-linux-android"
        ];

        # Check if we're on a Darwin system
        isDarwin = pkgs.stdenv.isDarwin;
        isLinux = pkgs.stdenv.isLinux;

        # Get rust-std for each target
        targetStds = builtins.map (target: pkgs.fenix.targets.${target}.stable.rust-std) crossTargets;

        # Combined toolchain with all targets
        fullToolchain = pkgs.fenix.combine (
          [
            rustToolchain
          ]
          ++ targetStds
        );

        # Android SDK/NDK setup (Linux only)
        androidSdk =
          if isLinux then
            android-nixpkgs.sdk.${system} (
              sdkPkgs: with sdkPkgs; [
                cmdline-tools-latest
                build-tools-34-0-0
                platform-tools
                platforms-android-34
                ndk-26-1-10909125
              ]
            )
          else
            null;

        # Helper to get NDK toolchain path
        ndkVersion = "26.1.10909125";

        # Common build inputs (platform-agnostic)
        commonBuildInputs = with pkgs; [
          # Build essentials
          pkg-config
          openssl
          perl

          # For ring crate and boringssl bindgen
          llvmPackages.libclang.lib
          glib
          clang
          cmake
        ];

        # Linux-specific cross-compilation toolchains
        linuxCrossInputs =
          with pkgs;
          pkgs.lib.optionals isLinux [
            # Musl cross-compilation
            pkgsCross.musl64.stdenv.cc
            pkgsCross.aarch64-multiplatform-musl.stdenv.cc
            pkgsCross.armv7l-hf-multiplatform.stdenv.cc

            # Static libraries for musl builds
            pkgsCross.musl64.zstd.dev
            pkgsCross.musl64.zstd.out

            # Windows cross-compilation
            pkgsCross.mingwW64.stdenv.cc
            pkgsCross.mingw32.stdenv.cc
          ];

        # Darwin-specific inputs
        # Note: With newer nixpkgs, frameworks are bundled in apple-sdk and
        # propagated automatically by stdenv. We only need libiconv explicitly.
        darwinInputs =
          with pkgs;
          pkgs.lib.optionals isDarwin [
            libiconv
          ];

        # Platform detection for shell hook
        ndkPrebuiltDir = if isDarwin then "darwin-x86_64" else "linux-x86_64";

        # Shell hook to set up environment variables
        shellHook = ''
          # Rust environment
          export RUST_BACKTRACE=1
          export CARGO_INCREMENTAL=1

          # For ring/openssl builds
          export LD_LIBRARY_PATH=${
            pkgs.lib.makeLibraryPath [ pkgs.llvmPackages.libclang.lib ]
          }:$LD_LIBRARY_PATH

          ${pkgs.lib.optionalString isLinux ''
            # Android NDK paths (Linux only - Android cross-compile requires Linux host)
            export ANDROID_HOME="${androidSdk}/share/android-sdk"
            export ANDROID_NDK_HOME="${androidSdk}/share/android-sdk/ndk/${ndkVersion}"
            export NDK_HOME="$ANDROID_NDK_HOME"

            # Android target-specific linkers
            export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/${ndkPrebuiltDir}/bin/aarch64-linux-android34-clang"
            export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/${ndkPrebuiltDir}/bin/armv7a-linux-androideabi34-clang"
            export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/${ndkPrebuiltDir}/bin/x86_64-linux-android34-clang"
            export CARGO_TARGET_I686_LINUX_ANDROID_LINKER="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/${ndkPrebuiltDir}/bin/i686-linux-android34-clang"

            # Android AR tools (for cargo)
            export CARGO_TARGET_AARCH64_LINUX_ANDROID_AR="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/${ndkPrebuiltDir}/bin/llvm-ar"
            export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_AR="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/${ndkPrebuiltDir}/bin/llvm-ar"
            export CARGO_TARGET_X86_64_LINUX_ANDROID_AR="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/${ndkPrebuiltDir}/bin/llvm-ar"
            export CARGO_TARGET_I686_LINUX_ANDROID_AR="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/${ndkPrebuiltDir}/bin/llvm-ar"

            # CC/AR for ring crate build.rs (uses target-specific env vars)
            export CC_aarch64_linux_android="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/${ndkPrebuiltDir}/bin/aarch64-linux-android34-clang"
            export AR_aarch64_linux_android="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/${ndkPrebuiltDir}/bin/llvm-ar"
            export CC_armv7_linux_androideabi="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/${ndkPrebuiltDir}/bin/armv7a-linux-androideabi34-clang"
            export AR_armv7_linux_androideabi="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/${ndkPrebuiltDir}/bin/llvm-ar"
            export CC_x86_64_linux_android="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/${ndkPrebuiltDir}/bin/x86_64-linux-android34-clang"
            export AR_x86_64_linux_android="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/${ndkPrebuiltDir}/bin/llvm-ar"
            export CC_i686_linux_android="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/${ndkPrebuiltDir}/bin/i686-linux-android34-clang"
            export AR_i686_linux_android="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/${ndkPrebuiltDir}/bin/llvm-ar"

            # Musl target compiler/linkers for C deps (e.g. zstd-sys, ring, quiche/boringssl)
            export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="${pkgs.pkgsCross.musl64.stdenv.cc}/bin/x86_64-unknown-linux-musl-gcc"
            export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="${pkgs.pkgsCross.aarch64-multiplatform-musl.stdenv.cc}/bin/aarch64-unknown-linux-musl-gcc"
            export CC_x86_64_unknown_linux_musl="${pkgs.pkgsCross.musl64.stdenv.cc}/bin/x86_64-unknown-linux-musl-gcc"
            export CXX_x86_64_unknown_linux_musl="${pkgs.pkgsCross.musl64.stdenv.cc}/bin/x86_64-unknown-linux-musl-g++"
            export AR_x86_64_unknown_linux_musl="${pkgs.pkgsCross.musl64.stdenv.cc}/bin/x86_64-unknown-linux-musl-ar"

            # Windows target linkers
            export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="${pkgs.pkgsCross.mingwW64.stdenv.cc}/bin/x86_64-w64-mingw32-gcc"
            export CARGO_TARGET_I686_PC_WINDOWS_GNU_LINKER="${pkgs.pkgsCross.mingw32.stdenv.cc}/bin/i686-w64-mingw32-gcc"

            # Windows AR tools
            export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_AR="${pkgs.pkgsCross.mingwW64.stdenv.cc}/bin/x86_64-w64-mingw32-ar"
            export CARGO_TARGET_I686_PC_WINDOWS_GNU_AR="${pkgs.pkgsCross.mingw32.stdenv.cc}/bin/i686-w64-mingw32-ar"
          ''}

          echo "qsh development environment loaded (${system})"
          echo ""
          echo "Available targets:"
          echo "  Native:        ${system}"
          echo "  macOS:         x86_64-apple-darwin, aarch64-apple-darwin"
          ${pkgs.lib.optionalString isLinux ''
            echo "  Linux (musl):  x86_64-unknown-linux-musl, aarch64-unknown-linux-musl"
            echo "  Windows:       x86_64-pc-windows-gnu, i686-pc-windows-gnu"
            echo "  Android:       aarch64-linux-android, armv7-linux-androideabi,"
            echo "                 x86_64-linux-android, i686-linux-android"
          ''}
          ${pkgs.lib.optionalString isDarwin ''
            echo ""
            echo "Note: Cross-compile to Linux/Windows/Android requires Linux host."
            echo "      Use 'cargo build --target <arch>-apple-darwin' for macOS targets."
          ''}
          echo ""
          echo "Build examples:"
          echo "  cargo build --release --target x86_64-apple-darwin"
          echo "  cargo build --release --target aarch64-apple-darwin"
          ${pkgs.lib.optionalString isLinux ''
            echo "  cargo build --release --target x86_64-unknown-linux-musl"
            echo "  cargo build --release --target x86_64-pc-windows-gnu"
            echo "  cargo build --release --target aarch64-linux-android"
          ''}
        '';

      in
      {
        devShells = {
          default = pkgs.mkShell {
            buildInputs =
              commonBuildInputs
              ++ linuxCrossInputs
              ++ darwinInputs
              ++ [ fullToolchain ]
              ++ pkgs.lib.optionals isLinux [ androidSdk ]
              ++ (with pkgs; [
                # Development tools
                rust-analyzer
                cargo-watch
                cargo-edit
                cargo-outdated
                cargo-audit
                cargo-nextest
              ]);

            inherit shellHook;

            # Needed for openssl-sys and ring
            OPENSSL_DIR = "${pkgs.openssl.dev}";
            OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";
            OPENSSL_INCLUDE_DIR = "${pkgs.openssl.dev}/include";

            # For cross-compiled openssl
            OPENSSL_STATIC = "1";
          };

          # Minimal shell without Android (faster to build)
          minimal = pkgs.mkShell {
            buildInputs =
              with pkgs;
              [
                fullToolchain
                pkg-config
                openssl
                perl
                llvmPackages.libclang
                clang
              ]
              ++ darwinInputs
              ++ pkgs.lib.optionals isLinux [
                # Musl
                pkgsCross.musl64.stdenv.cc
                pkgsCross.musl64.zstd.dev
                pkgsCross.musl64.zstd.out
                # Windows
                pkgsCross.mingwW64.stdenv.cc
              ];

            shellHook = ''
              export RUST_BACKTRACE=1
              export LIBCLANG_PATH="${pkgs.llvmPackages.libclang.lib}/lib"
              ${pkgs.lib.optionalString isLinux ''
                export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="${pkgs.pkgsCross.musl64.stdenv.cc}/bin/x86_64-unknown-linux-musl-gcc"
                export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="${pkgs.pkgsCross.mingwW64.stdenv.cc}/bin/x86_64-w64-mingw32-gcc"
                # Musl C/C++ compiler for C deps (e.g. zstd-sys, ring, quiche/boringssl)
                export CC_x86_64_unknown_linux_musl="${pkgs.pkgsCross.musl64.stdenv.cc}/bin/x86_64-unknown-linux-musl-gcc"
                export CXX_x86_64_unknown_linux_musl="${pkgs.pkgsCross.musl64.stdenv.cc}/bin/x86_64-unknown-linux-musl-g++"
                export AR_x86_64_unknown_linux_musl="${pkgs.pkgsCross.musl64.stdenv.cc}/bin/x86_64-unknown-linux-musl-ar"
              ''}
              echo "qsh minimal dev environment (no Android)"
            '';

            OPENSSL_DIR = "${pkgs.openssl.dev}";
            OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";
            OPENSSL_INCLUDE_DIR = "${pkgs.openssl.dev}/include";
            OPENSSL_STATIC = "1";
          };
        };

        # Formatter
        formatter = pkgs.nixpkgs-fmt;
      }
    );
}
