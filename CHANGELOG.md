# Changelog

All notable changes to `yay-shield` will be documented in this file.

## v12.0.0 - First Official Public Release

Version 12 is the first official public open-source release of `yay-shield`.

Earlier versions were private development builds and were not published on GitHub.

### Added

- Official repository alternative prompting for AUR variants such as `blender-bin`.
- Target rewriting when the user chooses the official repository package instead of the AUR variant.
- Weak-advisory suppression by default to reduce noisy low-confidence findings.
- Detection for alias/function shadowing of trusted tools such as `curl`, `wget`, `git`, `pacman`, `makepkg`, and `sudo`.
- Stronger downstream build-script analysis for `build.rs`, `package.json`, `.install` files, Makefiles, CMake, Meson, and related build files.
- Better handling of obfuscated dangerous behavior in downstream build hooks.

### Changed

- Reduced false positives for normal VCS packages such as `-git` packages using `SKIP` checksums.
- Remote non-VCS downloads without checksums remain high-signal findings.
- Harmless downstream build hooks are treated with lower noise.
- Repeated nearby correlation findings are deduplicated.

### Security

- Improved detection of suspicious AUR installation behavior before package installation.
- Improved supply-chain risk detection across PKGBUILD files, install hooks, manifests, lockfiles, and downstream build scripts.
- Improved protection against package impersonation by suggesting official repository alternatives when available.
