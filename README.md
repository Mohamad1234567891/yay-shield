# yay-shield v12

`yay-shield` is a security-focused wrapper around `yay` for Arch Linux and AUR package installation. It reviews AUR package build files before installation and warns about suspicious PKGBUILD behavior, supply-chain risks, obfuscation, unsafe downloads, malicious install hooks, and package impersonation attempts before code reaches the user’s system.

Version 12 is the first official public open-source release of `yay-shield`. Earlier versions were private development builds and were not published on GitHub.

## Important: How to Read yay-shield Results

`yay-shield` is designed to help users make safer AUR installation decisions before package build scripts run on their system.

Most `LOW`, `MEDIUM`, and `HIGH` findings do **not** mean that a package is compromised. They usually mean that `yay-shield` found risky, unusual, fragile, or poorly implemented behavior in a scanned file such as a `PKGBUILD`, `.install` script, Makefile, manifest, or build hook.

In practical terms:

* If there are only `LOW`, `MEDIUM`, or `HIGH` findings, no `CRITICAL` findings, and the total risk score is below `540`, the package is usually still likely to be safe to install.
* These findings often point to packaging mistakes, unsafe implementation choices, weak integrity practices, or patterns that could make the package easier to compromise.
* If a `HIGH` finding appears, experienced users are encouraged to manually review the referenced file before installing.
* Legitimate packages can trigger warnings when they use complex build logic, custom install hooks, or unusual upstream build systems.

Some results should be treated as serious stop signs:

* If `yay-shield` reports one or more **`CRITICAL`** findings, installing the package is not recommended unless you fully understand and trust the behavior.
* If the total risk score is **540 or higher**, installing the package is not recommended, even if no `CRITICAL` finding appears.
* A `CRITICAL` finding or a risk score of `540+` means the package contains behavior that is highly abnormal, highly dangerous, or strongly consistent with compromise-style activity.

A `CRITICAL` finding does not mathematically prove that the package is compromised, but it is a strong warning that the package is too risky for normal installation. In that case, avoid installing it unless you know exactly what the package is doing and why.

## What yay-shield Does

`yay-shield` sits in front of `yay`. When the user tries to install an AUR package, it clones and analyzes the package build files before handing control back to `yay`.

It checks for:

* Dangerous shell execution patterns
* Download-piped-to-shell behavior
* `eval`, `bash -c`, `source`, process substitution, and encoded payloads
* Base64, hex, ANSI-C string, arithmetic, array, and variable-based command reconstruction
* IFS mutation and Bash parser-bypass tricks
* Network fetches in unexpected build contexts
* Dropper chains such as download -> chmod -> execute
* Suspicious `.install` lifecycle hooks
* PKGBUILD self-modification
* Recursive `makepkg` or integrity-bypass behavior
* Writes to sensitive system paths outside `$pkgdir`
* Service, cron, shell profile, autostart, sudoers, and persistence modifications
* Token, credential, browser-profile, SSH, cloud-config, and secret-directory access
* Typosquatting and Unicode homoglyph package names
* Low-trust AUR metadata such as orphaned, very new, or low-vote packages
* Maintainer reputation signals
* Dependency-confusion risks through `provides=`
* Official-repository alternatives for AUR variants like `blender-bin`
* Git hooks, suspicious executable files, symlink escapes, archive traversal, and path shadowing
* Manifest-level supply-chain risks in npm, Cargo, Go, Python, Ruby, Gradle, Maven, CMake, Meson, and lockfiles
* Downstream build-script behavior in `build.rs`, `setup.py`, `package.json`, Makefiles, CMake, Meson, and related files

## Use by AUR Maintainers and Contributors

`yay-shield` is also useful for AUR maintainers, package contributors, and experienced Arch users.

A maintainer can run `yay-shield` against their own package to see which parts of the package may look risky to users, which install logic could be hardened, and which packaging choices may expose the package to compromise. This makes `yay-shield` useful not only as an install-time defense tool, but also as a package-quality and hardening tool.

For maintainers, findings can help identify:

* Weak or missing source integrity checks
* Risky install script behavior
* Unsafe build hooks
* Suspicious command chains
* Unnecessary network access during build
* Dangerous file writes or permissions
* Patterns that could make the package easier to compromise

Even senior Arch users and AUR maintainers can use `yay-shield` as a second layer of review before trusting or publishing package changes.

## Version 12 Highlights

Version 12 adds safer and quieter behavior compared with earlier development builds:

* Offers official repository alternatives for AUR variants. For example, if the user installs `blender-bin` and `blender` exists in the official Arch repositories, `yay-shield` asks whether to install the official package instead.
* Rewrites the selected package target only if the user agrees.
* Suppresses very weak advisory findings by default to reduce noise.
* Reduces false positives for normal VCS packages such as `-git` packages using `SKIP` checksums.
* Keeps remote non-VCS downloads without checksums loud.
* Makes downstream build-script scanning quieter for harmless hooks and stronger against obfuscated malicious behavior.
* Detects alias/function shadowing of trusted tools such as `curl`, `wget`, `git`, `pacman`, `makepkg`, and `sudo`.
* Deduplicates repeated nearby correlation alerts.

## Requirements

Required runtime dependencies:

* Python 3
* `yay`
* `git`
* `curl`
* `pacman`
* `file`
* `sha256sum`

Optional dependencies:

* `shellcheck` for shell-script analysis
* `gpg` for PGP key verification checks
* `strings` for binary string inspection
* `bsdtar` for archive-related inspection
* `bwrap` and `strace` for optional sandbox checks
* `binwalk` for optional image/steganography inspection

On Arch Linux, install the common dependencies with:

```bash
sudo pacman -S --needed python git curl pacman file coreutils yay shellcheck gnupg binutils bubblewrap strace libarchive
```

`binwalk` may be installed separately if you want the optional steganography scan feature.

## Installation

Recommended manual installation:

```bash
git clone https://github.com/Mohamad1234567891/yay-shield.git
cd yay-shield
sudo install -m 755 yay-shield.py /usr/local/bin/yay-shield
```

Then verify:

```bash
yay-shield --version
```

After installation, use it like `yay`:

```bash
yay-shield -S package-name
```

Example:

```bash
yay-shield -S blender-bin
```

If an official repository alternative exists, `yay-shield` may offer to install the official package instead.

## Configuration

`yay-shield` is configured with environment variables.

Common options:

```bash
YSHIELD_FORCE=1
YSHIELD_MIN_SEVERITY=MEDIUM
YSHIELD_BLOCK_MIN_SEVERITY=HIGH
YSHIELD_REPORT_JSON=1
YSHIELD_REPORT_PATH=/tmp/yay-shield-report.json
YSHIELD_DEBUG=1
```

Analysis toggles:

```bash
YSHIELD_DATA_FLOW=1
YSHIELD_CALL_GRAPH=1
YSHIELD_SHELLCHECK=1
YSHIELD_BINARY_STRINGS=1
YSHIELD_HOMOGLYPH=1
YSHIELD_ANTI_ANALYSIS=1
YSHIELD_STRING_RECONSTRUCT=1
YSHIELD_SEMANTIC_VARS=1
YSHIELD_HEREDOC_SCAN=1
YSHIELD_DIFF_AWARE=1
YSHIELD_GPG_VERIFY=1
YSHIELD_PROC_SUB_NET=1
YSHIELD_TRAP_ANALYSIS=1
YSHIELD_GLOB_OBFUSC=1
YSHIELD_INDIRECT_VAR=1
YSHIELD_BUILD_SYSTEM_DEEP=1
YSHIELD_GIT_HOOK_SCAN=1
YSHIELD_ARITH_CHARCODE=1
YSHIELD_SHELL_OPT_ANALYSIS=1
YSHIELD_DROPPER_PATH_TRACKING=1
YSHIELD_MANIFEST_DEEP=1
YSHIELD_SOURCE_INTEGRITY_DEEP=1
YSHIELD_SYMLINK_SCAN=1
YSHIELD_ARCHIVE_RISK_SCAN=1
YSHIELD_LOCKFILE_SCAN=1
YSHIELD_HANDOFF_ARG_GUARD=1
YSHIELD_BASH_EAGER_DECODE=1
YSHIELD_PARAM_TRANSFORM_TRACK=1
YSHIELD_ARRAY_INDEX_TRACK=1
YSHIELD_FILE_TAINT_TRACK=1
YSHIELD_DOWNSTREAM_SCRIPT_CRAWL=1
YSHIELD_INSTALL_UNIFORM_SCAN=1
YSHIELD_OFFICIAL_ALT_PROMPT=1
YSHIELD_WEAK_ADVISORIES=0
```

## Security Model

`yay-shield` is a pre-installation security review layer for AUR installs. It is built to detect dangerous installer behavior, risky packaging choices, weak supply-chain practices, and common compromise patterns before the package is installed.

It is designed to help users:

* Avoid packages with highly dangerous install behavior
* Detect suspicious or compromised-looking AUR build scripts before execution
* Identify weak packaging practices that attackers could abuse
* Prefer safer official repository packages when available
* Make faster and better-informed decisions before trusting AUR packages

`yay-shield` is especially useful because AUR packages execute build and install logic from user-maintained repositories. A malicious or compromised package can do serious damage if dangerous behavior is not noticed before installation.

For best results, treat `yay-shield` as a strong pre-installation review tool:

* `LOW`, `MEDIUM`, and `HIGH` findings usually mean “review this” rather than “do not install.”
* One or more `CRITICAL` findings means installation is strongly discouraged.
* A risk score of `540` or higher means installation is strongly discouraged, even without a `CRITICAL` finding.
* Official repository alternatives are usually safer than AUR variants when they provide the same software.

## License

`yay-shield` is licensed under the GNU General Public License version 3.

Copyright (C) 2026 Muhammed Bekiroğlu
Copyright (C) 2026 Alshajara Computer Science Institute

Additional attribution notice under GPLv3 section 7(b):

> yay-shield was originally created by Muhammed Bekiroğlu.
> Original repository: https://github.com/Mohamad1234567891/yay-shield
> Author channel: https://www.youtube.com/channel/UCn5v_KxsVgdbba4vk1CxjAA?sub_confirmation=1

Redistributed copies and modified versions must preserve this reasonable author attribution in the source code, documentation, and other reasonable legal notices accompanying the work.

This attribution requirement does not limit, restrict, or otherwise modify the rights granted under the GNU General Public License version 3.

## Author

Created by **Muhammed Bekiroğlu**
Alshajara Computer Science Institute

* Original repository: https://github.com/Mohamad1234567891/yay-shield
* Author channel: https://www.youtube.com/channel/UCn5v_KxsVgdbba4vk1CxjAA?sub_confirmation=1
