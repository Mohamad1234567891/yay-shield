# yay-shield v12

`yay-shield` is a security-focused wrapper around `yay` for Arch Linux and AUR package installation. It reviews AUR package build files before installation and warns about suspicious PKGBUILD behavior, supply-chain risks, obfuscation, unsafe downloads, malicious install hooks, and package impersonation attempts before code reaches the user’s system.

Version 12 is the first official public open-source release of `yay-shield`. Earlier versions were private development builds and were not published on GitHub.

## Important: How to Read yay-shield Results

`yay-shield` is a risk scanner, not a malware verdict engine.

A `LOW`, `MEDIUM`, or `HIGH` finding does **not** automatically mean that a package is malicious or compromised. It means that `yay-shield` found something in a scanned file, such as a `PKGBUILD`, `.install` script, Makefile, manifest, or build hook, that may be risky, unusual, fragile, or exploitable under certain conditions.

In other words:

* A finding means “review this carefully.”
* A finding does **not** always mean “this package is malware.”
* Some legitimate packages may trigger warnings because they perform complex build steps.
* Some risky patterns may be vulnerabilities or bad packaging practices rather than active compromise.

However, some results should be treated very seriously:

* If `yay-shield` reports **one or more ****`CRITICAL`**** findings**, you should avoid installing the package unless you fully understand and trust the behavior.
* If the total risk score is **540 or higher**, you should avoid installing the package, even if no `CRITICAL` finding appears.
* If there is a `CRITICAL` finding, you should avoid installing the package even if the risk score is below `540`.

A `CRITICAL` finding or a very high risk score still does not mathematically prove that the package is compromised. It means the package contains behavior dangerous enough that installing it is not recommended.

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
sudo install -m 755 yay-shield /usr/local/bin/yay-shield
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

`yay-shield` is a pre-installation risk scanner. It is not a perfect malware detector and does not claim to prove that a package is safe or unsafe.

It is designed to:

* Catch common malicious and suspicious AUR patterns
* Expose risky package behavior before installation
* Reduce the chance of blindly executing malicious PKGBUILDs
* Give users clearer security context before trusting an AUR package

It cannot guarantee safety against every possible attack, especially attacks hidden in large upstream source trees, compiled binaries, generated code, runtime behavior, or intentionally evasive build systems.

For best results, use `yay-shield` together with normal security practices:

* Prefer official repository packages when available
* Avoid unknown, abandoned, or newly submitted packages when possible
* Prefer packages with pinned sources and valid checksums
* Avoid running untrusted build scripts as your main user
* Keep your system updated

## License

This project should include an open-source license before publication.

