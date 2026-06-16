# Security Policy

## Supported Versions

The currently supported version is:

| Version | Supported |
| ------- | --------- |
| v12.x   | Yes       |
| < v12   | No        |

Version 12 is the first official public release of `yay-shield`. Earlier versions were private development builds and are not supported.

## Reporting a Vulnerability

If you find a security vulnerability, bypass, serious false negative, or unsafe behavior in `yay-shield`, please report it responsibly.

Please do not publicly disclose serious security issues before they have been reviewed.

You can report security issues by opening a private GitHub security advisory if available, or by contacting the maintainer through the official project repository:

https://github.com/Mohamad1234567891/yay-shield

## What To Include

When reporting a vulnerability, please include:

- A clear description of the issue
- Steps to reproduce it
- The affected version of `yay-shield`
- Example PKGBUILD or test input, if possible
- Whether the issue causes a false negative, false positive, crash, bypass, or unsafe behavior

## Response Expectations

Security reports will be reviewed as soon as possible.

If the report is valid, a fix will be prepared and released in a future version. Public disclosure should happen only after a fix is available, unless the issue is already public or actively exploited.

## Scope

Security issues may include:

- Scanner bypasses
- Dangerous false negatives
- Unsafe handoff behavior
- Incorrect trust decisions
- Vulnerabilities in `yay-shield` itself
- Bugs that could cause users to install unsafe packages unintentionally
