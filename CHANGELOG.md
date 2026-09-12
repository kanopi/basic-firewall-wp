# Changelog

All notable changes to this plugin are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0]

First release. The WordPress port of the Drupal module `basic_firewall`, built
on `kanopi/firewall` v2.25.0.

### Added

- Nine rule types: IP address, Request / URL, user agent, rate limit, ASN,
  geolocation, vulnerability score, IP reputation (AbuseIPDB) and the OWASP Core
  Rule Set, each with its own form, validation, compilation and capability
  detection.
- Sixteen administrative screens covering the module's routes: dashboard, rule
  collection and editor with a type chooser, general, storage, logging,
  challenge, presets with a preview, advanced YAML, request tester, compiled
  configuration, export, import with a preview, log report, blocked clients with
  a lookup and unblock confirmation, and rebuild.
- Twelve WP-CLI commands under `wp basic-firewall`, mirroring the module's Drush
  verbs.
- Two evaluation paths: an mu-plugin installed on activation, and an optional
  `wp-config.php` bootstrap that runs before a page cache can serve.
- Nine Site Health tests, plus an admin notice for anything at Error severity.
- Export and import with credential redaction, `%env()` token preservation, and
  an import that never blanks an existing credential.
- A release build that vendors the library namespace-scoped, and verifies the
  result resolves before producing a zip.

### Security

- The private directory is created with `.htaccess`, `web.config` and
  `index.php` guards, given a random per-site name, and then **probed over HTTP**
  rather than assumed protected. On nginx the first two guards are inert, which
  Site Health reports as an error.
- WordPress's database credentials are never written into the compiled
  configuration. They are injected at request time, so an export cannot leak
  them, no plaintext password reaches disk, and a rotated password takes effect
  on the next request.
- Only the library's `file` secret processor is ever enabled, never `require`,
  which would turn an environment-variable injection into remote code execution.
- Destructive WP-CLI commands refuse to run without `--yes` and exit non-zero
  when they refuse, rather than exiting 0 having done nothing.
