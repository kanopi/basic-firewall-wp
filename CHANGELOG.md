# Changelog

All notable changes to this plugin are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Every firewall decision is announced as a WordPress action:
  `basic_firewall_decision` with the event and its kind, and
  `basic_firewall_decision_{$type}` — `allowed`, `blocked`, `challenged`,
  `challenge_solved`, `challenge_failed`, `recorded`, `redirected`, `marked`,
  `tarpitted`. The library already speaks PSR-14; the plugin hands it a small
  dispatcher that holds each decision until `plugins_loaded`, so a regular plugin
  hears it rather than only an mu-plugin, and announces a refusal at shutdown.
  Decisions made on the wp-config.php path wait for WordPress the way a mark
  does; a refusal there exits before WordPress loads and is never announced. A
  listener that throws is logged and changes nothing about the request.

- **Lockdown**, refusing every client but an allowlist before any rule is
  consulted, and recording none of them — so lifting it does not leave a block
  list full of customers. On the General screen, which refuses to arm it against
  an empty list, refuses `start-end` ranges the library would never match on
  this list, and warns when the list does not cover the address the firewall
  sees for you. The compiler applies the same refusal to an imported document.
  Site Health, the Status screen and `wp basic-firewall status` report it
  however it was armed, including from a panic file saying `lockdown`. In
  `exception` mode the refusal keeps its `Retry-After` header.

- A **panic file**, for turning the firewall down mid-incident without a deploy.
  Name a path at the bottom of the General screen, and writing a mode into that
  file changes the operating mode on the next request, on both evaluation paths.
  A file that names nothing recognisable changes nothing and is reported rather
  than being read as "off" — otherwise a leftover file would disable the firewall
  silently. While one is active, Site Health raises it as critical, the Status
  screen leads with it, and `wp basic-firewall status` reports it.
  `BASIC_FIREWALL_MODE` still wins over it, and the request tester ignores it,
  since a panic file saying `block` would otherwise end the admin page mid-test.

- Support for the responses `kanopi/firewall` 2.26.0 introduced: **redirect**,
  **mark** and **record**, alongside a per-rule choice of whether a match is
  written to the durable block list. Refusing and recording come apart, which is
  what a honeypot needs (record without refusing) and what a lockdown needs
  (refuse without recording — so lifting it does not leave every visitor banned).
- `basic_firewall_request_marked`, and `Runner::is_marked()`, so a marked request
  is observable from WordPress. The library records a mark on its own Symfony
  Request, which WordPress knows nothing about; without this, `mark` was a
  response the screen offered and nothing on the site could see. Works on both
  evaluation paths, including the wp-config.php one, where the mark is stashed
  until there is a hook to announce it on.

### Changed

- **Stored paths no longer use Drupal's `private://` scheme.** A relative path
  resolves inside the firewall's private directory and an absolute path is used
  as given. `private://` is a registered stream wrapper in Drupal and nothing at
  all in WordPress, so carrying it across put a Drupal-ism in front of every
  WordPress developer for a string their platform cannot resolve. Existing
  settings are rewritten by a schema upgrade, and the old spelling still
  resolves for anything the upgrade did not reach.
- The bundled library is now `kanopi/firewall` 2.33.0, and the plugin requires ^2.33.
- The library version is read from Composer's runtime data first and the
  build-time marker second. The marker is written at build time and went stale
  the moment a working copy ran `composer update` — reporting 2.25.0 while every
  test passed against 2.26.0. In a scoped release neither Composer name resolves,
  so the marker still answers there, and it is now committed rather than
  generated-only.

### Fixed

- A latent fatal in scoped builds. PHP-Scoper leaves Composer's classmap key for
  `InstalledVersions` unscoped while rewriting the file it points at to declare
  the prefixed class, so asking for the unscoped name after the scoped one is
  loaded is a "Cannot redeclare" fatal. Lookups now ask for the scoped name
  first and never touch the broken key.

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
