# Changelog

All notable changes to this plugin are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **The rule list says whether a scheduled rule is awake**, and until when, in
  the rule's own timezone — *Block — asleep now (until Mon 18:00 PDT)*. A
  sleeping rule matches nothing, which from the outside looks exactly like a
  broken one. A window whose last date has passed says it has ended, one the
  library cannot read says the rule is not running, and an observing rule says
  both. Activity windows are documented in the README for the first time.

- **Observe only**, per rule, so one rule can be tried on live traffic while
  every other rule keeps enforcing. An observing rule is evaluated and every
  match logged at `warning`, then treated as no match. The rule list reads
  *Block — observing only*, the Test screen reports *Matched, but only
  observed* rather than allowed, and the Log screen gains an enforcement filter
  that counts observed matches apart from everything else — matched on the
  library's message, because a mark carries the same `enforced: false`. Offered
  only where the library honours it; elsewhere an observing rule is skipped at
  compile time rather than left to enforce.

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

- The rule screen shows every response's fields as soon as that response is
  chosen, rather than only once a rule has been saved with it. Choosing
  Redirect on a new rule used to offer nowhere to type the destination, so the
  first save stored a redirect naming nowhere. Values only another response
  reads are no longer stored — a rule switched from redirect to block does not
  keep a destination nothing acts on.
- The response help text and the README now give the order the library
  actually evaluates in — allow, mark, record, challenge, redirect, block — and
  say that mark and record do not end evaluation. The README said
  "a match ends evaluation" of all six. The rule list names a record rule
  *Record (serve, then refuse next time)* and a mark rule *Mark (serve, and
  signal)*.
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

- **A redirect rule redirects in `exception` mode.** The outcome responder had
  no branch for the library's redirect outcome, so it fell through to being
  treated as a firewall failure: the visitor was served the page the rule was
  written to send them away from, and an evaluation error was logged on every
  request it matched. It now answers with the rule's destination and status —
  302 unless the rule says otherwise — and `Cache-Control: no-store`, as the
  library does in blocking mode. The wp-config.php path still fails open on
  every `exception` mode outcome, as before, and says so.
- The README said a rate limit "cannot depend on who is asking". Since
  `kanopi/firewall` 2.27.0 a limit line can count an account, a header or a
  field instead of the address, and the rule screen has offered it; what a
  limit still cannot do is give different visitors different allowances. The
  README now documents the fourth field, and why an identity-keyed limit
  catches the opposite attack to an address-keyed one and never bans.

- Several hour ranges in an activity window, separated by commas, are compiled
  as a list. They were handed to the library as typed, which reads one string as
  one range, refuses the line as malformed, and does not start the rule. A
  timezone chosen with nothing else is no longer written as a window that
  restricts nothing, and every day ticked is written as no restriction rather
  than seven days.
- An activity window is only offered where the library keeps it. On an older
  library the window is kept rather than cleared by an unrelated edit, and the
  compiler skips a scheduled rule — and one whose imported window the library
  cannot read — and says so, rather than letting it run at all hours or fail
  unnamed.

- A redirect rule naming nowhere, or a destination beginning `//`, is refused.
  The library does not reject either when it loads — an empty destination
  throws when the rule matches, turning each of those requests into a firewall
  error that is failed open on. The rule screen refuses to save one, and the
  compiler skips one that arrived by import or WP-CLI and says so. A URL rule
  redirecting into its own path conditions is saved with a loop warning. Mark
  names and mark headers are checked for characters the site's own code could
  not address.
- The request tester reports a redirect rule as **Redirected**, with the
  destination and status, instead of "could not be tested" — a redirect in
  `exception` mode is an exception it did not know by name. A record or mark
  rule that fired is reported as **Served, and recorded for next time** or
  **Served, and marked**, rather than "No rule matched this request".
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
