# Changelog

All notable changes to this plugin are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0]

First release. The WordPress port of the Drupal module `basic_firewall`, at
parity with its 2.0.0-beta9, built on `kanopi/firewall` ^2.33.1. The release zip
bundles 2.33.1, namespace-scoped. Requires WordPress 6.4 and PHP 8.1.

It installs in log-only mode with no rules, so nothing is refused until you say
so. The README explains every feature below, and — as the module does — what
does not work as well as what does.

### Added

- **Nine rule types**: IP address, Request / URL, user agent, rate limit, edge
  signal, ASN, geolocation, IP reputation (AbuseIPDB) and the OWASP Core Rule
  Set. Each has its own form, validation, compilation and
  library capability detection, so a type the installed library cannot run is
  not offered rather than compiled into something that matches nothing. Other
  plugins can add types through the `basic_firewall_rule_types` filter.
  - An IP address rule can reference published lists by URL instead of carrying
    copies, refreshed on WP-Cron and fetched off the request path.
  - A user agent rule can verify a crawler by reverse and forward DNS, so an
    allow rule for `bot equals true` is not a skeleton key for anyone who types
    `Googlebot/2.1`. Fails closed.
  - A rate limit line can count an account, header or field instead of the
    address. That catches a botnet against one account, misses one client
    walking a list of usernames, and never bans — so the screen and Site Health
    warn when one has no address-keyed limit beside it.
  - The edge signal type matches what the CDN worked out that the site cannot:
    a JA3 or JA4 TLS fingerprint, or the bot score, from Cloudflare, Fastly or a
    custom CDN. Believed only behind a trusted proxy.
  - Every setting of every type, and every site-wide setting, is proved in CI
    against the library that enforces it: the compiled file is loaded, and the
    library's own objects are asked what they ended up with, or a request is
    evaluated. A setting with no such test fails the build.
- **Six responses**, evaluated in this order: allow, mark, record, challenge,
  redirect, block. Mark and record do not end evaluation. Whether a match is
  written to the durable block list is a separate, per-rule choice, which is
  what a honeypot needs (record without refusing) and what a lockdown needs
  (refuse without recording).
- **Observe only**, per rule, so one rule can be tried on live traffic while the
  rest keep enforcing. Matches are logged and counted apart on the Log screen.
- **Activity windows**, per rule, in the rule's own timezone. The rule list says
  whether a scheduled rule is awake and until when, because a sleeping rule
  looks exactly like a broken one from outside.
- **Two evaluation paths.** An mu-plugin, installed on activation and removed on
  deactivation, runs at `muplugins_loaded` with no configuration. The installed
  copy is replaced when a release ships a different one — on update, on the
  first admin, cron or WP-CLI request after the loader's version changes, and
  from Site Health — atomically, and never recreated once removed. An optional
  `wp-config.php` bootstrap runs before `advanced-cache.php`, so a page cache
  hit is evaluated too. The bootstrap calls no WordPress API; database block
  storage works there when the snippet sits below the `DB_` constants. In
  `exception` mode the bootstrap answers blocks, lockdowns, redirects and
  challenges itself, with the plugin's own responder, rather than leaving them
  for the mu-plugin — which runs after a page cache has served the page.
- **Fifteen admin screens**: fourteen under the **Firewall** menu — Status,
  General, Storage, Rules, Logging, Challenge, Presets, Advanced, Log, Blocked,
  Compiled, Export, Import and Test — and the rule editor, reached from Rules,
  with its type chooser. The Test screen evaluates a made-up request against the
  live rules without recording anything.
- **Block list storage** in files, the database or Redis. Redis stores each
  block with a TTL, so expiry costs nothing. Database tables carry the site's
  table prefix, so sites on a network do not share a block list.
- **A cache backend** for parsed user agents and reverse-DNS verdicts: files,
  the WordPress object cache (only where it is persistent) or APCu. The parsed
  configuration and imported list bodies move with `BASIC_FIREWALL_CACHE_DIR`,
  which both evaluation paths read. The 1.7 MB agent detection corpus is built
  on WP-Cron after every rebuild, and on demand from the Storage screen or
  WP-CLI, so a deploy does not leave the first visitor to pay for it.
- **Logging** through Monolog, because it runs before WordPress's logger
  exists: a file, rotating files, the PHP error log or a database table, which
  the Log screen reads back. Any handler can send after the visitor has their
  response.
- **Challenges**: arithmetic, ALTCHA proof of work, Cloudflare Turnstile and
  Google reCAPTCHA.
- **Presets** from the library, included by reference so they update with it.
  The library's `wordpress` preset is withheld, because on a WordPress site it
  locks every administrator out.
- **Incident tools.** Lockdown refuses every client but an allowlist (addresses,
  CIDR blocks or `start-end` ranges), before any rule is consulted, and records none of them — so lifting it does not leave a
  block list full of customers. A panic file changes the operating mode on the
  next request, on both paths, without a deploy. `BASIC_FIREWALL_ENABLED` and
  `BASIC_FIREWALL_MODE` in `wp-config.php` need no database at all. Unticking
  **Enable the firewall** stops both paths as well: it is compiled as
  `mode: disabled` and mirrored into a `runtime.json` sidecar the
  `wp-config.php` path reads, so a pinned mode cannot switch it back on.
- **Fifteen WP-CLI subcommands** under `wp basic-firewall`: `status`, `rules`,
  `rebuild`, `sources`, `refresh-sources`, `check`, `block`, `unblock`,
  `blocked`, `clear-blocked`, `clear-cache`, `warm-cache`, `find-reference`,
  `export` and `import`.
- **Seventeen Site Health tests**: lockdown, panic switch, library, backends,
  compiled configuration, crawler verification, rate limit keys, private
  directory, wp-config.php snippet, evaluation point, client IP, operating mode,
  block list storage, cache, logging, block records and upgrades. Anything
  critical is also raised as an admin notice. The evaluation point test is
  critical when the `wp-config.php` path is in `exception` mode and cannot
  answer refusals before a page cache.
- **Hooks.** Every decision is announced as `basic_firewall_decision`, with its
  kind, and as `basic_firewall_decision_{$type}` — `allowed`, `blocked`,
  `challenged`, `challenge_solved`, `challenge_failed`, `recorded`,
  `redirected`, `marked`, `tarpitted`. They are held until `plugins_loaded` so a
  regular plugin hears them; a refusal is announced at shutdown, and a refusal
  on the `wp-config.php` path is never announced, because WordPress never loads.
  Also `basic_firewall_request_marked` and `Runner::is_marked()`,
  `basic_firewall_request_ended`, `basic_firewall_compiled`,
  `basic_firewall_settings_saved`, `basic_firewall_activated` and
  `basic_firewall_upgraded`; and the filters `basic_firewall_rule_types`,
  `basic_firewall_presets`, `basic_firewall_private_path`,
  `basic_firewall_trusted_proxies` and `basic_firewall_config_overrides`.
- **Export and import**, of the whole configuration or one rule, from the admin
  screens or WP-CLI, with a preview or `--dry-run`. Credentials are stripped and
  the document says which; `%env()%` tokens survive; an empty credential on
  import means "not carried", never "set to nothing".
- **Three capabilities** — manage, view reports, unblock — so support staff can
  read the log and release a client without being able to change the rules.
- **Uninstall removes what the plugin wrote**, on every site of a network: its
  options, tables, scheduled events and capabilities; the private directory
  wherever it resolves; the block list, offense, counter and log files at every
  path the settings name; the file cache pools and what the library wrote into
  `BASIC_FIREWALL_CACHE_DIR`; the Redis block list and counters, by `SCAN` and
  `DEL` under their prefix; the object cache group and APCu entries. A stored
  path can point anywhere, so it deletes only inside a directory the plugin
  created or guards, never follows a symlink, and has WP-CLI print a warning
  for everything it leaves.
- **Schema upgrades** that are numbered, idempotent and advance one routine at a
  time, so an upgrade interrupted by a timeout resumes rather than corrupting
  settings. A failure is reported in Site Health, never fatal.
- **A release zip** that vendors the library namespace-scoped, so it cannot
  collide with another plugin bundling `kanopi/firewall`, and needs no Composer
  on the server. The build proves the scoped classes resolve before zipping,
  and CI installs the zip on a clean WordPress and makes it refuse a request
  before publishing it to GitHub Releases on a version tag. It installs with
  one WP-CLI command from `releases/latest/download/basic-firewall.zip`, a URL
  that always means the current release. Composer installation works too,
  unscoped.

### Removed

- **The vulnerability score rule type**, before release. It saved a threshold
  and weights that the library's `VulnerabilityScore` plugin never reads — it
  scores with its own `scoring.*` signals and matches on `risk_levels` — so the
  rule matched nothing. It is withdrawn until it is rebuilt on that model. A
  rule saved by a pre-release build is kept, skipped, and named on the Status
  screen and in Site Health.

### Security

- The private directory is created with `.htaccess`, `web.config` and
  `index.php` guards, given a random per-site name, and then **probed over HTTP**
  rather than assumed protected. On nginx the first two guards are inert, which
  Site Health reports as an error and gives the server snippet for.
- WordPress's database credentials are never written into the compiled
  configuration. They are injected at request time, so an export cannot leak
  them, no plaintext password reaches disk, and a rotated password takes effect
  on the next request.
- Only the library's `file` secret processor is ever enabled, never `require`,
  which would turn an environment-variable injection into remote code execution.
  `%file()%` is off until `BASIC_FIREWALL_SECRET_DIRECTORIES` names where it may
  read.
- A trusted proxy may set `X-Forwarded-For`, `-Proto` and `-Port`, but not
  `-Host`, because a forwarded host is how cache poisoning and malicious
  password-reset links start.
- Destructive WP-CLI commands refuse to run without `--yes` and exit non-zero
  when they refuse, rather than exiting 0 having done nothing.
- An export strips a referenced list's credentials on every rule type that takes
  a list — `upstream.auth` and every `upstream.headers` entry — and replaces a
  credential in a list URL with `***`, naming each path in its header.
- An import keeps a stored credential the document left out only while the
  host, port, account or URL it belongs with is unchanged; otherwise it is
  blanked and the preview says so. Credentials follow their rule by identifier.
- A rate limit rule's Redis password and DSN are never rendered into its edit
  form; blank keeps the stored value and a box removes it. Limits and counter
  storage have their own controls, so saving the form unchanged stores what was
  there.
- The Compiled screen shows every credential in the compiled file as
  `[redacted]`; the file itself keeps them for the library.
- A user agent rule that asks to verify crawlers but is left with no domain to
  accept — an import or WP-CLI drops `*.googlebot.com` and keeps the verify flag
  — is skipped when the configuration is compiled and reported on the Status
  screen and in Site Health, never compiled as a plain agent match that lets
  anyone sending `Googlebot/2.1` past an allow rule.
- An `X-Firewall-Mark` header sent by the client is removed before evaluation on
  both paths, so `$_SERVER['HTTP_X_FIREWALL_MARK']` is only ever a mark the
  firewall applied.
- After a solved challenge in `exception` mode the visitor is sent only to a
  path on this site, rebuilt from the posted destination's path and query. A
  destination holding a control character or whitespace, raw or
  percent-encoded, or that a browser would read as `//` once its backslashes
  are slashes, is replaced with `/`, so `/<tab>/evil.example` cannot become
  `//evil.example`.

### Upgrading from a pre-release build

Only for a site that ran a development copy before 1.0.0. A new install can skip
this.

- **Stored settings are rewritten on the first request after the update**, and
  the configuration is recompiled. The routines:
  - Paths lose Drupal's `private://` prefix. A relative path now resolves
    inside the private directory; the old spelling still resolves anywhere the
    upgrade did not reach.
  - A regular expression is stored as its body rather than `#body#i`, and the
    `i` flag becomes the condition's case-sensitivity box, so no rule narrows.
  - Geolocation and ASN condition variables take the library's names:
    `country_name`, `timezone`, `latitude`, `longitude` and `organization`
    become `country.name`, `location.timeZone`, `location.latitude`,
    `location.longitude` and `asn_org`. Before this those conditions matched
    nothing. A condition on the ASN `network`, which has no library equivalent,
    is kept rather than dropped — dropping it would widen an "all" rule — and
    reported on the rule and the Status screen.
  - `storage.record_request`, new in library 2.31.0, is filled in.
- **Translated at compile time rather than rewritten**, so stored rules work
  without being edited: the operators `gt`, `gte`, `lt`, `lte` and
  `not_contains`, which the library does not know and which matched nothing;
  and the geolocation and ASN reader settings, which compiled to keys the
  library never read. So did these, each now compiled to the key the library
  reads:
  - Challenge provider options, which went nowhere. Turnstile or reCAPTCHA with
    any challenge rule stopped the firewall starting, and the plugin failed
    open. "Let the visitor through" if verification is unreachable is now
    honoured, and a timeout above 10 seconds is written as the 10 the provider
    allows.
  - The Core Rule Set's inbound and outbound thresholds, which were always 5
    and 4.
  - A user agent rule's choice of what `bot` consults, which was always the
    curated database.
  - AbuseIPDB's report age, which was always 30 days whatever the screen said.
  - A database-backed rate limit's table, which was always the library's
    unprefixed `firewall_rate_limit_storage`.
  - An IPv6 `start-end` range on an IP address rule, which matched nobody. It
    is compiled as the CIDR blocks covering the same addresses.
  - A referenced list declared as XML, which stopped its rule constructing. XML
    is no longer offered; the format is detected from a `.xml` URL instead.
  - A database log handler connecting with individual parameters, which was
    compiled with no connection.
- **Check by hand**:
  - A database-backed rate limit counted into `firewall_rate_limit_storage`,
    without the site's table prefix. It now counts into
    `{prefix}basic_firewall_ratelimit`, so counters start again. Drop the old
    table once nothing else using kanopi/firewall on that database needs it;
    uninstall names it but will not drop it.
  - A rate limit's status code field is gone. The library always answers 429,
    whatever it said.
  - **Seconds added when a blocked client returns** can no longer be 0, which
    the library read as 3600. A stored 0 is reported until it is changed.
  - A user agent rule saved from the rule screen in a pre-release build has
    **Cache agent detection** switched off, because the screen never posted it.
    Tick it and save, or each PHP worker pays about 618 ms on its first request.
  - A geolocation or ASN rule saved from its own screen may have lost its reader:
    a CDN-backed rule could have been put back on a database, and a custom header
    mapping could have lost its field names.
- **The mu-plugin loader refreshes itself.** A pre-release copy states no
  version, so the first admin, cron or WP-CLI request after the update replaces
  it with 1.0.0's, as does updating through the WordPress updater or opening
  Site Health. No deactivating and reactivating. Until then the older copy
  still works; on the `wp-config.php` path it answers a solved challenge at
  `plugins_loaded` rather than `muplugins_loaded`. If mu-plugins is not writable,
  Site Health says the loader is out of date and why; copy
  `mu-plugin/basic-firewall-loader.php` over it by hand.
- **Uninstall only removes directories carrying `.basic-firewall-owner`**,
  which is written only by 1.0.0. A directory a pre-release build created
  outside uploads — a filtered private path, or `BASIC_FIREWALL_CACHE_DIR` — is
  emptied of the plugin's files and left in place.
- A Composer install needs `kanopi/firewall` ^2.33.1.
