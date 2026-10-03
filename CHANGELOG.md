# Changelog

All notable changes to this plugin are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0-rc.8]

**Eighth release candidate for 1.0.0.** Published as a GitHub pre-release, so
the `releases/latest/download` URL does not serve it; install it by its own URL.
It bundles kanopi/firewall 2.37.0. The challenge, block and lockdown pages can
now carry the site's own wording, language and styling, a client asking for
JSON can be answered with JSON, and old log rows are deleted in batches. Sites
with a database log handler should run `wp basic-firewall migrate` once: read
*What changes on upgrade*. What changed since 1.0.0-rc.7 is below.

### What changes on upgrade

- **Existing database log tables need two new indexes.** kanopi/firewall 2.37.0
  indexes the log table by rule, in both orders
  ([kanopi/firewall#458](https://github.com/kanopi/firewall/issues/458)), but
  the library never alters a table it has already created. Until the indexes
  are added, the firewall's own log warns "Database table is behind the schema
  this release declares". Run `wp basic-firewall migrate --dry-run` to see what
  is missing, then `wp basic-firewall migrate`, or press **Add missing table
  indexes** on the Logging screen. Building an index locks the table, so do it
  at a quiet moment. A site without a database log handler has nothing to do.
- **The parsed configuration is now reused on web requests.** Before 2.37.0
  the library fingerprinted per-request environment values, so under PHP-FPM
  every request missed the parse cache, parsed the compiled file again and
  rewrote the cache entry
  ([kanopi/firewall#445](https://github.com/kanopi/firewall/issues/445)). No
  setting changes.
- **Old log rows are deleted in batches.** With retention set, the library
  used to delete the whole backlog in one statement inside a visitor's request.
  It now deletes up to 10 batches of 1,000 rows per write by default
  ([kanopi/firewall#459](https://github.com/kanopi/firewall/issues/459),
  [#464](https://github.com/kanopi/firewall/issues/464)).

### Changed

- **Requires and bundles kanopi/firewall 2.37.0** (from 2.36.1).

### Added

- **The challenge page's wording and styling.** The Challenge screen sets the
  page's tab title, heading, intro line, button label and error message, plus
  its own language, CSS and stylesheet
  ([kanopi/firewall#451](https://github.com/kanopi/firewall/issues/451)). A
  field left empty keeps the built-in wording. The page's CSS is added after
  the shared Page appearance CSS; its language or stylesheet replaces the
  shared one.
- **Notices on the challenge page.** One per line on the Challenge screen,
  each shown in its own box above the form: a help address, or why visitors
  are being asked (`challenge.notice`, library 2.35.0).
- **Block and lockdown pages.** The General screen can switch on an HTML page
  for a blocked client, using the banning message as its text, and for a
  visitor refused by lockdown, with its own message. Both have their own title
  and heading, and both are sent with a strict Content-Security-Policy
  ([kanopi/firewall#452](https://github.com/kanopi/firewall/issues/452)). Off,
  the refusal is the plain-text message, as before.
- **Page appearance.** The language tag, extra CSS and a stylesheet on the
  General screen apply to the challenge, block and lockdown pages alike. Every
  colour on them is a `--fw-*` CSS custom property
  ([kanopi/firewall#454](https://github.com/kanopi/firewall/issues/454)).
  A value the library would refuse to start on is refused when it is saved,
  in the library's words. A value that arrives by import or a hand edit is left
  out of the compiled file instead, so a typo in a colour can't switch the
  firewall off.
- **JSON for API clients.** With **JSON for API clients** ticked, a client
  whose first preference is JSON gets `{"error":"blocked",…}` instead of the
  page or the message.
- **`{{block.status}}` and `{{block.rule}}`** in the banning message.
- **`wp basic-firewall migrate`** and the **Add missing table indexes** button
  on the Logging screen. They add the columns and indexes the firewall's
  tables are missing (block list, rate-limit counters, database log handlers),
  and nothing else. This is the plugin's equivalent of the library's
  `bin/firewall-migrate`.
- **Retention batch settings** on a database log handler: rows per delete and
  most deletes per write.

### Fixed

- **In `exception` mode, a block page or a JSON answer is sent as the library
  built it.** The responder used to escape the library's message into a page
  of its own, which would have shown a block page's HTML as source and given
  an API client HTML. It now sends the library's content type, plus the
  Content-Security-Policy for a page.

## [1.0.0-rc.7]

**Seventh release candidate for 1.0.0.** Published as a GitHub pre-release, so
the `releases/latest/download` URL does not serve it; install it by its own URL.
It bundles kanopi/firewall 2.36.1: Request / URL rules can count query
parameters with `query_count` (for capping facet crawling), and equality on a
number compares as a number, so a referenced list on `port` or `query_count`
works as written. Read *What changes on upgrade*. What changed since
1.0.0-rc.6 is below.

### What changes on upgrade

- **Equality on a number from a referenced list starts working.** kanopi/firewall
  2.36.1 compares a numeric entry with a number by value
  ([kanopi/firewall#443](https://github.com/kanopi/firewall/issues/443)), so a
  list-backed *is equal to* / *is one of* on `port`, `query_count` or a numeric
  geolocation field matches, and *is not equal to* no longer matches every
  request. Conditions typed into a rule were already compiled as numbers by the
  plugin and behave as before. A list-backed equality the plugin refused before
  2.36.1 (see Fixed) is now accepted.

### Changed

- **Requires and bundles kanopi/firewall 2.36.1** (from 2.35.1). 2.36.0 adds the
  opt-in `query_count` variable; 2.36.1 makes equality on a number compare as a
  number (see *What changes on upgrade*).

### Added

- **`query_count.<name>` and `query_count` in Request / URL rules.** How many
  values the client sent for one query parameter, or with the Name left
  blank, how many parameters in all — counted from the raw query string, so
  `f[0]=`, `f[]=`, sparse or named keys, a repeated `f=` and encoded brackets
  all count the same. Offered on the rule screen as one family with an
  optional name; `query_count.` with nothing after the dot is refused. The
  library compares equality strictly, so a count is compiled as an integer
  for *is equal to*, *is not equal to* and *is one of* (each entry), and for
  the greater/less-than comparisons too; a value that is not a whole number is
  refused on save. The README has a *Stop facet crawling* example
  (`path` starts with `/search` and `query_count` / `f` is greater than 3,
  response **challenge**).
- **`query_count` and `query_count.<name>` as rate-limit key components**,
  the name kept in the case it was written, as the library reads it.

### Fixed

- **A referenced list compared for equality with `port` or `query_count` can
  no longer fail silently.** Both are numbers to the library, and a list's
  entries arrive as text. Before kanopi/firewall 2.36.1 the library compared
  the two strictly, so "port is one of" a list never matched and "is not equal
  to" a list matched every request (on a block rule, every visitor). With the
  bundled 2.36.1 such a list works as written. On an older library, for
  example one supplied by a site's own Composer tree, the plugin refuses the
  rule on the rule screen, naming the alternatives (greater / less than, a
  regular expression such as `^(8443|9443)$`, or the values typed into a
  condition). It also skips a rule that arrives by import, WP-CLI or a hand
  edit and names it on the Status screen and in Site Health. The plugin
  decides by probing the library rather than trusting a version, and also
  checks a shorthand template such as `port@equals:{value}`
  (kanopi/firewall#443).

## [1.0.0-rc.6]

**Sixth release candidate for 1.0.0.** Published as a GitHub pre-release, so
the `releases/latest/download` URL does not serve it; install it by its own URL.
The vulnerability score rule type is back, rebuilt on the library's own
scoring model (#52); latitude/longitude equality matches against a database
(#49); condition values are stored as typed, so `<` and `%xx` survive a save
(#60); and the unused geolocation license key is removed (#54). Read *What
changes on upgrade* for the two settings rewrites. What changed since
1.0.0-rc.5 is below.

### What changes on upgrade

- **Vulnerability score rules saved by a pre-release build are translated**
  (schema 12). A rule with a threshold and no weights becomes one risk level
  that matches at that threshold, with the new type's default scores, and
  keeps its response and whether it was on — so a rule that matched nothing
  starts matching. A rule with weights has no equivalent in the library's
  scoring, so it is kept as it was, switched off, and named on the Status
  screen, in Site Health and in the rule list until you set its scores or
  delete it.
- **Latitude/longitude *is equal to*, *is not equal to* and *is one of*
  start working against a MaxMind database** (#49). *Is not equal to* stops
  matching every visitor.
- **The geolocation and ASN license key is deleted** (schema 13, #54). Every
  stored copy is removed from the rules that held one; nothing read it, so no
  rule changes what it matches.

### Added

- **The vulnerability score rule type is back, rebuilt on the library's
  scoring model** (#52). Withdrawn from 1.0 because it saved a threshold and
  weights the library's `VulnerabilityScore` plugin never reads. It now
  stores exactly what that plugin reads: risk levels (a threshold, whether
  the rule matches there, and an optional status code and ban length per
  level) and scores for the request method, attack patterns, user agent,
  country and network, with a MaxMind Country and ASN database opened only
  when a score needs one. Defaults are a working subset of the library's
  `malicious-requests` preset. The form refuses what the library would
  reject or silently ignore: a regex without matching delimiters or that
  does not compile, an unknown location or match type, a matching level at
  zero or below, duplicate level names or thresholds, a pass level above a
  matching one, and country or network scores without a database. Every
  field is covered by the honoured-settings tests against the real library.
  See "What changes on upgrade" for rules saved by a pre-release build.

### Fixed

- **Latitude/longitude *is equal to*, *is not equal to* and *is one of*
  match against a MaxMind database** (fixes #49). The record holds floats,
  the value compiled as text, and the library compares these operators
  strictly (2.35 coerces only the ASN), so *is equal to* never matched and
  *is not equal to* matched every visitor. A database-backed geolocation
  rule now compiles those values as numbers; a CDN-backed one sends text
  and is compiled as before. Rules need no change.

- **Patterns keep `<` and percent-encoded characters through the rule
  screen.** The textarea sanitiser stripped both from the vulnerability
  score's patterns on every save; fields a type marks `verbatim` are now
  read as typed, and still checked by the type's validator.

- **Condition values are stored as typed** (fixes #60). The rule screen put
  every condition value through the textarea sanitiser, which turns `<` into
  `&lt;` or strips it with whatever follows, and deletes every `%xx`
  sequence, so a URL rule on `query.q contains %3Cscript` was stored as a
  rule on `script` and one on `path contains %2e` was refused for having no
  value. Condition values on every condition rule type (URL, user agent,
  geolocation, ASN, edge signal), the fields of a referenced list, and
  rate-limit lines are now read as typed, with only control characters
  removed and whitespace at either end trimmed (as before, so a pasted
  trailing space can't leave a block rule matching nothing; a regex can still
  match a leading or trailing space with `\s`); the rule type's validator
  checks them (operator, regex, UTF-8, at most 4,096 characters). The pasted document on the Import and Rules
  screens, the Advanced YAML box and the Test screen's path, user agent,
  headers and body are read the same way. A value that contains an entity,
  such as `&lt;`, now survives being saved again untouched.

### Removed

- **The MaxMind license key field on geolocation and ASN rules** (fixes #54).
  It was kept "for whatever downloads the database", and nothing did: the
  firewall only ever opens a local database. The stored value is deleted on
  upgrade (see above), and an imported document that still carries it is
  imported without it, with a note in the preview.

## [1.0.0-rc.5]

**Fifth release candidate for 1.0.0.** Published as a GitHub pre-release, so
the `releases/latest/download` URL does not serve it; install it by its own URL.
It adds diagnostics for the wp-config.php early path, readable from WP-CLI and
Site Health, so a host where the web containers behave differently from WP-CLI
(#34) can be diagnosed: the last web request's report and the last anomaly,
failed rules and mode/compiled-file mismatches, and every fail-open logged
(rate-limited) to the PHP error log. It keeps credentials out of the Advanced
YAML box and exports, and lets the Redis password stay out of the compiled
file through `BASIC_FIREWALL_REDIS_PASSWORD` (#47, #48). The early path no
longer loads a second Composer autoloader when the library is already loaded
(#44). It bundles kanopi/firewall 2.35.1, which **changes what some existing
rules do** (ASN equality, path normalisation, presets at any depth, rate-limit
case): read *What changes on upgrade* first. The "verification cookie did not
come back" notice now shows in `block` mode too (#46). What changed since
1.0.0-rc.4 is below.

### What changes on upgrade

This release bundles kanopi/firewall 2.35.1. Several of its fixes change what
an existing configuration does:

- **ASN equality rules start matching.** An ASN rule with *is equal to* or
  *is one of* (`16509`, `AS16509`) never matched before; a block rule on a
  network now blocks it. **An ASN *is not equal to* X rule stops matching
  network X** — it used to match every visitor, X included. Check your ASN
  rules, especially negated ones.
- **The path every rule sees is normalised.** Doubled slashes, `.` segments
  (raw or `%2e`), percent-encoded unreserved characters and `;params` no
  longer change what a rule or rate limit matches; `..` is kept as written.
  The log and block records show the normalised path.
- **The WordPress presets are at Preset-Version 2.** `search-bots.yml` (and
  `wordpress.yml`, which this plugin does not offer on a WordPress site)
  match WordPress's paths at any depth: **wider** (a subdirectory install,
  core in its own directory, `readme.html` anywhere) and slightly
  **narrower** (a slug that merely starts with `wp-login` or `wp-admin`, such
  as `/wp-login-help/`, is no longer treated as the login or the admin).
- **Rate-limit paths ignore case**, as URL rules already did: a
  `/wp-login.php` limit also counts `/WP-LOGIN.PHP`. A pattern written as a
  regular expression keeps its own flags.
- **Redirect targets with a raw control character or whitespace go to `/`**
  after a solved challenge, as does anything a browser would read as `//`.
- **`firewall-check --lint` may warn about a rate-limit entry that never
  runs** because an earlier entry in the same rule covers it. The rule screen
  now says the same.
- **The logged URL of a directly requested file loses its stray trailing
  `/`** (`/wp-login.php`, not `/wp-login.php/`), matching the block record.

### Added

- **The rule screen warns about a rate-limit line that can never run**
  because an earlier line in the same rule covers it (`/log*` before
  `/login`, `/login` before `/LOGIN`), naming the line that takes its
  requests: the cases `firewall-check --lint` reports from 2.35.1. The rule
  still saves.

- **The "verification cookie did not come back" notice in `block` mode**
  (#46). A visitor challenged within two minutes of solving a challenge,
  carrying the `<cookie_name>_solved` marker but not the pass, is told why, as
  #37 did for `exception` mode. Decision_Dispatcher adds the line to the
  library's `RequestChallenged` event (kanopi/firewall 2.35.0), which the
  library renders above the form on its own page in `block` mode and puts in
  the render context's `notices` in `exception` mode, so both modes now share
  one implementation and the plugin no longer splices its own paragraph into
  the page. In `block` mode the library issues the pass itself, so the
  dispatcher also sets the marker when the library announces the solve. Both
  evaluation paths: the wp-config.php path reads the pass cookie's name from
  the runtime sidecar (a new `pass_cookie` key, written when the name is not
  the default). The library's `challenge.notice` has no Challenge-screen field
  yet; the Advanced YAML can set it.

- **Diagnostics for the early path, readable from anywhere** (#34). Every
  status screen described its own request, and WP-CLI's is not a web request:
  on a host that runs WP-CLI in its own container, `status` could report the
  early path evaluating while the web containers were not. The runner now
  saves a compact report of the last web request that reached WordPress, and
  separately of the last anomalous one (a fail-open, an early path that did not
  evaluate for a reason other than `disabled`, `switched-off` or
  `deferred-login`, or a refusal the early path handed on instead of
  answering), in transients kept for a day and written at most once every five
  seconds; WP-CLI and cron are never recorded. Each report carries both paths'
  view of the request (called, evaluated, reason, autoloader, verdict,
  failure with file:line), the mode each path's firewall was actually in, the
  library copy and version, the compiled file's path, modification time and
  hash prefix, and the cache backend on each path. No query string, cookies,
  headers or client address.
- **`wp basic-firewall early-report`** dumps both reports (JSON, or
  `--format=yaml`), and `wp basic-firewall status` gains **Last web request**
  and **Last anomaly** rows.
- **Site Health raises a recent anomaly** (under six hours old) on the
  evaluation check: critical for a request let through unfiltered in `block` or
  `exception` mode, or an unanswered early verdict; recommended for an early
  path that did not evaluate, with the fix for the reason.
- **`BASIC_FIREWALL_DEBUG`** adds an `X-Basic-Firewall-Early` response header
  with the compact report, on responses the early path writes and on requests
  that reach WordPress. Troubleshooting only, and off by default: it tells
  anybody who can make a request how the firewall is deployed.

- **Rules that failed to construct, per path** (#41). The library skips a rule
  whose constructor throws and carries on, so a rule failing only on the web
  containers showed up nowhere. Both paths now record their firewall's
  `getFailedRules()` as `bucket/Class:index` names (`failed_rules`; no
  messages) in the saved report, `early-report`, the `status` summary and the
  debug header. Sampled rather than asked on every request, because answering
  builds every rule and so defeats the library's lazy construction: each path
  asks with `BASIC_FIREWALL_DEBUG` on, on a request that failed open, or at
  most once a minute per container (a marker file, one stat when not due).
  The trade-off is that an intermittent failure can fall between samples.
  `failed_rules_sampled` says why a request asked (`null` otherwise), and the
  latest sample from each path is kept apart and shown by `early-report`
  (`failed_rules_sample`) and `status` ("Failed rules (last sample)"). Any failed rule makes the request a new `failed-rules`
  anomaly, which Site Health raises as critical in `block` or `exception` mode
  and as recommended in `log` mode. Reports now also carry `anomalies`, every
  anomaly a request had, most serious first.

- **A `mismatch` anomaly** (#41). The report recorded the configured mode, the
  mode each path ran and each path's view of the compiled file, but a
  disagreement was not an anomaly, so the next ordinary request overwrote it.
  It is now flagged when a path's mode differs from the one the last compile
  wrote, or the compiled file's hash differs between the paths or from the last
  compile's — the signature of a stale copy on a container that did not do the
  compile — and kept in the anomaly slot; Site Health recommends a rebuild. A
  panic file, `BASIC_FIREWALL_MODE` and lockdown are reported under
  `mode.overrides` rather than flagged. The compile now records the hash prefix
  and mode of what it wrote in its meta, and the early path records the
  compiled file's hash prefix alongside its modification time.

- **`BASIC_FIREWALL_REDIS_PASSWORD`** (#48): the password for every Redis
  connection — block list storage and rate limit counters — supplied from
  wp-config.php and injected at request time on both evaluation paths, the way
  the `DB_*` credentials are. With it defined the compiled file holds no Redis
  password; the compiler records only where each connection's `auth` belongs,
  in the compile metadata and a `redis-auth-paths.json` sidecar (paths and ACL
  usernames, never a password). The Storage screen shows the field as set in
  wp-config.php while it is defined, and the rate limit editor says it is
  overridden.
- **Site Health: "Basic Firewall Redis password"** (#48). *Recommended* when a
  Redis password is written into the compiled file in plain text (define the
  constant or use `%env()%`), or when the constant was defined after the last
  rebuild; *critical* when the file was built with the constant and it has
  since been removed.

### Changed

- **Requires and bundles kanopi/firewall 2.35.1** (from 2.34.1). Several of
  its fixes change what an existing configuration does; see *What changes on
  upgrade* above.

- **`fail-open (early|runner)` log lines are rate-limited** (#41). They were
  written on every request, so a persistent failure on a busy site logged one
  line per request. The first is still always written; after that, at most one
  line a minute per exception class and file:line, and the next line written
  says how many were held back (`… (N more since <time> UTC)`). The state is
  kept in a marker file in the private directory, as the `not-evaluated`
  warning's is, so the limit holds across workers and containers; a marker
  that cannot be written means logging every time. The report still records
  every failure.

### Fixed

- **The rate-limit pairing check judges coverage by the line that runs**, as
  `firewall-check --lint` does from kanopi/firewall 2.35.1. On save and in
  Site Health, an identity-keyed line that an earlier line in its rule covers
  is no longer reported as unpaired (it never runs); a companion is the line
  of another enabled rule that actually takes the request, found with the
  library's `RateLimit::patternToRegex()`; paths are compared without regard
  to case; and a disabled rule never counts as coverage.
- **WordPress in its own directory: presets fire, and Site Health flags only
  the site's own rules** (#45). kanopi/firewall 2.35.0 made `wordpress.yml`
  and `search-bots.yml` match WordPress's paths at any depth, so the crawler
  allow no longer covers `/wp/wp-login.php`. Site Health's *request path*
  check no longer flags every enabled preset: it asks each of the site's own
  enabled rules whether it matches `/wp-login.php`, `/xmlrpc.php`,
  `/wp-cron.php` or `/wp-admin` at the root and misses it under the prefix
  (`equals`, `is one of`, `starts with`, a regular expression, a rate limit
  pattern; `ends with` and `contains` pass), and lists each by name. An
  enabled preset's rate limit on a bare core path, such as
  `rate-limiting.yml`'s `/wp-login.php`, is still named, since that preset
  is unchanged and rate limit patterns are anchored.
- **A `/wp-login.php` rate limit counts `/WP-LOGIN.PHP` too** (#50). On a
  case-insensitive filesystem the server runs `wp-login.php` for any casing,
  and `path` keeps the client's; rate-limit patterns now ignore case, as URL
  rules already did. Tests cover both, with the server values such a server
  sends.
- **Paths routed through `index.php` can no longer be spelled around a rule**
  (#51). The library normalises the path every rule sees, on both path
  sources, so `//wp-json/…`, `/./wp-json/…`, `/%2e/wp-json/…`,
  `/%77p-json/…` and `/wp-json;x/…` match a rule or rate limit on
  `/wp-json/`, as the direct-file spellings of #32 already did. `..` is kept
  as written. Covered in `PathSpellingTest`, over HTTP on the early path and
  end to end.
- **ASN rules are compared by the library as numbers, and the plugin's
  workarounds are gone** (refs #49). The type no longer casts a typed number
  to an integer or strips `AS` at compile time, and a list of numbers compared
  with *is equal to*, *is one of* or *is not equal to* is no longer compiled
  into a digits-only `#^16509$#` pattern: the library reads both sides as a
  number now. A list entry written `AS16509` is matched instead of skipped.
  Stored rules need no change. (Latitude/longitude *equals* is not part of
  this release.)

- **The block list screen and WP-CLI resolve a `%env()%` Redis password**
  rather than sending the token itself as the password (#48).

- **The early path no longer requires a second Composer autoloader when the
  library is already loaded** (#44). A site whose `wp-config.php` required one
  autoloader above the snippet while a different `vendor/` sat beside the
  WordPress root had that second one required too, so classes could resolve
  from either tree. "Library already loaded" is now asked before the fixed
  site locations: the order is the plugin's own `vendor/`, the `autoloader`
  option, `BASIC_FIREWALL_AUTOLOADER`, a library already loaded (`loaded`),
  then `dirname( ABSPATH ) . '/vendor'` (`site`). The plugin's scoped copy
  still wins, and a named autoloader that cannot be read still stops the
  search with `autoloader-unreadable`.
- **A firewall failure that fails open is now logged.** Anything other than a
  verdict that made either evaluation path let a request through — the library
  failing to start, or throwing partway through evaluating — was recorded only
  for Site Health on the request it happened on, which is a visitor's, so it
  left no trace (#34). Each now writes `Basic Firewall [warning]: fail-open
  (early)` or `(runner)` to the PHP error log, with the exception class, its
  message (credentials in a URL masked) and where it was thrown. The request
  still goes through: failing open is the design, failing silently was not.
- **An early path that is called and does not evaluate is logged**, at most
  once every 15 minutes per reason across every web container (a marker file in
  the private directory): `Basic Firewall [warning]: not-evaluated (early)`.
- **Uninstall removes the runtime sidecar from a pre-existing private
  directory** (#43). Where the `basic_firewall_private_path` filter names a
  directory the plugin did not create, uninstall removes only the plugin's own
  files from it, and `runtime.json` (written when the firewall is switched off
  in the admin or its mode pinned) was missing from that list, so it outlived
  the plugin. A directory the plugin created was always removed whole.

### Security

- **Credentials in the Advanced YAML are no longer shown or exported** (#47).
  The box was a free-form pass-through, outside the redaction #17 and #23
  applied, so a Redis password, API key, token or DSN typed there went back
  into the page and into every export in the clear. A value under a
  credential-shaped key (`*password*`, `*secret*`, `*token*`, `auth`,
  `api_key` and a few more; never a bare `key`), a credential header, and the
  password in a URL are now shown as `[redacted]`, and `%env()%`/`%file()%`
  tokens stay visible. A placeholder saved back unchanged keeps the stored
  value; one that moved, or whose host changed beside it, refuses the save
  rather than storing `[redacted]`. An export masks them and lists each as
  `advanced_yaml: <path>`; an import restores them from the receiving site's
  own block or drops and reports them, and names any credential an imported
  block carries in the clear. The Compiled screen hides them too.
- **The Redis password can be kept out of the compiled file** (#48), which
  lives under uploads and is web-readable on some servers: define
  `BASIC_FIREWALL_REDIS_PASSWORD` (injected at runtime, never written) or use a
  `%env()%` token (only the name is written). A password typed literally is
  still written, because the wp-config.php path cannot read the settings, and
  Site Health now recommends against it.

## [1.0.0-rc.4]

**Fourth release candidate for 1.0.0.** Published as a GitHub pre-release, so
the `releases/latest/download` URL does not serve it; install it by its own URL.
It hardens `exception` mode on the wp-config.php path so a verdict can never
serve the page (#34), makes the pass cookie name a setting both evaluation
paths honour (#35), and bundles kanopi/firewall 2.34.1, which keeps every
response the library writes out of caches. What changed since 1.0.0-rc.3 is
below.

### Changed

- **Requires and bundles `kanopi/firewall` 2.34.1** (was ^2.34). The release
  zip bundles 2.34.1, namespace-scoped. In `block` mode the library answers
  itself, and every response it writes now carries the full no-cache set
  ([kanopi/firewall#417](https://github.com/kanopi/firewall/issues/417),
  [#418](https://github.com/kanopi/firewall/pull/418)): the challenge
  interstitial, block pages (which sent no cache header at all), lockdown,
  redirects, and the challenge-verify JSON that sets the pass cookie (none
  either). The interstitial ignores a double submit while one is in flight.
  A spent challenge solution coming back from a different client, which is
  what a cached challenge page looks like, is now logged at warning; the
  same client twice stays at info. No configuration changes.
- **The mu-plugin loader is 1.2.0**; the plugin replaces the installed copy
  on the next admin, cron or WP-CLI request. See Fixed.
- **The pass cookie name set on the Challenge screen is now what both
  evaluation paths issue and check** (#35). The compiled file always names
  the cookie explicitly (the field's value, trimmed; `bfw_pass` by default)
  rather than leaving it to the library's default, and in `exception` mode
  the runner sets the pass under the compiled name instead of re-reading
  settings. The field is required: an empty or malformed name is refused
  with a notice and nothing is saved. Upgrade routine 11 recompiles on the
  first request after updating. **Changing the name invalidates passes
  already issued**, so each visitor holding one is challenged once more.

### Fixed

- **A solved challenge that keeps being challenged is now explained in
  `exception` mode** (#35). Some hosts or edge caches only forward cookies
  whose names match their own rules, so the pass never comes back; the fix
  is to set a name the host forwards (see Changed, and the README). A
  visitor challenged within two minutes of solving one, without the pass, is
  now told the verification cookie did not come back, and a warning is
  logged. It uses a short-lived, unsigned marker cookie named after the pass
  cookie (`<name>_solved`), so a prefix chosen for the host applies to it
  too; the interstitial stays no-store. `block` mode is unchanged, because
  the library renders that page itself.
- **An `exception` mode verdict on the wp-config.php path can no longer
  serve the page** (#34). Every route by which the early path could fail
  open on a challenge, redirect or block now ends in a plain 503
  "Verification required" refusal instead: the responder throwing (the
  verdict used to be handed to the runner, which runs after a page cache, or
  not at all), the responder returning as though the request may continue
  (it used to return `true` straight to wp-config.php), the responder
  missing from the plugin copy, and a verdict thrown by the other library
  copy (scoped or unscoped), which the responder took for a firewall failure
  and let through. Each is logged to the PHP error log at warning. The runner
  also refuses, and reports to Site Health, any request the early path
  recorded a verdict on and did not answer, so an older `bootstrap.php`
  still required from wp-config.php cannot fail open silently; the mu-plugin
  loader (now 1.2.0) loads the plugin for that case. The report's exact
  setup, a per-rule ALTCHA challenge on a WordPress-routed page, did not
  reproduce locally on DDEV in either the zip or a Composer install; it is
  now covered over HTTP.
- **Every response the plugin writes carries the full no-store set** from
  [kanopi/firewall#418](https://github.com/kanopi/firewall/pull/418):
  `Cache-Control: private, no-store, no-cache, must-revalidate, max-age=0`,
  `Pragma: no-cache`, `Expires: 0`, `Surrogate-Control: no-store` and
  `CDN-Cache-Control: no-store`, each replacing any earlier header of the
  same name. That is the challenge interstitial, block, lockdown and redirect
  answers, and the solved-challenge JSON and redirect. They carried only
  `no-store` and `Pragma`, which Pantheon's edge caches anyway. The set is
  the library's `NoStore::HEADERS`.

## [1.0.0-rc.3]

**Third release candidate for 1.0.0.** Published as a GitHub pre-release, so
the `releases/latest/download` URL does not serve it; install it by its own URL.
The headline is #30: rules now see the path of a directly requested PHP file
(`wp-login.php`, `xmlrpc.php`, `/wp-admin/*.php`), which they did not before.
What changed since 1.0.0-rc.2 is below.

### Changed

- **Requires and bundles `kanopi/firewall` 2.34.0** (was ^2.33.2). The release
  zip bundles 2.34.0, namespace-scoped. It adds `global.path_source` and
  `global.base_path`, which the fix below uses
  ([kanopi/firewall#414](https://github.com/kanopi/firewall/issues/414),
  [#415](https://github.com/kanopi/firewall/pull/415)), and stores a direct
  file's URL in block records without a trailing `/`.
- **`bot equals true` now matches Nikto.** 2.34.0 requires
  `matomo/device-detector` ^6.5.2, which adds Nikto's default agent to the
  curated bot database. The rule screen, README and readme.txt no longer list
  Nikto among what `bot` misses. sqlmap, curl and python-requests still need
  `automated`.
- **With WordPress in its own directory** (Site Address `/`, WordPress Address
  `/wp`), WordPress's own files are matched with that directory:
  `/wp/wp-login.php`, `/wp/wp-admin/edit.php`. The front controller is the web
  root's `index.php`, so there is no base path to strip, and stripping `/wp`
  would need the raw-URL reading this release removes. Rules on those files
  need the prefix. Site Health recommends it when a rule or an enabled preset
  names them without it, and the Test screen defaults to `/wp/wp-login.php`.

- **A rule that matched `path` `/` no longer catches every directly requested
  file.** Before this release a direct `wp-login.php`, `xmlrpc.php` or
  `/wp-admin/*.php` request reached the rules as `/`, so `path equals /` (or a
  pattern that only `/` satisfied) matched all of them. It now matches the
  front page only. Check any rule written against what the old behaviour
  logged.

### Fixed

- **Rules now see the path of a directly requested PHP file** (#30). WordPress
  serves `wp-login.php`, `xmlrpc.php`, `wp-cron.php`, every `/wp-admin/*.php`
  screen and custom endpoints in the site root from the file itself rather than
  through `index.php`, and for those the library's `path` was `/`. A
  `/wp-login.php` rate limit never counted a login, a rule on `/wp-admin` or
  `/xmlrpc.php` never matched, a negated path condition matched every such
  request, and the log and block records said `path: /`. The compiled
  configuration now sets `global.path_source: script_name`, so `path` is the
  file the web server ran, on the wp-config.php path, in the mu-plugin
  (including logged-in requests deferred to `plugins_loaded`) and on the Test
  screen. `global.base_path` is compiled for a subdirectory install from the
  Site Address, or from the network's path on a multisite network, and the
  compiled file is rebuilt when either address changes. A challenge on a
  direct file posts its answer under the front controller's directory, through
  a compiled `challenge.submit_url`, so an admin screen's challenge is
  recognised. A Site Health check, *Basic Firewall request path*, asks the
  library what a direct `wp-login.php` request resolves to under the compiled
  settings. It is critical if `path_source: script_name` is missing, or if the
  login page or a page resolves to anything but itself. Schema routine 10
  recompiles every site on update.

  Because `path` is the file the web server ran rather than the URL as typed,
  a spelling the server normalises -- `/./wp-login.php`, `/%77p-login.php`,
  `//wp-login.php`, `/x/../wp-login.php`, `/wp-login.php;x` -- is matched as
  `/wp-login.php`, so none of them gets past a rule or rate limit on it.

## [1.0.0-rc.2]

**Second release candidate for 1.0.0.** Published as a GitHub pre-release, so
the `releases/latest/download` URL does not serve it; install it by its own URL.
What changed since 1.0.0-rc.1 is below; the full description of the plugin is
under 1.0.0-rc.1.

### Added

- **Naming the Composer autoloader for the wp-config.php early path.** An
  `'autoloader'` option to `basic_firewall_evaluate()`, and a
  `BASIC_FIREWALL_AUTOLOADER` constant, for a site-level Composer install whose
  `vendor-dir` is not beside the WordPress root. The option beats the constant.
  The plugin's own `vendor/` still comes first, so a release zip keeps running
  its scoped copy of the library whatever a site names.
- The snippet on the Status screen, in Site Health and in
  `wp basic-firewall status` carries the `'autoloader'` line when the plugin is
  running from a site-level Composer install whose autoloader the bootstrap
  would not find. The path is read off the library actually running, and
  written relative to `ABSPATH` when it is inside it.
- `wp basic-firewall status` warns with the reason when the wp-config.php
  snippet is present but not evaluating, and prints the snippet when the
  reason is a missing or unreadable autoloader.

### Changed

- **Requires and bundles `kanopi/firewall` 2.33.2** (was ^2.33.1). The release
  zip bundles 2.33.2, namespace-scoped.

### Fixed

- **A custom Composer `vendor-dir` left the early path doing nothing** (#26).
  The bootstrap looked only in the plugin's `vendor/` and beside the WordPress
  root, so a site with `"vendor-dir": "web/wp-content/mu-plugins/vendor"`
  always ended in `no-autoloader` and was evaluated after
  `advanced-cache.php`. It now also uses the autoloader the site names, and a
  library `wp-config.php` already loaded above the snippet.
- A named autoloader that cannot be read is reported as
  `autoloader-unreadable`, naming the file and whether the option or the
  constant named it, instead of falling through to the guessed locations.
- The `no-autoloader` reason in Site Health and on the Status screen says how
  to fix it, and both print the snippet beside it rather than a rebuild button
  that cannot help.
- **A rate limit can count a form field, cookie or query parameter whose name
  has capitals in it.** Before 2.33.2 the library lower-cased every key
  component, so `post.userName` read a field called `username`, found nothing,
  and put every request in one counter; the rule screen refused such a key for
  that reason. 2.33.2 keeps the case of the name after `post.`, `cookie.` and
  `query.`, and the plugin now stores and compiles it as typed. The prefix and
  a header name are still lower-cased, exactly as the library does it, and the
  refusal and its message are gone.

  **No stored limit changes counter, and there is no upgrade step.** Every
  path to the library runs the rate limit validator — the rule screen, the
  importer and the settings service on the way in, and the compiler again on
  the way out, for anything written straight into the option — which
  lower-cased every key and refused a capitalised POST, cookie or query name.
  So every key the library has ever been handed is lower case, and 2.33.2
  hashes it to exactly the counter it used before. The only difference is that
  a rule written straight into the option with such a name, which the compiler
  used to skip and report, now compiles. Check that a field name in a key matches the form's spelling exactly:
  `post.username` against a form posting `userName` still reads nothing.

## [1.0.0-rc.1]

**Release candidate for 1.0.0.** Published as a GitHub pre-release, so the
`releases/latest/download` URL does not serve it; install it by its own URL.
Please try it on a staging site and report anything that surprises you.

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
  - An ASN rule's referenced list of numbers matches with *is equal to*, *is
    one of* and *is not equal to*, each entry compared as a whole number. An
    entry has to be digits alone to be used; one written `AS16509` is skipped,
    and the rule screen says so.
  - A geolocation or ASN rule checks the type of the MaxMind database it is
    given — City for geolocation, GeoLite2-ASN for ASN — and a database of the
    wrong kind, which the reader refuses on every lookup, is reported on the
    rule, on the Status screen and in Site Health.
  - The edge signal type matches what the CDN worked out that the site cannot:
    a JA3 or JA4 TLS fingerprint, or the bot score, from Cloudflare, Fastly or a
    custom CDN. Believed only behind a trusted proxy.
  - A regular expression condition is written as the pattern alone; the
    delimiters and the case flag come from the form. A pattern between slashes,
    such as `/wp-admin/`, is a path and is kept exactly as written through
    every save.
  - A document written straight into the option — WP-CLI, a deploy, a restore
    — is compiled as each rule type's validator reads it, so settings in the
    shape a person types them compile as the rule screen would store them. A
    rule that could only be read by dropping part of it is skipped and named on
    the Status screen and in Site Health.
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
  live rules without recording anything: no block, no offense, no log line,
  and no rate limit counter — every rate limit, presets' included, counts in
  memory for the run.
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
  response. Names added under **Additional variables to redact** are redacted
  on both paths as well as the library's own set.
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
- **Exempting a role.** Members of roles ticked on the General screen are not
  evaluated. A request carrying a WordPress login cookie is evaluated at
  `plugins_loaded` instead, on both paths, once the cookie can be validated; a
  forged one is evaluated like any other request. Off by default, and while it
  is off nothing about either path changes.
- **Multisite, per site.** Each site of a network has its own settings,
  compiled file, block list, counters and logs, and is evaluated from the
  mu-plugin against its own rules. The `wp-config.php` path steps aside on a
  network, since it runs before the site is known; Site Health says to remove
  a snippet left in.
- **A release zip** that vendors the library namespace-scoped, so it cannot
  collide with another plugin bundling `kanopi/firewall`, and needs no Composer
  on the server. Both evaluation paths run the scoped copy even when another
  copy of the library was loaded first. The build proves the scoped classes
  resolve, and boots the zip beside an unscoped copy, before zipping, and CI installs the zip on a clean WordPress and makes it refuse a request
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
- A rule's credentials are never rendered into its edit form: a rate limit
  rule's Redis password and DSN, a geolocation or ASN rule's MaxMind license
  key, an AbuseIPDB rule's API key, and any setting a contributed rule type
  declares secret. Blank keeps the stored value and a box removes it. A
  referenced list's Advanced box shows its `upstream.auth` credential and each
  header value as `[redacted]`, and a credential in the list's URL as `***`;
  a save keeps each while the list's URL is unchanged. Limits
  and counter storage have their own controls, so saving the form unchanged
  stores what was there.
- The Storage screen and each database log handler on the Logging screen offer
  every way a connection can be given — WordPress's credentials, a DSN or
  individual parameters, and for storage a preset — and render the DSN and
  password write-only in the same way. Saving either screen unchanged keeps the
  connection as stored.
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
    `i` flag becomes the condition's case-sensitivity box, so no rule narrows
    or changes case — upgrading from the earliest builds included.
  - Geolocation and ASN condition variables take the library's names:
    `country_name`, `timezone`, `latitude`, `longitude` and `organization`
    become `country.name`, `location.timeZone`, `location.latitude`,
    `location.longitude` and `asn_org`. Before this those conditions matched
    nothing. A condition on the ASN `network`, which has no library equivalent,
    is kept rather than dropped — dropping it would widen an "all" rule — and
    reported on the rule and the Status screen.
  - Request / URL conditions on `referer` and `content_type` become
    `header.referer` and `header.content-type`, which is how the library reads
    them; before this a negated one matched every request. Conditions on `uri`,
    `body` and `server.*`, which the library cannot read at all, are kept and
    reported on the rule, the Status screen and in Site Health.
  - `storage.record_request`, new in library 2.31.0, is filled in.
- **Translated at compile time rather than rewritten**, so stored rules work
  without being edited: the operators `gt`, `gte`, `lt`, `lte` and
  `not_contains`, which the library does not know and which matched nothing;
  the renamed condition variables above, for a document that reaches the
  compiler without the upgrade; a `port` compared with *is equal to*, *is not
  equal to* or *is one of*, which is compiled as a number;
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
