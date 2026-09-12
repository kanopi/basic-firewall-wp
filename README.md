# Basic Firewall

Evaluates every incoming request against a set of rules and allows, challenges
or blocks it — as early in the request as WordPress can act. Traffic you reject
costs almost nothing to serve.

Built on [`kanopi/firewall`](https://github.com/kanopi/firewall), with a full
administrative interface for everything the library can do. It is the WordPress
port of the Drupal module [`basic_firewall`](https://www.drupal.org/project/basic_firewall),
and it keeps that module's vocabulary, its defaults, and — more importantly —
its habit of writing down what does not work.

## Table of contents

- [What this costs per request](#what-this-costs-per-request)
- [What it cannot do](#what-it-cannot-do)
- [Installation](#installation)
- [Getting started safely](#getting-started-safely)
- [Where evaluation happens](#where-evaluation-happens)
- [The private directory, and why WordPress makes this hard](#the-private-directory-and-why-wordpress-makes-this-hard)
- [Proxies and the client IP](#proxies-and-the-client-ip)
- [Rule types](#rule-types)
- [Storage](#storage)
- [Logging](#logging)
- [Export and import](#export-and-import)
- [wp-config.php options](#wp-configphp-options)
- [WP-CLI commands](#wp-cli-commands)
- [Multisite](#multisite)
- [Building a release](#building-a-release)
- [Deliberately out of scope](#deliberately-out-of-scope)

## What this costs per request

**The cost is additive, not a saving.** The firewall runs before WordPress does
its own work, so it is paid on every request — including ones a page cache would
otherwise have answered without booting much of anything. This is a correctness
tool, not a throughput one. The honest framing is that you are buying protection
with latency.

Figures below are the Drupal module's, measured against `kanopi/firewall`
2.24.0 on PHP 8.4 with six enabled rules and two presets. The shape carries over
to WordPress; the absolute numbers on your host will not match.

| What | Cost |
|---|---|
| Evaluating a request — six rules, two presets | **3.8 ms** median |
| …of which reading the compiled configuration | **0.08 ms**, from the library's parse cache |
| Reading the compiled configuration with a cold cache | **42 ms**, paid by the first request after a deploy |
| Block list lookup, database storage | 0.07 ms, flat |
| Block list lookup, file storage, empty list | 0.007 ms |
| Block list lookup, file storage, 2,000 blocked clients | **0.75 ms**, and rising |

Three things in that table are worth acting on.

**The parse cache matters more than anything else.** The compiled file is YAML,
and parsing it used to happen on every request. The plugin points the library's
cache at `cache/compiled` inside the private directory — persistent, beside the
compiled file, and not the system temporary directory, which gets cleared. Every
clear costs that 42 ms again, on every php-fpm worker.

**File storage is the one cost that grows with an attack.** Its lookup is
proportional to the size of the block list, so it gets slower exactly when the
firewall is busiest. File is the default because it is faster on a quiet site and
needs no credentials; it loses once the list passes roughly a hundred clients,
which an attack reaches in seconds. Site Health tells you when you have crossed
that line. Switching backends does **not** move the existing list.

**Debug logging is enormous.** On a file handler it is roughly 100 KB per
*allowed* request — about 97 MB per thousand. Set it, reproduce the request, set
it back. The logging screen says so at the point the level is chosen.

### Two ways to measure this wrong

**A challenge rule refuses your load generator.** The bot detector flags `curl`,
`ApacheBench` and most monitoring agents. A benchmark that appears to show the
firewall rejecting everything is usually measuring that.

**Load-testing your own site will block you.** A rate limit counts your
generator's requests, records an offense, and adds the address to the durable
block list — so every subsequent request is refused whatever you change.
`wp basic-firewall clear-blocked --yes` is the way out. This happened repeatedly
while developing the plugin, including once on a bare `curl` of the homepage.

## What it cannot do

Read this section before the feature list.

**No PHP firewall can touch a host edge cache.** On Pantheon, WP Engine, Kinsta
or anything behind a CDN, requests served by the platform's own cache layer never
reach PHP at all. Nothing in this plugin evaluates them. This is the most
consequential limitation there is, and no configuration changes it.

**Database-backed block storage does not work on the `wp-config.php` evaluation
path.** That path runs before WordPress exists, so there is nothing to read
database credentials from. A site combining the two **fails open on every
request while the admin screens report it as blocking**. This is the plugin's one
known fail-open. It is carried over from the Drupal module deliberately rather
than hidden, Site Health raises it as an error, and there is not a second one.

**The private directory is probably readable over the web.** See
[below](#the-private-directory-and-why-wordpress-makes-this-hard) — WordPress has
no private file system, and on nginx the usual guard files do nothing at all.

**A rate limit cannot depend on who is asking.** The counter is keyed on address
and pattern, never on the account. A premium *endpoint* can carry its own limit;
a premium *user* cannot. Per-user quotas belong in the application.

**WP-Cron is request-driven.** Source refreshes and log pruning run on WP-Cron,
which fires when somebody visits the site. On a quiet site they run late or not
at all. Define `DISABLE_WP_CRON` and add a real cron entry hitting
`wp-cron.php`, or run `wp cron event run --due-now` from crontab.

**The firewall always fails open.** If the compiled file is missing, unreadable
or invalid, the request is allowed through and the problem is reported in Site
Health. A firewall misconfiguration will never be the reason your site is
unreachable — which also means a broken firewall enforces nothing, and the only
thing standing between you and not noticing is that the failure is loud.

## Installation

Either route works. They produce different builds, and the difference matters.

### From a release zip (recommended)

Download `basic-firewall-<version>.zip` and install it through
**Plugins → Add New → Upload Plugin**. No Composer, no shell, no build step.

The zip ships with the library vendored **and namespace-scoped**, which makes it
immune to a collision with any other plugin that bundles `kanopi/firewall`.
`wp basic-firewall status` reports `Collision safe: yes (scoped)`.

### With Composer

```bash
composer require kanopi/basic-firewall-wp
```

Installs into `wp-content/plugins/` via `composer/installers`. In this mode the
library is resolved normally and is **not** scoped, so the plugin shares the
library's namespace with the rest of the site. That is fine on a site that
controls its own dependencies and is worth knowing about on one that does not:
if another plugin bundles a different version of `kanopi/firewall`, whichever
autoloader registers first wins. Site Health says so.

## Getting started safely

A firewall can lock you out of your own site. The plugin is built so that cannot
happen by accident:

1. **It installs in log-only mode with no rules.** Nothing is blocked and
   nothing matches until you say so.
2. **Add your own address to an allow rule first.** Rule type *IP address*,
   response *Allow*, weight `-200`. Allow rules run before everything else and a
   match ends evaluation, so this is your safety net.
3. **Add the rules you actually want**, and leave the mode on *Log only*.
4. **Read the log for a few days.** Every would-be block is recorded at
   `warning` with the full request. Look for anything legitimate.
5. **Switch the mode to *Block*** on the General screen once the log is clean.

If you do lock yourself out, any of these works and none needs the admin screens:

```bash
wp basic-firewall unblock 203.0.113.10      # release one client
wp basic-firewall clear-blocked --yes       # release all of them
```

```php
// wp-config.php. Takes effect on the next request, needs no database access.
define( 'BASIC_FIREWALL_ENABLED', false );
```

## Where evaluation happens

This is the hardest thing to translate from Drupal, and the answer is less tidy.
The module registers middleware at priority 280, ahead of the page cache, so
even a cache hit is firewalled. WordPress has no equivalent ordering.

```
host edge cache (Varnish/CDN)   <- no PHP runs at all. Unreachable.
  wp-config.php                 <- the early path. Optional; see below.
    advanced-cache.php          <- Batcache, W3TC, WP Super Cache: serve and exit
      mu-plugins                <- the normal path. Installed automatically.
        plugins
          theme, init, authentication
```

**The normal path** is an mu-plugin, copied into `wp-content/mu-plugins/` on
activation and removed on deactivation. It is the earliest hook a plugin can own
and it needs no configuration, which is why it is the default.

**The early path** is a `require` in `wp-config.php`. It exists because
`advanced-cache.php` serves a cached response and calls `exit()` before any
mu-plugin loads — so on exactly the busy, cached site that most needs a
firewall, the normal path never runs for a cache hit.

Site Health detects a page cache and prints the snippet with your site's real
private path filled in. It looks like this:

```php
// In wp-config.php, AFTER any BASIC_FIREWALL_ constants and immediately
// BEFORE the line that requires wp-settings.php.
require_once ABSPATH . 'wp-content/plugins/basic-firewall/bootstrap.php';
basic_firewall_evaluate( array(
    'private_path' => '/path/to/uploads/basic-firewall-private-abc123',
) );
```

Placement matters: the snippet uses `ABSPATH`, which `wp-config.php` defines
near the bottom. Putting it above that line is a fatal error on every request.

`bootstrap.php` contains no WordPress API calls at all, which is what makes it
safe to require that early — and also what makes database-backed storage
unusable there.

## The private directory, and why WordPress makes this hard

Drupal has a private file system: a directory outside the web root, served only
through a code path that checks access. **WordPress has nothing of the kind.**

The plugin creates `wp-content/uploads/basic-firewall-private-<random>/` and
hardens it three ways:

| Guard | Works on |
|---|---|
| `.htaccess` | Apache, LiteSpeed |
| `web.config` | IIS |
| `index.php` | everything — but it only stops a directory *listing* |

**On nginx the first two do nothing at all**, and nginx serves a large share of
WordPress sites. This is not theoretical: on the stock nginx site this plugin was
developed against, `blocked.data`, `firewall.yml` and the log files were all
downloadable with HTTP 200. What leaks is the list of addresses you are blocking,
every decision the firewall has made, and your compiled configuration.

So two further things happen:

- **The directory name carries a random per-site suffix.** That is mitigation,
  not a fix, but it works everywhere with no configuration and it means an
  attacker has to be told the path before any of it is reachable.
- **Site Health asks the web server**, rather than assuming. It writes a canary
  and requests it over HTTP, and it asks for `.yml`, `.data` and a `.log` in a
  subdirectory — deliberately not a dotfile. An earlier version of that check
  probed a dotfile, which nginx commonly denies by name, and reported the
  directory *protected* while everything that mattered was being served.

If Site Health reports it exposed, fix it properly:

```nginx
location ~* /basic-firewall-private-[a-f0-9]+/ { deny all; return 404; }
```

Or move the directory out of the web root entirely, which is strictly better:

```php
add_filter( 'basic_firewall_private_path', fn() => '/var/private/basic-firewall' );
```

## Proxies and the client IP

Every rule that looks at an address depends on the client IP being trustworthy,
and Symfony only honours `X-Forwarded-For` once trusted proxies are established.
Until they are, both of these are true:

- every visitor appears to come from your proxy, so one visitor's offense blocks
  everybody and a per-IP rate limit counts the whole site as one client;
- and if you later trust too wide a range, anything on that network can forge the
  header and walk straight through IP allow-lists, block-lists and rate limits.

Drupal has `$settings['reverse_proxy_addresses']` and the module simply reuses
it. WordPress has no equivalent, so this plugin defines one rather than guessing
— there is no safe default between trusting nothing and trusting everything:

```php
// wp-config.php. Narrow this to the proxies that actually front the site.
define( 'BASIC_FIREWALL_TRUSTED_PROXIES', array( '10.0.0.0/8' ) );
```

### Local development is proxied too

DDEV, Lando and Docksal all route through a router container, so PHP sees the
router and the real client only in `X-Forwarded-For` — the same shape as
production, and none of them configure it for you. Measured on this plugin's own
DDEV site: a single blocked request recorded `172.20.0.5`, the router, and every
subsequent request from any client was refused.

```php
if ( getenv( 'IS_DDEV_PROJECT' ) === 'true' ) {
    define( 'BASIC_FIREWALL_TRUSTED_PROXIES', array( '172.16.0.0/12' ) );
}
```

Three parts of that are deliberate: the Docker range rather than the router's
address, because container addresses are reassigned on recreate; the
`IS_DDEV_PROJECT` guard, so a `/12` cannot follow the file to real hosting; and
no forwarded-host trust, because the host is what decides which URLs get
generated.

## Rule types

| Rule type | Matches on |
|---|---|
| IP address | Client IP — single addresses, CIDR blocks, `start-end` ranges, IPv4 and IPv6 |
| Request / URL | Method, host, path, scheme, port, query, POST body, headers, cookies |
| User agent | Automated flag, bot flag, device, browser, OS, brand, model — parsed, not string-matched |
| Rate limit | Requests per address, per time window, per pattern |
| ASN | Autonomous system number or organisation. Needs a MaxMind ASN database |
| Geolocation | Country, continent, city, postal code, timezone. MaxMind database or CDN headers |
| Vulnerability score | Method, country, network, attack patterns, user agent — summed |
| IP reputation | AbuseIPDB confidence score. Free API key, one cached lookup per visitor per day, fails open |
| OWASP Core Rule Set | The full CRS ruleset, via `kanopi/crs-engine` |

Each rule has a **response** — Allow, Challenge or Block — evaluated in that
order, and a match ends evaluation. Within a group, lower weights run first.

### Use `automated`, not `bot`

The user agent rule offers both, and the difference decides whether the rule
stops scanners:

| Agent | `bot:true` | `automated:true` |
|---|---|---|
| `sqlmap/1.7` | allowed | **blocked** |
| `Nikto/2.5.0` | allowed | **blocked** |
| `curl/8.0` | allowed | **blocked** |
| `python-requests/2.31` | allowed | **blocked** |
| `Googlebot/2.1` | blocked | blocked |
| iPhone Safari | allowed | allowed |

`bot` is backed by a curated crawler database that does not classify scanners or
generic HTTP client libraries. **A rule written as `bot equals true` has been
letting sqlmap and nikto straight through.** The rule screen says so where the
variable is chosen.

### How a rate limit counts

The counter is keyed on the visitor's **address and the pattern that matched** —
not on the path they asked for. That one detail decides how every limit behaves,
and it is the opposite of what "requests per path" suggests:

| You configure | What it actually limits |
|---|---|
| `/api/*` at 100/min | 100 per address across **everything below `/api/` combined** |
| `/wp-login.php` at 5/min | 5 per address for that exact path |
| the fallback | **one** count per address across all uncovered paths together |

**Visitors sharing an address share a count** — one office behind one NAT, a
corporate VPN, a school, a mobile carrier's gateway. And a path that both opens
and closes with a slash (`/api/`) satisfies the library's "is this a regex?" test
and matches any path *containing* `api`. Use `/api/*` or `/api`. The rule screen
rejects the ambiguous form.

### Regular expressions need delimiters

`#^/wp-admin#`, not `^/wp-admin`. The library silently rejects an undelimited
pattern, so the rule saves, reports itself active, and matches nothing. Every
screen that takes a pattern validates this.

## Storage

| Backend | Use when |
|---|---|
| File | Single web node. No credentials, and the only option that works on the early path |
| Database | Multiple web nodes, or a block list of any size. Flat lookup cost |

Clients are keyed by IP address. **Switching backends does not move the block
list** — each keeps its own, so a client blocked under file storage is not
blocked after a switch, and is blocked again if you switch back.

**WordPress's database credentials are never written into the compiled file.**
The compiled storage section carries the two table names and nothing else; the
connection is injected at request time. That buys three things: an export cannot
leak them, a plaintext password never reaches disk in a directory that may be
web-readable, and a rotated password takes effect on the next request rather than
at the next rebuild. That last one is the reason it is a requirement rather than
a nicety — Pantheon rotates credentials per environment and on container
operations, and a baked snapshot goes stale silently:

```
block()  -> false          the client is not recorded
request  -> allowed        the firewall fails open
```

## Logging

The firewall logs through Monolog, not through WordPress, because it runs before
WordPress's logger exists. Blocks — and, in log-only mode, would-be blocks — are
recorded at `warning`.

Keep logs in the private directory. A log under a public directory is
downloadable by anyone and discloses exactly which addresses you are blocking.

The **Database table** handler writes each event as a row and the **Log** screen
reads them back. A file answers "what happened just now" if you can reach a
shell; a table answers the questions that actually get asked — which rule has
blocked the most clients this week, whether a rule has matched anything at all
since it was added, what the firewall did to an address before its owner
complained.

## Export and import

WordPress has no `drush config:export`, so this **is** the deployment story and
it carries more weight here than it does in Drupal.

```bash
wp basic-firewall export --file=firewall.yml
wp basic-firewall import firewall.yml --dry-run
wp basic-firewall import firewall.yml --mode=replace --yes
```

Three behaviours are guaranteed, and each has a test that fails if it regresses:

**Credentials are stripped, and the document says which.** Every rule type
declares which of its own settings are secret, so a type contributed by another
plugin has its API key redacted without the exporter knowing the type exists.

**`%env(NAME)%` tokens are references, not secrets, and survive intact.** A token
names an environment variable rather than holding one, so stripping it would
break the receiving site and protect nothing.

**An empty credential on import means "not carried", never "set to nothing".**
This is the direction that does damage: writing a stripped export over a
receiving site would erase its challenge secret — and a firewall that cannot
start fails open, so every rule silently stops being enforced while the interface
goes on reporting "Blocking".

## wp-config.php options

All optional, all added by hand. This plugin never writes to `wp-config.php`.

```php
// Switch the firewall off entirely. Needs no database access.
define( 'BASIC_FIREWALL_ENABLED', false );

// Force a mode regardless of what is configured: block, log, exception, disabled.
define( 'BASIC_FIREWALL_MODE', 'log' );

// Supply the challenge signing secret without storing it in the database.
define( 'BASIC_FIREWALL_CHALLENGE_SECRET', getenv( 'FIREWALL_CHALLENGE_SECRET' ) );

// Addresses permitted to declare the client address.
define( 'BASIC_FIREWALL_TRUSTED_PROXIES', array( '10.0.0.0/8' ) );

// Allow %file(...)% tokens to read secrets from these directories, and only
// these. Off entirely when unset.
define( 'BASIC_FIREWALL_SECRET_DIRECTORIES', array( '/etc/firewall' ) );
```

The interface reports when any of these is in effect, so nobody wonders why the
setting they saved is being ignored.

### Keeping secrets out of the database

Every field that can hold a secret accepts a token instead, resolved by the
library each time it loads the compiled configuration:

```
api_key:  %env(ABUSEIPDB_API_KEY)%
password: %env(FW_DB_PASSWORD)%
secret:   %file(/etc/firewall/hmac.key)%
```

`${VAR}` does **not** work — only the `%env(...)%` form is substituted.

One token naming a variable that does not exist means **the entire configuration
fails to load** — every rule, not just the setting the token appeared in — and
the firewall then allows all traffic. Site Health reports it and
`wp basic-firewall rebuild` refuses to claim success.

`%file()%` reads a file and is **off until you name the directories it may read
from**. Only the `file` processor is ever enabled, never `require`: the library
offers both behind one switch, and `require` executes the path it is given, which
would turn any environment-variable injection into remote code execution.

## WP-CLI commands

```bash
wp basic-firewall status            # what the firewall is doing right now
wp basic-firewall rules             # rules in evaluation order
wp basic-firewall rebuild           # recompile the configuration
wp basic-firewall sources           # available presets

wp basic-firewall check IP          # is this address blocked?
wp basic-firewall block IP          # block it
wp basic-firewall unblock IP        # unblock it
wp basic-firewall blocked           # list every blocked client
wp basic-firewall clear-blocked     # empty the block list
wp basic-firewall find-reference REF # which rule produced this block reference

wp basic-firewall export            # portable document, credentials stripped
wp basic-firewall import FILE       # read one back, --dry-run to preview
```

`check` exits 0 whether or not the address turned out to be blocked — the exit
status reports whether the *query* ran. Read the `blocked` field.

Anything destructive refuses to run without `--yes` and exits non-zero when it
refuses. It will never exit 0 having done nothing.

## Multisite

Per-site. Each site gets its own settings, its own block list, its own counters
and its own logs, and nothing is shared unless you deliberately point two sites
at the same place. That falls out of WordPress: `get_option()` is per site,
`wp_upload_dir()` is `uploads/sites/N/`, and `$wpdb->prefix` carries the blog id.

The prefix has to be applied by hand, because the firewall reaches the database
through Doctrine DBAL rather than through `$wpdb` and nothing else would apply
it. Without that, every site in a network writes to `basic_firewall_blocked`:
blocking a client on one site blocks them everywhere, offense counts merge so
escalation triggers sooner than configured, and one site's block list is readable
from another. A prefix you typed yourself is not doubled, and the Storage screen
shows the resulting table names.

There is no network-wide settings screen. Configuring 200 sites means
`wp site list --field=url` and a loop.

## Building a release

```bash
composer install
bash build/build-zip.sh
```

Produces `build/dist/basic-firewall-<version>.zip`. The build scopes the vendor
tree under `Kanopi\BasicFirewall\Vendor` and then **proves the result works**
rather than assuming it: it loads the built autoloader and resolves the classes
the library will actually ask for, checks the classmap is complete under an
authoritative dump, reads the library's own presets for class names that scoping
should have rewritten, and confirms the functions `wp-config.php` calls by name
are still global.

That verification is not ceremony. `kanopi/firewall` resolves class names out of
configuration data — it calls `class_exists()` on a string from the config and
instantiates it — and when that string names a class scoping renamed, the library
does not throw. It **skips the plugin and carries on**. A scoping mistake
therefore produces a firewall that installs, activates, shows every preset as
enabled, reports itself healthy, and enforces nothing. Seven distinct defects of
exactly that shape were found while building this, each of which produced a zip
that installed and activated perfectly; they are documented in the commit
history and in `DECISIONS.md`.

`BFW_SKIP_SCOPING=1` builds unscoped, for local testing only.

## Deliberately out of scope

Listed rather than omitted, so you know they were considered.

- **A network-wide settings screen.** Configuration is per site; see
  [Multisite](#multisite). A network policy would be additive and is not in 1.0.
- **WordPress.org distribution.** Releases are self-hosted, because a plugin
  release is how a library update reaches sites and coupling that to a review
  queue is the wrong dependency. `readme.txt` is maintained so the decision stays
  cheap to reverse. See `DECISIONS.md` section 4.
- **A role-based bypass matching the module's second evaluation point.** Roles
  are exempted on the General screen, but the module's trick of deferring
  cookie-bearing requests past the page cache to a second evaluation point is not
  ported — WordPress has no equivalent policy to lean on, and the bypass that
  Drupal's version introduced is not one worth reimplementing blind.
- **Editing preset rules.** Presets are included by reference so they update with
  the library. To carve out an exception, add an allow rule with a lower weight.
- **Per-user rate limits.** Not expressible; see
  [How a rate limit counts](#how-a-rate-limit-counts).

## Licence

GPL-2.0-or-later. See `LICENSE`.
