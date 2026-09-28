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
- [Presets](#presets)
- [Storage](#storage)
- [Caching on hosting where shared storage is slow](#caching-on-hosting-where-shared-storage-is-slow)
- [Logging](#logging)
- [Reacting to a decision](#reacting-to-a-decision)
- [Export and import](#export-and-import)
- [During an incident](#during-an-incident)
- [wp-config.php options](#wp-configphp-options)
- [WP-CLI commands](#wp-cli-commands)
- [Multisite](#multisite)
- [Uninstalling](#uninstalling)
- [Building a release](#building-a-release)
- [Releasing](#releasing)
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
clear costs that 42 ms again, on every php-fpm worker. Where the private
directory is a network mount, `BASIC_FIREWALL_CACHE_DIR` moves it — see
[caching](#caching-on-hosting-where-shared-storage-is-slow).

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

**Database-backed block storage depends on where you put the bootstrap.** The
Drupal module lists this as an outright fail-open — no CMS on the early path
means no credentials — and the limitation is Drupal's, not the early path's.
`wp-config.php` defines `DB_NAME`, `DB_USER`, `DB_PASSWORD` and `DB_HOST` as
plain constants near the top of the file, so a bootstrap required *below* them
has the credentials already in scope, and database storage works there. Required
*above* them it does not, and a site combining the two **fails open on every
request while the admin screens report it as blocking**. Site Health checks
which of the two you have and says so.

**The private directory is probably readable over the web.** See
[below](#the-private-directory-and-why-wordpress-makes-this-hard) — WordPress has
no private file system, and on nginx the usual guard files do nothing at all.

**A rate limit cannot give different visitors different allowances.** A limit
can count something other than the address — the username posted to
`wp-login.php`, say — but every bucket it counts gets the same allowance. A
premium *endpoint* can carry its own limit; a premium *user* cannot. Per-user
quotas belong in the application, where the account is known. See
[How a rate limit counts](#how-a-rate-limit-counts).

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

Composer is optional. The release zip carries everything the plugin needs, so a
site with no Composer anywhere installs it with WP-CLI or through the admin. The
two builds differ, and the difference matters.

### With WP-CLI (recommended)

```bash
wp plugin install https://github.com/kanopi/basic-firewall-wp/releases/latest/download/basic-firewall.zip --activate
```

That URL always resolves to the current stable release. To pin one, name it:

```bash
wp plugin install https://github.com/kanopi/basic-firewall-wp/releases/download/1.0.0/basic-firewall-1.0.0.zip --activate
```

To upgrade, run the same command with `--force`; WP-CLI replaces the plugin in
place and keeps its settings. `wp plugin update` cannot do it, because the
plugin is not listed on wordpress.org, so WordPress has nowhere to look for a
newer version.

### Through the admin

Download `basic-firewall.zip` (or the versioned `basic-firewall-<version>.zip`,
the same file) from the
[GitHub Releases page](https://github.com/kanopi/basic-firewall-wp/releases) and
upload it at **Plugins → Add New → Upload Plugin**.

### What the zip is

It is the one CI installed on a clean WordPress with no Composer on the machine,
and made to refuse a request, before publishing it; see [Releasing](#releasing).
No shell, no build step. It ships with the library vendored **and
namespace-scoped**, which makes it immune to a collision with any other plugin
that bundles `kanopi/firewall`. `wp basic-firewall status` reports
`Collision safe: yes (scoped)`.

### With Composer

```bash
composer require kanopi/basic-firewall-wp
```

The package is not on Packagist yet, so until it is, point Composer at the
repository first. Composer reads versions straight from the repository's tags,
so every release tag is also a Composer release:

```bash
composer config repositories.basic-firewall vcs https://github.com/kanopi/basic-firewall-wp
composer require kanopi/basic-firewall-wp:^1.0
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

The copy is kept in step with the one the plugin ships, so an update that
changes the loader reaches the site without deactivating anything. The installed
loader states its version in a constant, and the plugin compares that with its
own on admin, cron and WP-CLI requests — two constants, no file read, and never
on a visitor's request. When they differ, or when the plugin is updated through
the WordPress updater, activated, or Site Health is opened, the two files are
compared byte for byte and the installed one is replaced: written to a
temporary file beside it and renamed over it, so a concurrent request never
loads half a file. It is only ever replaced, never recreated: a loader that has
been removed stays removed until the plugin is activated again. If mu-plugins is
not writable, Site Health reports the loader as out of date and says why. To
manage the file yourself — mu-plugins deployed from version control, say —
define `BASIC_FIREWALL_MU_LOADER_REFRESH` as `false`.

**The early path** is a `require` in `wp-config.php`. It exists because
`advanced-cache.php` serves a cached response and calls `exit()` before any
mu-plugin loads — so on exactly the busy, cached site that most needs a
firewall, the normal path never runs for a cache hit.

The Status screen always prints the snippet with your site's real private path
filled in — you cannot write it yourself, because the private directory carries
a random per-site suffix. Site Health prints it too, when it finds a page cache
in front of the firewall. It looks like this:

```php
// In wp-config.php, AFTER any BASIC_FIREWALL_ constants and immediately
// BEFORE the line that requires wp-settings.php.
require_once ABSPATH . 'wp-content/plugins/basic-firewall/bootstrap.php';
basic_firewall_evaluate( array(
    'private_path' => '/path/to/uploads/basic-firewall-private-abc123',
) );
```

Placement matters twice over:

* The snippet uses `ABSPATH`, which `wp-config.php` defines near the bottom.
  Putting it above that line is a fatal error on every request.
* It must sit **below** the `DB_` constants. The bootstrap reads them to build
  the connection for database-backed block storage. Above them there is nothing
  to read, no connection is built, and that storage fails open.

`bootstrap.php` contains no WordPress API calls at all, which is what makes it
safe to require that early. The database connection is not an exception: the
constants are plain `define()`s, and the injection *paths* come from a small
JSON sidecar written beside the compiled file, because the option the normal
path reads them from needs a WordPress that does not exist yet. The sidecar
holds path strings only — the credentials are read from the constants per
request and never touch disk, on either path.

### `exception` mode before WordPress

In every other mode the library sends its own response and exits. In `exception`
mode it hands each verdict to the plugin to answer — and on the early path the
plugin answers it there and then, with the same responder the mu-plugin uses,
loaded without WordPress:

| Verdict | Answered | With |
|---|---|---|
| Block | in `bootstrap.php` | the status and message, `no-store` |
| Lockdown | in `bootstrap.php` | 503 and its `Retry-After` |
| Redirect | in `bootstrap.php` | the rule's destination and status, `no-store` |
| Challenge | in `bootstrap.php` | the library's interstitial, 503, `Retry-After` |
| Solved challenge | at `muplugins_loaded` | the pass cookie, and JSON for the interstitial's script |

Not later, from the mu-plugin, because `advanced-cache.php` runs in between: a
page cache would serve the refused visitor the page. The solved challenge is
the exception because it needs settings to name the pass cookie, and it is safe
to leave because it is a POST to the challenge path, which no page cache serves.
The bootstrap leaves it in a global and the runner answers it before any
ordinary plugin loads — or at `plugins_loaded`, if the mu-plugin loader is
missing or was copied by an older release.

Where a solved challenge sends the visitor came back through the visitor, so it
is not trusted. Only a path on this site is followed, rebuilt from the posted
path and query. Anything holding a control character or whitespace, raw or
percent-encoded, goes to `/` instead, and a backslash counts as the slash a
browser makes of it before the `//` check. Browsers strip tabs and read `\` as
`/`, so `/<tab>/evil.example` and `/\evil.example` would otherwise leave the
site.

If the bootstrap cannot find the plugin's responder it hands refusals to the
runner the same way, so they are still answered, but after a page cache has had
its chance. Site Health reports that as **critical** while the mode is
`exception`.

**Deactivating the plugin switches this path off in every mode.** Whether the
plugin is active is an option, and the bootstrap has no options to read — so
deactivation deletes the compiled file, and without it the bootstrap evaluates
nothing. A plugin switched off without its deactivation hook running — the
`active_plugins` option edited by hand, a database restored from before it was
activated — leaves the compiled file behind: the early path then goes on
enforcing the last configuration, in `exception` mode exactly as in `block`
mode. The one thing that goes unanswered then is a solved challenge, which
grants nothing — the visitor is simply challenged again. Delete the compiled
file, or the snippet, to stop it.

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

### How stored paths resolve

Plainly, with no scheme:

| Stored | Resolves to |
|---|---|
| `blocked.data` | inside the private directory |
| `logs/firewall.log` | inside the private directory |
| `/var/private/firewall/blocked.data` | exactly that |

A relative path keeps the setting portable — it survives an export to another
site, it is per-site on a network, and it does not embed one environment's
filesystem layout. An absolute path is used as given, for a site that keeps this
data somewhere it chose. `php://stdout` and `php://stderr` are passed through
too, for a container that collects logs from the process.

**A relative path stays relative in the compiled file.** The plugin does not
expand it. The firewall library resolves `storage.config.storage_file`,
`storage.config.offense_file` and a file log handler's first argument against
the directory holding the configuration file that named them — and it does so
whether or not the file exists yet, which on a first run is all of them. The
compiled file lives in the private directory, so the destination is the same
either way; the difference is that the document says `blocked.data`, which is
what you typed, instead of ninety characters of absolute path belonging to one
machine. What the plugin does not delegate is stripping `..`, because a
relative path is only safe to hand onward once it cannot climb out of whatever
it will be resolved against.

The Drupal module writes `private://blocked.data`, because `private://` is a
real registered stream wrapper there. WordPress has no such thing, so that
spelling is not used here. Settings written by an early build of this plugin
that did use it are migrated on upgrade, and still resolve if they are not.

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
| Rate limit | Requests per address — or per account, header or field — per time window, per pattern |
| Edge signal | The TLS fingerprint (JA3, JA4) or bot score your CDN computed. Needs a CDN sending the headers, and trusted proxies |
| ASN | Autonomous system number (`asn`) or organisation (`asn_org`). Needs a MaxMind ASN database |
| Geolocation | Country, continent, city, postal code, timezone, coordinates. MaxMind database or CDN headers |
| IP reputation | AbuseIPDB confidence score. Free API key, one cached lookup per visitor per day, fails open |
| OWASP Core Rule Set | The full CRS ruleset, via `kanopi/crs-engine` |

**The vulnerability score type is withdrawn from 1.0.** It saved a threshold and
a set of weights, and the library's `VulnerabilityScore` plugin reads neither: it
scores with its own signals (`scoring.*`) and matches on `risk_levels`. So the
rule loaded, reported itself healthy, and never matched anything. It comes back
when it is rebuilt on the library's scoring model. Until then it is not offered,
another plugin cannot register a type under its id, and a rule saved by a
pre-release build is kept as it is — never compiled, and named on the Status
screen and in Site Health until you delete it.

### Responses

Six, evaluated in this order. Within a group, lower weights run first.

| Response | What happens | Recorded? |
|---|---|---|
| **Allow** | Let the request through and stop evaluating | no |
| **Mark** | Let the request through, and flag it | only if you say so |
| **Record** | Let the request through, and block them next time | yes |
| **Challenge** | Serve an interstitial the visitor must solve | no |
| **Redirect** | Send the visitor somewhere else | only if you say so |
| **Block** | Reject the request | yes, unless you say not to |

Two parts of that order are worth stating, because the obvious order is
different. **Mark and record do not end evaluation, and run even on a request
something below is about to refuse** — a signal that only appeared on requests
nobody refused could not be correlated with a block, and a honeypot has to
record the client even though something below ends the request. And **redirect
beats block** because the terminal responses run gentlest first: a redirect
leaves the visitor somewhere to go.

The last four arrived in `kanopi/firewall` 2.26.0, which the plugin's ^2.33.1
requirement covers. On an older library — possible when a site's own Composer
autoloader wins the race — they are not offered, and a rule carrying one is
skipped at compile time with a warning rather than compiled into something the
library would never evaluate.

**Refusing and recording are separate.** That split is what makes two common
setups possible:

- **A honeypot.** A rule catching a scanner on a bait URL wants it blocked
  *next* time, not to refuse the fetch it is already answering — refusing tells
  the scanner exactly which URL is wired, which is the one thing a honeypot must
  not do. That is `record`, or `mark` if you only want the signal.
- **A lockdown.** A rule that refuses everybody and records them leaves a block
  list full of customers once it is lifted, each on an escalating ban nobody
  asked for. Set **Record the client** to *No* on the block rule — or use
  [Lockdown](#lockdown-refuse-everyone-but-a-list), which is that, already built.

**Reading a mark from your own code.** A marked request is allowed through and
flagged, and the plugin hands that to WordPress on both evaluation paths:

```php
add_action( 'basic_firewall_request_marked', function ( array $marks ) {
    // e.g. log it, tag the session, vary the response
} );

// Or ask directly, any time after plugins_loaded:
if ( Kanopi\BasicFirewall\Runtime\Runner::is_marked( 'honeypot' ) ) { … }
```

A rule can also set a request header, for something downstream — a CDN, a log
pipeline — that was never written to know this plugin exists.

**Prefer a temporary redirect.** A rule's verdict changes with the next edit, and
a 301 is cached by browsers and intermediaries more or less forever: somebody
caught by a rule you later tune would keep being sent to the notice page long
after it stopped matching them.

**A redirect is a redirect in every mode that acts.** In `exception` mode the
library hands the redirect to the plugin rather than sending it, and the plugin
answers it the way the library would have — the destination, the status, and
`Cache-Control: no-store`. That holds on the wp-config.php path too — see
[`exception` mode before WordPress](#exception-mode-before-wordpress).

**A redirect has to name somewhere.** That is not tidiness. The library does not
reject a redirect rule with no destination when it loads; it throws when the
rule *matches*, so every request the rule was written for becomes a firewall
error — which the plugin fails open on, serving the visitor as though the rule
did not exist and never reaching a block rule below it. The rule screen refuses
to save one, and refuses a destination beginning `//`, which reads like a path
and sends the visitor to another site. Anything that bypasses the screen — an
import, WP-CLI, a hand-edited option — is caught by the compiler instead, which
skips the rule and says so on the Status screen. On a URL rule whose own path
conditions look like they match the destination, you get a warning: that
combination is a loop the visitor experiences as a dead browser.

A mark name has to be letters, numbers, hyphens and underscores, because it
becomes part of a request attribute key your code addresses. A redirect or mark
carries no status code of its own, so that field disappears when you choose
either.

**The Test screen names all three.** A redirect is reported as *Redirected*,
with the destination and status, and a record or mark as *Served, and recorded
for next time* or *Served, and marked*. Both of those serve the request by
design, and reporting them as *Allowed* — which is what the screen says when no
rule matched at all — would tell somebody testing their honeypot that it does
not work at the moment it has just caught them.

### Giving a rule opening hours

Any rule can declare when it is awake, under **When this rule is awake** on the
rule screen: a timezone, a set of days, one or more hour ranges, and optionally
a first and last date. Leave it all alone and the rule is awake always, which is
what nearly every rule wants.

"Block this country outside business hours." "Turn this rate limit on for the
campaign." "Allow the deploy pipeline during the maintenance window." Each of
those is otherwise a rule somebody disables and remembers to re-enable — or
does not.

A range whose end is earlier than its start runs over midnight, so `18:00-06:00`
is the evening and the night that follows it. Several ranges can be given at
once, separated by commas — `09:00-12:00, 13:00-17:00` — and are compiled as a
list, because the library reads one string as one range and refuses a line of
several as malformed. A bare `until` date closes at the end of that day, so a
one-day campaign runs for the day. Ticking every day is the same as ticking
none, and a timezone on its own is not a window: neither is written into the
compiled file.

**The window is checked before the rule is evaluated**, not after. A sleeping
geolocation rule costs a comparison rather than a database lookup, and — more
usefully — a sleeping rate limit does not spend a request out of somebody's
budget for a window it was never going to enforce.

**The rule list says which rules are asleep, and when they wake.** A sleeping
rule matches nothing, which from the outside looks exactly like a broken one, so
the Response column answers it directly — *Block — asleep now (until Mon 18:00
PDT)* — in the rule's own timezone, rather than leaving you to work out what
time it is somewhere else. A window whose last date has passed says so, and one
the library cannot read says the rule is not running. An observing rule says
both: *Block — observing only, awake now (until …)*.

#### Daylight saving is followed, not corrected for

Comparisons are wall-clock time in the rule's own zone, so a window means what
somebody standing in that timezone would say it means:

- **Spring forward.** On the day the clocks jump from 02:00 to 03:00, a
  `01:00-03:00` window is simply shorter — no local time inside the gap
  happens, so none is matched.
- **Fall back.** On the day 01:30 happens twice, a window covering it is active
  both times, because both are 01:30 locally.

Neither is a bug being worked around. A rule about business hours should follow
the clock on the wall of the business.

#### Three things worth knowing

**The timezone defaults to your site's**, from *Settings → General*, not to UTC.
The library defaults an unnamed zone to UTC on purpose, so a rule means the same
thing wherever it is deployed — right for a library, wrong for this screen,
where somebody typing business hours means their own. The zone is always
written out, so the compiled file and the screen never disagree.

**A window that cannot be read stops the rule.** The library does not guess:
treating a schedule it cannot read as always-on would silently over-block, and
always-off would silently stop protecting, so the rule fails to start. The rule
screen hands the window to the library before saving and refuses what it
refuses, in the library's words. A window that arrives another way — an import,
WP-CLI — is caught by the compiler, which skips the rule and names it on the
Status screen.

**It needs the library to keep it.** Windows arrived in `kanopi/firewall`
2.27.0. On an older library — possible when a site's own Composer autoloader
wins the race — the window is not offered, a stored one is kept rather than
cleared by an unrelated edit, and the compiler skips a scheduled rule rather
than letting it run at all hours.

### Observing a rule before letting it act

Any rule can be set to **Observe only**, on the rule screen. It is evaluated
normally and every match is logged at `warning`, then treated as no match — so
evaluation carries on and every other rule enforces exactly as before.

This is the answer to the question every new rule raises: *what will this
actually catch?* Without it the options are enforcing a rule nobody has measured
and finding out from visitors, or setting the whole firewall to log mode and
stopping every other rule enforcing with it. Neither is a reasonable thing to
ask somebody, which is why unsure rules get left disabled, where they say
nothing at all.

The workflow it exists for:

1. Add the rule and tick **Observe only**.
2. Leave it a week.
3. Open the **Log** screen and set the enforcement filter to *Observed only*,
   with the rule chosen. That is exactly what this rule would have done.
4. Look at what it caught. If it is what you expected, clear the box.

Worth knowing:

- **It is independent of the response.** A block rule set to observe refuses
  nobody; a challenge rule set to observe challenges nobody. The response
  records what the rule *would* do, which is the thing you are measuring.
- **The rule list says so.** An observing rule's Response column reads
  *Block — observing only* rather than *Block*, because a page you opened to
  check what your firewall does should not tell you the opposite.
- **The Test screen says so too.** A request an observing rule matches is
  reported as *Matched, but only observed* rather than as allowed — otherwise
  testing the rule you just set to observe would report that it does not work.
- **It fails towards doing nothing.** The box is only offered when the installed
  library honours it. On a library that would ignore the key — possible when a
  site's own Composer autoloader wins the race — the compiler skips an observing
  rule and says so on the Status screen, rather than letting it enforce while
  the screen says it is watching.
- **A typo enforces.** The library accepts `log`, `block` and `enforce` in the
  underlying `metadata.mode` and warns about anything else, then enforces. That
  is deliberate upstream: `mode: observe` and `mode: lgo` are both easy to write
  and neither observes anything. The screen only ever stores a value the library
  accepts, so this concerns a hand-edited compiled file or Advanced YAML, not
  the interface.

### Adding your own rule type

Drupal discovers rule types by scanning for a PHP attribute. WordPress has no
discovery at all, so `basic_firewall_rule_types` is the whole extension story:

```php
add_filter( 'basic_firewall_rule_types', function ( array $types ): array {
    $types['acme_tarpit'] = new Acme_Tarpit(); // implements Rule_Type
    return $types;
} );
```

A contributed type is first-class. It appears in the rule type chooser labelled
*Added by another plugin*, sorts by its own weight alongside the shipped ones,
compiles into the same firewall configuration, and **its credentials are
stripped from an export** — because a type declares which of its own settings
are secret, and the exporter reads that declaration rather than a list of its
own. That is the only way the redaction guarantee can hold for code written
after the exporter was.

Two things it cannot do. It cannot take the id of a shipped type: the shipped
one wins and the collision is recorded, because silently replacing a type would
let a plugin change what an existing rule compiles to without anything in the
interface changing. And it cannot make the firewall library do something it
cannot do — `library_class()` has to name a plugin class the installed library
actually has, or the type reports itself unavailable and its rules are skipped
at compile time with a warning.

Removing a type is equally legitimate. A site that must not offer geolocation
can `unset( $types['geolocation'] )`, and the screen 404s accordingly.

### Referencing a list instead of copying it

An **IP address** rule can reference published lists by URL instead of carrying
copies of them. Add as many as the rule needs; each is fetched and shaped
independently.

The simple case is a URL and nothing else:

```yaml
- name: uptimerobot
  upstream: 'https://cdn.uptimerobot.com/api/IPv4andIPv6.txt'
  format: txt
  validate: cidr
  ttl: 86400
  on_error: last_known_good
  max_delta: 0.5
```

Most published lists are not that. AWS publishes ten thousand prefixes as JSON
and you want one service's:

```yaml
- name: aws-cloudfront
  upstream: 'https://ip-ranges.amazonaws.com/ip-ranges.json'
  format: json
  select: 'prefixes.*'            # the .* iterates; without it you get one record
  template: '{value[ip_prefix]}'  # {value} is the record; index into it
  validate: cidr
  max_delta: 0.25
  where:
    - service@equals:CLOUDFRONT   # 10,517 prefixes in, 211 out
```

Every field above has a control on the rule screen except `where`, nested
`template` maps, `header_row`/`delimiter`/`comment`, and `upstream` extras —
those go in a per-list **Advanced** YAML box that is merged into the definition.

| field | what it is for |
|---|---|
| **Format** / **Compression** | `txt`, `json`, `ndjson`, `yaml`, `csv`, `tsv`; gzip. Detected from the URL by default |
| **Select** | dot-path to the records, ending `.*` to iterate them |
| **Template** | `{value}` is the record — `{value[ip_prefix]}`, `{value[0]}` for a headerless CSV column, `{value[ip_prefix\|ipv6_prefix]}` for whichever key exists |
| **Check each entry is** | asserted per entry, so a feed that starts emitting hostnames is rejected rather than contributing entries that match nothing |
| **Refresh every** | how stale a cached copy may get |
| **If it cannot be fetched** | keep the last good copy (default), drop the list, or refuse to start |
| **Reject a change larger than** | a fraction: `0.5` refuses a refresh moving the entry count by more than half. The guard against a provider serving a truncated file — without it, an allow list that briefly returns empty silently stops allowing |
| **Required** | a load failure stops the firewall starting, overriding the policy above |

Three spellings are worth getting right, because each one fails *silently*:
`select` needs its trailing `.*`, `template` indexes through `{value[...]}`
rather than naming the key directly, and the declaration keys are snake_case —
`on_error`, not `onError`. A camelCase key is not rejected; it is ignored, and
the default quietly applies.

**Nothing is fetched while a visitor waits.** The request path runs with the
library's offline flag set: it reads a cached copy and nothing else, so an
outage at the provider cannot become latency here. The cache is filled out of
band, by a WP-Cron job on the interval set on the General screen, or by hand:

```bash
wp basic-firewall refresh-sources            # refresh anything stale
wp basic-firewall refresh-sources --force    # revalidate everything
wp basic-firewall refresh-sources --dry-run  # show what is referenced
```

On a host where WP-Cron is disabled, set the interval to **Never** and call the
command from your own scheduler or deploy. The General screen reports when the
last refresh ran and how many entries each list contributed, because "this allow
rule stopped allowing" is otherwise a hard thing to trace.

A list behind a credential goes in the Advanced box as `upstream.auth`, and is
stripped from an export like every other credential the plugin holds — the
token, password or value, and every `upstream.headers` entry, on every rule type
that takes a list. A credential typed into the URL itself
(`https://user:pass@…`, or a parameter named `token`, `key`, `api_key`,
`password`, `secret`, `signature` and the like) is replaced with `***` and the
URL kept; a key in a parameter with any other name is not recognised, which is
one more reason to use `upstream.auth`. Prefer an `%env()%` token over the
literal value. Two things are refused outright when you
type them: an absolute path, and any scheme other than `http`/`https` — a source
is read at the web server's privilege, and this setting travels in an imported
configuration document. A relative filename resolves inside the private
directory.

### On rules that match conditions

The same editor appears on the **Request / URL**, **User agent**, **ASN** and
**Geolocation** rules, with one field more: what to compare each entry against.

```
List URL                  lists/crawlers.txt
Match each entry against  [header.user-agent ▾] [contains ▾] ☐ Invert
```

Each line of the list becomes one condition, so a file holding

```
GPTBot
CCBot
ClaudeBot
```

blocks all three by user agent, and adding a fourth name to the file changes
what the firewall enforces without touching the rule. That is the case worth
having: crawler names, scanner agents and probe paths all change on somebody
else's schedule.

The entry is compiled into the same structured condition a typed one produces,
rather than the `variable@operator:{value}` shorthand the library also accepts —
so a condition from a list and a condition from the form are evaluated by
identical code, including negation and the operator names this plugin uses. Set
**Template** by hand if you want something the two selects cannot express, such
as an AND group; it wins over the selects.

One difference from the IP rule is worth knowing: **a relative file reference is
resolved to an absolute path at compile time.** The library resolves
`storage.config.*` and log paths against the directory holding the config file,
and does *not* do the same for `metadata.sources.*.upstream`. Left relative it
would resolve against the process working directory — a different answer under
php-fpm, WP-CLI and cron, and all three wrong — so the list would load nothing
while the error policy hid the reason.

Not offered on rate limiting, IP reputation or the Core Rule Set: none of those
matches a list of values. The rule screen asks each type
whether it supports references and only offers the fields when it does.

### Naming a header, cookie or query parameter

A condition reads a named value through a **Look at** / **Name** pair, the same
split the Drupal module uses:

| Look at | Name | reads |
|---|---|---|
| `query` | `test` | `?test=…` |
| `header` | `x-api-key` | the `X-Api-Key` request header |
| `cookie` | `wordpress_logged_in` | that cookie |
| `post` | `log` | that posted field |
| `server` | `request_method` | that server variable |

The Name column appears only for those five families, and a family without a
name is refused — `query` on its own reads nothing, so a condition on it would
save, report itself active, and match nothing.

Stored as one string, `query.test`, which is what the library reads and what
every export, import and CLI command already carries; the two columns are a
display of it. A dotted variable that is not one of these families — the user
agent type's `client.name`, `bot.category` — is left whole.

This is a quick way to see a challenge without pretending to be a scanner: a
rule on `query` / `test` equals `1`, response **challenge**, and `?test=1` on
any URL raises the interstitial.

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

### Verifying a crawler is the crawler it claims to be

A user agent is whatever the client typed. An allow rule for `bot equals true`
is therefore a skeleton key: anyone can send `Googlebot/2.1` and be let past
every rule below it. Since that is a rule people are actively encouraged to
write, the hole is worth closing.

Tick **Verify the crawler** on a user agent rule and list the domains you
accept — `googlebot.com`, `search.msn.com`, `applebot.apple.com`,
`duckduckgo.com`. The firewall then does the round trip Google, Bing, Apple and
DuckDuckGo all document: reverse-resolve the address, check the hostname sits in
a domain you named, then forward-resolve that hostname and confirm it comes back
to the address it started from. Reverse DNS alone proves nothing — anyone
controlling an address can put any name on it — so the forward confirmation is
the part that makes it proof.

Matching is on a label boundary, so `googlebot.com` does not accept
`evilgooglebot.com`. The screen refuses anything that is not a domain — a URL, a
wildcard, a bare `com` — and refuses verification with no domain listed, since
the library treats that as matching nobody.

An import, WP-CLI or a hand edit is not refused, so it keeps what the screen
would have: the entries that are not domains are dropped and the verify box
stays ticked. A rule left verifying against no domain at all — every entry was
`*.googlebot.com`, say — is **skipped when the configuration is compiled**, and
named on the Status screen and in Site Health. It is never compiled without its
verification, because an allow rule on the agent alone lets anyone through who
sends `Googlebot/2.1`.

It **fails closed**: no PTR record, a hostname outside your list, a forward
lookup that does not return, or DNS being unreachable all mean the rule does not
match. On an allow rule that is the safe direction — an unverified client is
simply treated as ordinary traffic.

**A local caching resolver is a prerequisite.** Verification was measured
upstream at about 112 ms cold — 38 ms reverse plus 74 ms forward — against
3.5–5 ms for the firewall's entire evaluation. `systemd-resolved`, `dnsmasq` or
`unbound` takes that to roughly 2 ms. A cached verdict costs 0.02 ms, and
verification only runs *after* the rule's conditions have matched, so most
requests never pay it. But the cold figure is what a cache miss costs, and PHP
cannot put a timeout on a DNS lookup — neither `gethostbyaddr()` nor
`dns_get_record()` accepts one — so without a local resolver a slow nameserver
is bounded only by the system resolver's own retries. The library trips a
breaker after one slow lookup, and fails closed until it resets.

#### It is not switched off by keeping rule lists offline

The plugin keeps every rule-list refresh off the request path, by defining
`KANOPI_FIREWALL_SOURCES_OFFLINE` on both evaluation paths. Until
`kanopi/firewall` 2.33.0 the verifier read that same switch, so on a default
install every verifying rule matched nobody, with nothing but a debug line to say
so. The Drupal module answered that by refusing to save verification until the
site opted out of offline sources — which also lets rule lists refresh while a
visitor waits.

2.33.0 gave verification its own switch, and the compiler writes
`verify_offline: false` on every rule that verifies: ticking the box is asking
for the lookups. `BASIC_FIREWALL_SOURCES_OFFLINE` goes on meaning only what its
name says.

On an older library — possible when a site's own Composer autoloader wins the
race — the old behaviour is refused rather than faked. The screen will not save
verification that cannot run, and Site Health reports an existing rule in that
state as critical, because such a rule silently matches nobody. On a library too
old to verify at all, the setting is not offered and the compiler skips a rule
carrying it: that library would ignore the key and let every self-declared
crawler through.

### Reading what the CDN worked out

The **Edge signal** rule matches on what a CDN computed at the edge and this
site cannot: a **TLS fingerprint** — `ja3`, `ja4` — which identifies the client
stack rather than what it claims to be, so a script wearing a browser's user
agent still negotiates TLS like a script; and a **bot score**, the edge's own
verdict from signals that never reach the origin. Arrived in
`kanopi/firewall` 2.27.0, which the plugin's ^2.33.1 requirement covers.

Choose the CDN — Cloudflare, Fastly, or *something else* with the header names
typed as `signal: Header-Name`. Akamai and CloudFront are not named on purpose:
Akamai's headers are configured per property and CloudFront computes no bot
signal, so a named profile for either would be invented header names that look
authoritative and match nothing.

Three things to know before writing one:

- **An edge header is a claim, not a fact.** Anything that can reach the site
  directly can send `Cf-Bot-Score: 99`, so the library believes these headers
  only on a request that arrived through a trusted proxy. Without
  [trusted proxies](#proxies-and-the-client-ip) the rule matches nothing and
  logs a warning on every request, and the rule screen says so.
- **None of the headers arrive by default.** Cloudflare's need Managed
  Transforms switched on per zone; Fastly's are set in VCL. A missing header
  matches nothing rather than matching wrongly.
- **Cloudflare's bot score runs backwards.** 1 is certainly a bot and 99
  certainly a human — the opposite of every other score in the firewall. The
  rule that blocks bots is `bot_score` *is less than or equal to* `5`. Written
  the habitual way round, `bot_score` *is greater than* `30` on a block rule
  blocks the humans, and it looks like it is working: what it lets through is
  the automation. Try it with **Observe only** first.

A custom CDN naming no header the library can read, or a signal it does not
know, is refused on the screen and skipped by the compiler: the library refuses
to start on either, and a firewall that cannot start fails open on every rule.

### Where a location or a network comes from

A **Geolocation** rule reads from one of two places, chosen on the rule under
*Reader*; an **ASN** rule reads only the first.

- **A MaxMind database**, looked up on this server. Authoritative, needs no
  proxy configuration, and fills every field — but MaxMind databases cannot be
  redistributed, so the plugin never ships one. Give the path to the `.mmdb`
  file: relative resolves inside the private directory, absolute is used as
  given. A path to a file that is not there yet saves with a warning, because the
  download job may not have run; until it does, the rule matches nothing.
- **The lookup your CDN already did**, read from a request header. Nothing to
  license and no lookup cost — but a geo header is a claim, not a fact. Anything
  that can reach the site directly can send `CF-IPCountry: US`, so the firewall
  believes it only from a trusted proxy, and the rule warns when the site has not
  said it is behind one. Only Cloudflare sends anything unasked, and only the
  country; a field the CDN does not send matches nothing rather than wrongly. For
  a CDN not in the list, map each field to its header, one `field: Header-Name`
  per line. The fields are the library's — `country`, `country.name`,
  `continent`, `city`, `postal`, `region`, `location.latitude`,
  `location.longitude` — and any other is refused, because the library refuses
  to start on it and the firewall then fails open on every rule.

Switching source keeps the other one's settings, so switching back loses nothing.

Conditions use the library's names for what a lookup returns, whichever
source answers: `country`, `country.name`, `continent`, `city`, `postal`,
`location.timeZone`, `location.latitude` and `location.longitude` on a
geolocation rule; `asn` and `asn_org` on an ASN rule. Anything else resolves to
nothing, which is why the rule screens offer no other. Earlier releases offered
`country_name`, `timezone`, `latitude`, `longitude` and `organization`, which
matched nothing; they are rewritten on upgrade and translated if one arrives in
an import. `network`, once offered on the ASN rule, is not something the library
reads at all — a rule still carrying it says so, and a network block belongs in
an IP address rule. Coordinates are floats, so compare them with "is greater
than" or "is less than"; an autonomous system number can be typed with or
without its `AS`.

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

#### Counting something other than the address

A fourth field on a limit line names what to count, comma separated, using the
vocabulary the Request / URL rule uses — `path`, `method`, `host`, `header.x`,
`post.y`, `cookie.z`, `query.q` — plus `client_ip` and `rule_pattern`, which are
what a line without one counts:

```
/wp-login.php 5 300 post.log        # the account being tried, from anywhere
/wp-json/* 100 60 client_ip,path    # each endpoint, rather than the API as a whole
```

`log` is the username field on WordPress's own login form. Arrived in
`kanopi/firewall` 2.27.0, which the plugin's ^2.33.1 requirement covers.

**Read this before reaching for it:** the two key shapes catch opposite attacks,
and swapping one for the other removes protection while looking like it adds
some.

| Keyed by | Catches | Misses |
|---|---|---|
| address | one client hammering many accounts | a botnet against one account |
| identity, such as a posted username | many clients against one account | one client walking a list of usernames, which gets a fresh budget per name |

An identity-keyed limit also **never bans**. The library records no offense for a
key without `client_ip` in it, and the reason is stronger than "the address is not
what misbehaved": the block list is keyed on the address, so banning there would
let an attacker spend a victim's account budget from their own machines and get
the *victim's* address banned — for everything, lengthening each time if
escalation is on. The request is still refused; only the durable ban is
withheld.

So an identity-keyed limit alone leaves brute force unprotected and nothing on
the block list. Keep the address-keyed limit and add the identity-keyed one
beside it, rather than replacing it. The rule screen says so when you save one
without a companion, and Site Health says so for as long as it stays that way.
A key that *includes* `client_ip` — `client_ip, post.log` — is still
address-keyed as far as banning goes, and is not warned about.

**The companion has to be a separate rule.** Within one rate limit rule the
library uses the first line whose pattern matches and never looks further, so
two lines for `/wp-login.php` in the same rule leave the second doing nothing:

```
# Rule "Login accounts"
/wp-login.php 5 300 post.log

# Rule "Login addresses" — a second rate limit rule
/wp-login.php 50 300
```

The screen refuses the same pattern twice in one rule for that reason. (The
library's own documentation shows the pair as two entries in one list, and its
linter accepts that; both are wrong about what the evaluator does.) The pairing
check compares patterns as written, so `/wp-*` in another rule is not recognised
as covering `/wp-login.php` even where it would.

It also counts every attempt against the named account from anywhere, which
means anyone can spend that account's budget for it: five failed logins as
`alice` lock `alice` out for the window. That is the classic account-lockout
trade — choose it when credential stuffing is the bigger worry. Setting
**Record the client** to *Yes* on such a rule overrides the library's refusal to
ban, and hands the ban to whichever address trips the limit next — usually the
account's owner. The screen warns when you do.

Two keys are refused outright, because they would put every request in one
bucket and let one visitor spend the allowance for the whole site: a component
the library cannot resolve (`pots.log`, a bare `post`), and a form field, cookie
or query parameter named with capitals. The library lower-cases every component
before looking it up, which is harmless for a header and means `post.userName`
looks for `username` and finds nothing.

#### Where the counts are kept

Each rate limit rule keeps its own counters — in a file in the private
directory, a database table, or Redis — chosen with **Keep the counters in** on
the rule. A file is enough for one web server; several servers behind a load balancer
each keep their own file and each allow the full limit, so use the database or
Redis there. The Redis password and a DSN are typed and never shown: the field is
always empty, leaving it blank keeps what is stored, and *Remove the stored
value* clears it. Both are stripped from an export and shown as `[redacted]` on
the Compiled screen, and a password is kept by an import only while the Redis
host and port are unchanged.

### Regular expressions

**Write the pattern only.** No delimiters, no flags:

```
^/wp-admin              not   #^/wp-admin#
(sqlmap|nikto|wpscan)   not   #(sqlmap|nikto|wpscan)#i
```

The delimiters are added when the rule compiles, and the *Case sensitive* box
beside the field becomes the `i` flag — so it means the same thing on this
operator as on every other one. A delimiter that appears in your pattern is
handled: the plugin picks one that does not, and escapes if it has to.

A pattern pasted with its own delimiters is unwrapped rather than refused,
because anyone who has written regular expressions before will type them out of
habit. The box still decides the case, so `#foo#i` saved with *Case sensitive*
ticked compiles to `#foo#`.

Two problems disappear with this, both of which were silent:

**An undelimited pattern used to match nothing.** The field accepted
`^/wp-admin`, the library rejected it, and the rule saved and reported itself
active. There was a validation message about it; now there is nothing to warn
about.

**Case-insensitivity used to rewrite the pattern.** The library implements it by
lowercasing both sides of the comparison — and for this operator one side is the
pattern. Lowercasing a pattern does not make it case-insensitive:

| written | would have run as | |
|---|---|---|
| `\D` non-digit | `\d` digit | **inverted** |
| `\W` non-word | `\w` word | **inverted** |
| `\S` non-whitespace | `\s` whitespace | **inverted** |
| `[A-Z]` | `[a-z]` | different class |

So `#\D+#` matched only numbers. The pattern now reaches the library exactly as
assembled, with case carried by its flag, which is where a regular expression
has always expressed it.

Patterns stored by an earlier version are rewritten on upgrade — the delimiters
come off and an `i` flag becomes an unticked box, so nothing changes about what
a rule matches. Nothing depends on that having run: a delimited value is
unwrapped wherever one turns up.

## Presets

A preset is a rule set the firewall library ships — AI crawlers, malicious URLs,
honeypot paths, rate limiting, the Pantheon storage and logging conventions.
Tick one on the Presets screen and it is included **by reference**, not copied,
so it updates when the library does. `wp basic-firewall sources` lists what is
available, and the Compiled screen is the only place that shows what a preset
actually contributed.

The Compiled screen shows every credential in the file as `[redacted]` —
passwords, secret keys, tokens, API keys, a list's headers and the credential in
a list URL — along with anything the settings hold at a secret path, wherever it
was compiled. The file itself keeps them, because the library reads it. An
`%env()%` token is shown as written.

### The `wordpress` preset is withheld

The library ships a `wordpress` preset written for sites that do **not** run
WordPress, where `/wp-admin`, `/wp-login.php`, `/xmlrpc.php` and `/wp-json` are
only ever probes. Enabling it on a WordPress site locks every administrator out
and breaks the block editor.

It is therefore not offered: the Presets screen lists it under *Not available on
this site* with that reason, and the compiler refuses it with the same reason
recorded as a problem if it arrives some other way — an imported document, or a
hand-edited option. Every other preset is unaffected.

### Contributing a preset

`basic_firewall_presets` takes either a path to a YAML file or an inline array:

```php
add_filter( 'basic_firewall_presets', function ( array $presets ): array {
    // A YAML file shipped with your plugin.
    $presets['acme_edge'] = array(
        'label' => 'Acme edge rules',
        'file'  => plugin_dir_path( __FILE__ ) . 'firewall/acme-edge.yml',
    );

    // Or the same thing inline, written out to the private directory on rebuild.
    $presets['acme_inline'] = array(
        'label'  => 'Acme inline rules',
        'config' => array(
            'plugins' => array(
                array(
                    'plugin'   => 'Kanopi\\Firewall\\Plugins\\Url',
                    'response' => 'block',
                    'weight'   => 50,
                    'enable'   => true,
                    'metadata' => array( 'name' => 'acme_probe' ),
                    'config'   => array(
                        array(
                            'variable' => 'path',
                            'operator' => 'equals',
                            'value'    => '/acme-probe',
                        ),
                    ),
                ),
            ),
        ),
    );

    return $presets;
} );
```

Contributed presets appear in the list, are ticked and unticked like any other,
and compile into the same `configs:` includes. As with rule types, a contributed
preset cannot take the name of one the library ships — the shipped one wins and
the collision is recorded, so a plugin cannot change what an already-ticked
preset does without anything in the interface changing.

One thing to know about the merge: an included preset is layered **over** the
document that includes it, so a preset that writes `storage:` or `global:`
replaces what the screens produced. Keep a contributed preset to `plugins:`
unless replacing those is the point.

## Storage

| Backend | Use when |
|---|---|
| File | Single web node. No credentials needed |
| Database | Multiple web nodes, or a block list of any size. Flat lookup cost |
| Redis | Multiple web nodes, and you would rather expiry cost nothing. Needs `ext-redis` |

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

### Redis, and why expiry is the interesting part

File and database storage both sweep expired blocks as they go. Redis does not
need to: a block is stored with a TTL and Redis evicts it itself, so the sweep
has nothing to do at all. The cost is not reduced, it is gone — and that matters
most during an attack, which is exactly when the block list is largest and when
you least want a lapsed batch landing on one unlucky visitor.

The option appears on the Storage screen only where it can work: the library has
the backend and this PHP has `ext-redis`. The library lists the extension as a
Composer *suggest* rather than a *require*, so it installs without it, and since
kanopi/firewall 2.29.0 the backend degrades rather than crashing when it is
missing — which keeps the site up and leaves a block list that stores nothing.
No client is recorded, no repeat offender recognised, nothing escalates. So:

- The Storage screen says which half is missing when Redis is not offered — the
  library or the extension — because they are different fixes.
- A site **already on Redis** that loses the extension keeps the setting, with
  an error on the Storage screen, rather than being quietly moved to file
  storage the next time anything there is saved.
- **Site Health reports it as critical**, as it does in-memory storage, because
  it amounts to the same thing.
- The compiler does not fall back. The compiled file is often written from
  WP-CLI on a box that is not a web node, so the extension being absent there
  says nothing about the nodes serving requests. It warns instead.

**The key prefix.** Left empty it is `firewall:`, which is what the library
would use on its own — and on a network, `firewall:<table prefix>:`, so sites
sharing one Redis do not share one block list. Anything typed is used exactly,
so give each site its own.

**Authentication.** A password alone is the ordinary `requirepass` case; fill in
the username as well only for a server using ACLs. The password is kept as typed
— not trimmed — and never echoed back into the page: leave the field blank to
keep the stored one, or tick *Remove the stored password*. It is written into the
compiled file and stripped from an export, so `%env(YOUR_VARIABLE)%` is the
better answer: that token is not a credential, survives an export, and never
reaches the database.

It is not injected at request time the way WordPress's database credentials
are. Those come from constants that exist on both evaluation paths; this password
lives in the settings option, which the wp-config.php path cannot read without
WordPress. Getting it there would mean writing it to a file beside the compiled
one — the same plaintext on the same disk, with one more file to protect. The
token is the way to keep it off disk.

Redis needs no WordPress credentials, so it works on the wp-config.php
evaluation path exactly as it does on the mu-plugin path. If the server cannot be
reached, the firewall carries on enforcing every rule and Site Health names the
backend it is running without. `ext-redis` also emits a PHP warning of its own
when a connection fails, which the library cannot suppress, so a wrong host is
noisy in the log as well as reported.

### What a block record keeps

When a rule blocks a request, the request is recorded alongside the address. That
record outlives the request by the length of the ban, and the block list is the
artifact people paste into tickets — so each part of the request is kept by
**allowlist**, on the Storage screen. One name per line; a single `*` keeps
everything in that bucket, an empty field keeps nothing.

| Bucket | Default | Why |
|---|---|---|
| Cookies | none | A session cookie is not the firewall's to hold |
| Headers | a short list | The ones that describe a client rather than authenticate it |
| Query parameters | **everything** | For a scanner, the query string *is* the attack |
| Request body | none | A blocked login attempt has the password in it |

Query is the one to think about, and the reason is WordPress rather than the
firewall: `wp-login.php?action=rp&key=…` is a working password reset and
`wp-activate.php?key=…` is an account, so a blocked request to either stores a
usable credential. Narrowing the bucket is not much of an answer — an allowlist
cannot say "everything except this", and enumerating what a scanner might send is
exactly what allowlists are bad at. **Site Health counts how many of your current
records hold one**, which is the actionable version of the same warning.

Redaction happens on the way in, so records written before this existed are
unaffected by the setting. They expire with their bans; clearing the block list
removes them sooner, at the cost of unblocking whoever is in it.

## Caching on hosting where shared storage is slow

The block list is one thing the firewall writes; the other is what it *works
out* — parsed user agents and verified crawler names. All of that is cached, and
by default all of it is cached in files in the private directory, under uploads.

On hosting where uploads is a network mount — most managed WordPress hosting —
this is usually where the firewall spends its time: not one slow read but many
small ones through the request. The Storage screen offers three answers:

| Backend | Use when |
|---|---|
| Files | The default. Leave the directory empty for the private directory, or name somewhere local such as `/tmp/basic-firewall` |
| The WordPress object cache | The site has a persistent object cache — an `object-cache.php` drop-in for Redis or Memcached |
| APCu | No shared cache. Memory per web node, not shared between them |

Everything here can be worked out again. Losing it costs a rebuild, never a
client going unblocked, so a volatile backend is a legitimate choice: APCu is cold
after PHP restarts and a container-local directory is empty after a redeploy, and
neither costs correctness.

**The object cache means a persistent one.** Without a drop-in, WordPress's
object cache is an array that forgets everything when the request ends, and
handing that to the firewall would rebuild the agent detection corpus — the
better part of a second — on every request. So the option is offered only where
the object cache is persistent; a site that chose it and then lost its drop-in
caches in files instead, and Site Health says so. Entries live in a
`basic_firewall` group of their own, per site on a network, and clearing them
never flushes the rest of the site's cache.

**APCu means enabled in the web server's PHP.** It is offered only where it is,
because the library does not fall back to files when the pool it was told to
build cannot be built — it runs detection uncached, roughly 600 ms a request.
Site Health reports that as critical.

**Three reach the wp-config.php path; one cannot.** Files and APCu are written
into the compiled configuration as a pool class and its arguments, which is all
that path has. The object cache is handed to the library as a live object while
WordPress loads, and on the wp-config.php path there is no WordPress to take it
from — so a site using that path keeps files there, and only there.

**One setting covers agent detection and crawler verification together.** A user
agent rule does not say where it caches; the Storage screen does, for every
rule at once. The AbuseIPDB rule is the exception: the library takes a directory
for it and no pool, so it stays on files whatever is chosen.

### The two caches that can only be files

The parsed configuration and the bodies of imported rule lists cannot use the
backend above: both are read on the wp-config.php path before WordPress exists.
They are small — one PHP file the opcode cache then serves from memory, plus one
file per list — but on a network mount they are still reads. Move them with a
constant, which both evaluation paths read:

```php
define( 'BASIC_FIREWALL_CACHE_DIR', '/tmp/basic-firewall' );
```

A constant, not a field on the Storage screen, on purpose. A setting would reach
the mu-plugin path and WP-CLI but not the early path, so cron would refresh the
list bodies into one directory while requests looked for them in another — and
every rule built on a list would match nothing there, without a word. With the
constant set, the AbuseIPDB cache and the files backend's default follow it too,
so nothing the firewall caches touches uploads. What remains there is the
compiled configuration itself, which is read once per request and cannot move,
and whatever the block list and the log are configured to use.

**The block list is not a cache.** Do not reach for this section to make *it*
faster — use database or Redis storage for that, and the database log handler
instead of the file one. Those are the write-heavy settings, and they are where
a site on slow shared storage should look first.

### Building it ahead of time

The agent corpus is the one expensive thing here: identifying an agent means
compiling a 1.7 MB pattern set, and the first request to reach a user agent rule
after a deploy, a clear or a PHP restart pays for it — the better part of a
second. `wp basic-firewall warm-cache` pays it now instead, which is worth a
place in a deployment step. The Storage screen has **Build cached data now**
beside the clear button, and every rebuild — a settings save, an activation, an
upgrade — schedules one on WP-Cron thirty seconds later, so an administrator
saving a form does not pay for it either.

On APCu the button is the only thing that works. APCu memory belongs to the
process pool that filled it, so a warm from the command line fills the command
line's own and leaves the web server's cold; the command says so rather than
reporting a success that means nothing. A scheduled warm reaches it only when
WP-Cron runs in a web request — not with `DISABLE_WP_CRON` and a system cron
calling WP-CLI.

It builds only what the rules read. The library stops parsing at the deepest
phase the conditions ask for, so a site whose rules only ask `automated` gets the
bot corpus and not the client, OS and device corpora it never looks at. A rule
with *Cache agent detection* off is left alone.

Only the agent corpus can be built ahead of time. Everything else the firewall
caches — reverse-DNS and AbuseIPDB verdicts — is keyed on the visitor's address,
and there is nothing to work out for an address that has not arrived.

### Clearing it

**Clear cached data** on the Storage screen discards what the firewall has
cached, on every backend rather than only the current one — switching backends
leaves the old one warm. Two things are kept: the parsed configuration and the
imported list bodies, because the firewall is weaker until they come back.
`wp basic-firewall clear-cache` does the same, with one exception it cannot fix:
APCu memory belongs to the process pool that filled it, so a clear from the
command line empties the command line's own APCu and leaves the web server's
untouched. The button runs in a web request, which is the only place that clear
can reach. WordPress has no "clear all caches" moment to hook, and
`wp cache flush` reaches neither files nor APCu.

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

### Off the request path

Every handler has a **Send after the visitor has their response** option. It holds
records in memory and flushes them after the response has been sent, so a slow
destination is not a slow page. It buys nothing for a local file, which is already
fast; it earns itself on anything that makes a network round trip — a database on
another host, or a handler you add through the advanced YAML that posts to a log
service. The cost is that a fatal error before shutdown loses the buffer, which is
the right trade for a firewall log and the wrong one for an audit log.

The advanced YAML can now nest handlers, which the library gained in 2.31.0 —
before it, a wrapping handler could not be expressed in configuration at all:

```yaml
logger:
  # Hold debug records in memory; write them only if something goes wrong.
  - class: Monolog\Handler\FingersCrossedHandler
    args:
      - class: Monolog\Handler\StreamHandler
        args: [/var/log/firewall/firewall.log, Monolog\Level::Debug]
      - Monolog\Level::Error
```

## Reacting to a decision

Every verdict is announced as a WordPress action, so a plugin can react to one
without polling the block list or parsing the log:

```php
add_action( 'basic_firewall_decision_blocked', function ( $event ) {
    if ( ! $event->isEnforced() ) {
        return; // Log mode: the rule matched, but nothing was refused.
    }

    $rule   = $event->getPlugin()?->getName() ?? 'block list';
    $status = $event->getStatusCode();
    $ip     = $event->getRequest()->getClientIp();
} );

// Or every decision, with its kind:
add_action( 'basic_firewall_decision', function ( $event, string $type ) {
    // $type is one of the names below.
}, 10, 2 );
```

| `$type` | Announced when |
| --- | --- |
| `allowed` | Nothing matched, or an allow rule matched |
| `blocked` | A blocking rule matched, or the client was already on the block list |
| `challenged` | A visitor was asked to solve a challenge |
| `challenge_solved` | They solved it |
| `challenge_failed` | They did not |
| `recorded` | A rule recorded the client without refusing them |
| `redirected` | A rule sent the visitor elsewhere |
| `marked` | A rule marked the request for downstream code |
| `tarpitted` | A rule held the request before letting it continue |

The Drupal module hands the library Drupal's own event dispatcher, which is
already PSR-14. WordPress's equivalent is an action, so this plugin passes a
small PSR-14 dispatcher that turns each decision into the two actions above. A
few things follow from that, and are worth knowing before you build on it:

- **Switch on `$type`, and duck-type the event.** Do not type-hint
  `Kanopi\Firewall\Event\RequestBlocked`: in a release zip the library is
  namespace-scoped, so that class name does not exist there and the callback
  fatals. `getRequest()` and `isEnforced()` are on every event; `getPlugin()` and
  `getStatusCode()` on a block.
- **`getStatusCode()` is the rule's own code.** A rule left on the site-wide code
  reports `0`: the library announces before it resolves that to the General
  screen's status code. Set a code on the rule if a listener needs the number.
- **A listener cannot change the verdict.** The events carry no setters and an
  action's return value is discarded. Blocking decisions belong to rules.
- **A listener that throws is not an outage.** The exception is written to the
  PHP error log and the request carries on exactly as it would have — though
  WordPress stops the rest of that action's callbacks for that decision. It also
  means a listener is not the place for anything the request depends on: if it
  fails, traffic will not tell you.
- **`isEnforced()` is how log mode is visible.** In log mode a decision is still
  announced, carrying the rule and the status it *would* have returned, with
  `isEnforced()` false. That is what lets you measure a new rule against live
  traffic before switching it on.

**When they arrive.** The firewall evaluates at `muplugins_loaded`, before any
regular plugin or theme has loaded, so an action fired there would reach only
mu-plugins. Decisions are held and announced at `plugins_loaded` instead, once
plugins have had the chance to listen. A refusal ends the request before that,
so it is announced at shutdown — by which point WordPress has only loaded
mu-plugins, so **to hear refusals, listen from an mu-plugin**. On the
[wp-config.php path](#the-one-line-that-matters) the decisions that let a
request through wait for WordPress in the same way, but a refusal exits before
WordPress loads at all and is **never announced**.

`basic_firewall_request_marked`, [above](#responses), predates this and fires as
the mark is made — on the ordinary path, at `muplugins_loaded`. From a regular
plugin, listen for `basic_firewall_decision_marked` or ask `Runner::is_marked()`
instead.

For metrics, prefer the library's own StatsD listener, declared under
`metrics.statsd` in the Advanced YAML: it runs inside the library, on both
paths, refusals included, and a Prometheus counter would not survive the
PHP-FPM process that incremented it anyway.

## Export and import

WordPress has no `drush config:export`, so this **is** the deployment story and
it carries more weight here than it does in Drupal.

```bash
wp basic-firewall export --file=firewall.yml
wp basic-firewall import firewall.yml --dry-run
wp basic-firewall import firewall.yml --mode=replace --yes
```

### One rule at a time

A single rule travels on its own, which is how a rule written on one site
reaches another without carrying that site's storage, logging and challenge
settings with it:

```bash
wp basic-firewall export --rule=login-rate-limit --file=login-rate-limit.yml
wp basic-firewall import login-rate-limit.yml --yes
```

The Rules screen has both ends of this: **Export** on each row, and **Import a
rule** below the table, taking a pasted document or an uploaded file. That
import is always a merge — a document arriving there holds one rule, and the
mode that empties every other section is not something anyone reaches for from a
list of rules. A rule whose identifier is already in use is replaced, and you
are told which rules were added and which were replaced rather than given a
count.

A single-rule document is an ordinary configuration document with one rule in
it, so the full Import screen accepts it too.

Three behaviours are guaranteed, and each has a test that fails if it regresses:

**Credentials are stripped, and the document says which.** Every rule type
declares which of its own settings are secret, so a type contributed by another
plugin has its API key redacted without the exporter knowing the type exists.
Every type that takes a referenced list has the list's credentials stripped as
well, and a list URL is exported with any credential in it replaced by `***`;
the header names those URLs separately.

**`%env(NAME)%` tokens are references, not secrets, and survive intact.** A token
names an environment variable rather than holding one, so stripping it would
break the receiving site and protect nothing.

**An empty credential on import means "not carried", never "set to nothing".**
This is the direction that does damage: writing a stripped export over a
receiving site would erase its challenge secret — and a firewall that cannot
start fails open, so every rule silently stops being enforced while the interface
goes on reporting "Blocking".

**A kept credential goes only where it went before.** A stored password is kept
only while the settings it belongs with are unchanged: the Redis host, port and
username, a database connection's driver, host, port and user, a log handler's
type and table, a CAPTCHA's site key, a list's URL. A document that points any of
those somewhere new without carrying the credential gets it blanked instead, and
the preview — on the screen and from `wp basic-firewall import` — names each one
and what changed. A URL exported with `***` is restored from the stored copy when
the two match apart from the credential. Rules are matched by identifier, so
reordering them moves nothing to the wrong rule.

## During an incident

### Lockdown: refuse everyone but a list

Under attack and want only the office in? Tick **Lockdown** near the bottom of
the General screen and name the addresses to keep serving. Every other rule stops
mattering: a client not on that list is refused before any rule is consulted,
with a 503 and `Retry-After` — temporary, which is what a CDN needs to hear
rather than caching the refusal as a verdict.

The part that makes this worth having rather than building it from an allow rule
and a block-everything rule: **nobody is recorded**. That pairing refuses the
same traffic and writes every refused client to the block list — an internet's
worth of addresses, during exactly the incident when your storage is under the
most pressure, each left on an escalating ban once the lockdown is lifted.

Four things to know before you reach for it:

- **An empty allowlist serves nobody.** The library treats absent and empty
  alike, which is the honest reading of the word. The General screen refuses to
  save that combination, and the compiler refuses it from an import or WP-CLI
  too — reported, and not applied.
- **Addresses, CIDR blocks and `start-end` ranges**, the forms an IP rule
  takes. Ranges match from kanopi/firewall 2.33.1, which is why the plugin
  requires it; before that the library kept a range here and matched nobody. A
  range written backwards (`.20-.10`) or mixing IPv4 and IPv6 is refused on
  save, because the library refuses it too rather than guess.
- **Check your own address is on the list.** The screen shows the address the
  firewall sees for you — after trusted proxies, so behind a CDN it is yours and
  not the CDN's — and warns if the list does not cover it. A warning rather than
  an error, because allowlisting the office range from a laptop elsewhere is a
  real thing to want. `define( 'BASIC_FIREWALL_ENABLED', false )` is the way back
  in if you get it wrong.
- **The panic file can arm it too**, with `echo lockdown > /path/to/panic`,
  which is the no-deploy route into it and out again. See below.

While it is on, Site Health reports it as critical, the Status screen leads with
it and `wp basic-firewall status` carries a `Lockdown` row.

### Turning the firewall down without a deploy

`BASIC_FIREWALL_MODE` works, but it lives in `wp-config.php`, and on most
hosting changing that file is a release — which is the wrong speed when a rule is
refusing real customers.

Set a **panic file** at the bottom of the General screen, then during an
incident:

```console
echo log > /path/to/panic    # stop enforcing, keep recording
rm /path/to/panic            # back to the configured mode
```

No deploy, no cache flush, no restart, on either evaluation path. It costs one
`is_file()` per request while a path is set, and nothing at all while it is not.
A relative path resolves inside the private directory, which is guarded against
web access; wherever it goes, keep it out of anything a deploy recreates. A file
that turns the firewall down is worth exactly as much as write access to its
path, which is also why there is no default.

The file has to **name** a mode — `block`, `log`, `exception`, `disabled`, or
`lockdown`, which refuses everyone but the [lockdown
allowlist](#lockdown-refuse-everyone-but-a-list), so fill that in first. An
empty file, a typo, or one that cannot be read changes **nothing** and is
reported as a problem. That is deliberate: if any file at all meant "off", one
left behind from an incident last month would disable the firewall and nothing
would say so.

While it is active, Site Health reports it as critical and names both the
effective and the configured mode — which also puts it in an admin notice on
every screen — the Status screen leads with it, and `wp basic-firewall status`
reports it on the `Mode` and `Panic file` rows. The realistic failure here is not
somebody flipping it; it is nobody noticing three weeks later that the site has
been in log mode since the incident.

`BASIC_FIREWALL_MODE` still wins over the panic file, so an environment that pins
the mode keeps it pinned. The request tester ignores the file too: it answers
what the rules decide, not what an incident has them doing.

## wp-config.php options

### The one line that matters

Everything below is optional. **This is not.** Without it the firewall still
works, but it runs from an mu-plugin — after `advanced-cache.php` has already
served and exited on a cache hit, which on a busy cached site is most of your
traffic. The snippet is what moves evaluation ahead of WordPress entirely:

```php
require_once ABSPATH . 'wp-content/plugins/basic-firewall/bootstrap.php';
basic_firewall_evaluate( array(
    'private_path' => '/path/to/uploads/basic-firewall-private-abc123',
) );
```

Four ordering rules, and each one has a failure attached to it:

| Put it | Or else |
|---|---|
| **below** the `DB_` constants | database block storage cannot build a connection and fails open |
| **below** `define( 'ABSPATH', … )` | fatal error on every request — the snippet uses `ABSPATH` |
| **below** any `BASIC_FIREWALL_*` constants | the bootstrap reads them at call time, so ones defined after it are ignored on this path and silently apply only to the mu-plugin one |
| **above** `require_once ABSPATH . 'wp-settings.php'` | WordPress has already booted; there is nothing left to skip |

The Status screen prints it with your site's real private path filled in. You
cannot write it yourself: the directory carries a random per-site suffix.

### Everything else

All optional, all added by hand. This plugin never writes to `wp-config.php`.

```php
// Switch the firewall off entirely. Needs no database access.
define( 'BASIC_FIREWALL_ENABLED', false );

// Force a mode regardless of what is configured: block, log, exception, disabled.
// Wins over a panic file too.
define( 'BASIC_FIREWALL_MODE', 'log' );

// Supply the challenge signing secret without storing it in the database.
define( 'BASIC_FIREWALL_CHALLENGE_SECRET', getenv( 'FIREWALL_CHALLENGE_SECRET' ) );

// Addresses permitted to declare the client address.
define( 'BASIC_FIREWALL_TRUSTED_PROXIES', array( '10.0.0.0/8' ) );

// Allow %file(...)% tokens to read secrets from these directories, and only
// these. Off entirely when unset.
define( 'BASIC_FIREWALL_SECRET_DIRECTORIES', array( '/etc/firewall' ) );

// Never rewrite the installed mu-plugin loader when a release ships a new one.
// For mu-plugins deployed from version control; Site Health still says when
// the copy there is out of date.
define( 'BASIC_FIREWALL_MU_LOADER_REFRESH', false );

// Which forwarding headers a trusted proxy may set. Defaults to
// X-Forwarded-For, -Proto and -Port; deliberately NOT -Host, because the host
// decides which site a request belongs to and which URLs get generated, and
// trusting a forwarded host is how cache poisoning and malicious
// password-reset links start. Only override it if your proxy needs something
// else, and pass Symfony's Request::HEADER_* bitmask.
define( 'BASIC_FIREWALL_TRUSTED_HEADERS', Request::HEADER_X_FORWARDED_FOR );

// Keep the parsed configuration and imported list bodies somewhere other than
// uploads -- local disk, where uploads is a network mount. Read on both paths.
define( 'BASIC_FIREWALL_CACHE_DIR', '/tmp/basic-firewall' );

// Let rule sources fetch over the network during a request. Off unless
// explicitly false: a firewall that makes an outbound HTTP call while a
// visitor waits is a firewall that fails when the network does.
define( 'BASIC_FIREWALL_SOURCES_OFFLINE', false );
```

The last three are read on **both** evaluation paths, so they belong above the
bootstrap snippet like the rest.

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
wp basic-firewall refresh-sources   # re-fetch the lists rules reference

wp basic-firewall check IP          # is this address blocked?
wp basic-firewall block IP          # block it
wp basic-firewall unblock IP        # unblock it
wp basic-firewall blocked           # list every blocked client
wp basic-firewall clear-blocked     # empty the block list
wp basic-firewall clear-cache       # discard parsed agents and verified crawlers
wp basic-firewall warm-cache        # build the agent corpus before a visitor has to
wp basic-firewall find-reference REF # which rule produced this block reference

wp basic-firewall export            # portable document, credentials stripped
wp basic-firewall import FILE       # read one back, --dry-run to preview
```

`check` exits 0 whether or not the address turned out to be blocked — the exit
status reports whether the *query* ran. Read the `blocked` field.

Anything destructive refuses to run without `--yes` and exits non-zero when it
refuses. It will never exit 0 having done nothing.

`sources` lists **presets**; `refresh-sources` re-fetches the **lists a rule
references**. Two different things, and the names do not currently say so.

All of it is covered by `tests/cli/commands.sh`, which runs `wp` for real rather
than calling PHP, and so is the only place the subcommand registration and the
exit statuses are checked:

```bash
BFW_WP="ddev wp" bash tests/cli/commands.sh
```

Agreeing to a destructive command is opt-in through `BFW_CLI_DESTRUCTIVE=1`, so
running it against a site you care about does not empty its block list. CI opts
in, because its site goes away with the runner.

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

The one shared piece is the mu-plugin loader, because mu-plugins is shared. Every
site of a network runs the same copy of the plugin and so wants the same loader:
whichever site refreshes it first leaves the others finding it current, and a
refresh that cannot write the directory is recorded as a network option rather
than against the site that noticed.

There is no network-wide settings screen. Configuring 200 sites means
`wp site list --field=url` and a loop.

## Uninstalling

Deactivating is reversible: it removes the mu-plugin loader and the compiled
file and keeps everything else. **Delete** is not. It removes, on every site of
a network:

- every `basic_firewall_*` option and transient, the scheduled events, and the
  `basic_firewall_blocked`, `_offenses`, `_log` and `_ratelimit` tables;
- the private directory — under uploads, the `WP_CONTENT_DIR` fallback, and
  wherever the `basic_firewall_private_path` filter puts it;
- the block list, offense history, rate limit counters and log files at every
  path the settings name, with their `.lock` files and rotated copies;
- the files cache backend's pools, and what the library wrote into
  `BASIC_FIREWALL_CACHE_DIR`;
- the Redis block list and Redis rate limit counters, by `SCAN` and `DEL` under
  their prefix — never `KEYS`, never `FLUSHDB`;
- the `basic_firewall` object cache group and the plugin's APCu entries;
- the mu-plugin loader and the capabilities.

### What it will not delete

A stored path can point anywhere — `/var/log/syslog` is a valid log handler
path — so uninstall only deletes inside a directory it can tell is the plugin's:

- one the plugin **created**, which carries a `.basic-firewall-owner` file.
  Only these are removed as directories;
- one the plugin **guards**, which carries its `.htaccess` or `web.config`. The
  plugin's own files come out; the directory, and anything else in it, stays;
- the private directory itself, which its random suffix identifies.

Symlinks are removed as links and never followed. Everything else is left in
place, and WP-CLI prints a warning for each thing left:

```
wp plugin uninstall basic-firewall --deactivate
```

The Plugins screen deletes over Ajax and has nowhere to show those warnings, so
these are the cases to check by hand:

- **A stored file outside any directory the plugin created or guards** — an
  absolute log or storage path you chose. Delete it yourself.
- **A filtered private directory that existed before the plugin used it**, or
  that an older release created: emptied of the plugin's files and left.
- **`BASIC_FIREWALL_CACHE_DIR`**, unless the plugin created it or it is named for
  the plugin (as `/tmp/basic-firewall` is). A directory such as `/tmp` is not
  touched; remove its `compiled`, `sources`, `device-detector`,
  `kanopi_firewall_rdns` and `abuseipdb` directories yourself.
- **Redis, when the server is unreachable or ext-redis is missing** at uninstall
  time. Block records expire with their ban; offense histories and permanent
  bans do not. A Redis backend that is configured but no longer selected is not
  contacted at all: on a single site its default prefix is the library's bare
  `firewall:`, which another application on the same server could share.
- **The object cache**, when the drop-in cannot flush a single group
  (`wp_cache_supports( 'flush_group' )`, WordPress 6.1 or later and a drop-in
  that implements it). Entries are left to expire.
- **APCu, when uninstalling from WP-CLI.** APCu belongs to the process that
  filled it; the web server's entries expire on their own, or restart PHP-FPM.
- **A table renamed on the Storage screen, or kept in another database** through
  a DSN. Only the four default names are dropped, because a `DROP` built from a
  stored name is one an imported settings document could aim anywhere.
- **`firewall_rate_limit_storage`**, unprefixed. A pre-release build counted
  database-backed rate limits into it by mistake; so can anything else using
  kanopi/firewall on the same database, and nothing in it says which. Uninstall
  names it when a rule could have written to it.
- **Networks larger than 500 sites.** Uninstall visits the first 500; beyond
  that, run `wp plugin uninstall` per site.

## Continuous integration

CircleCI, in `.circleci/config.yml`. Twelve jobs on every push, a thirteenth on
a release tag, and none of them advisory:

| Job | Runs |
|---|---|
| `static` | `check-platform-reqs --no-dev`, PHPCS, PHPStan — on 8.1, the declared floor |
| `unit-php-*` | The unit suite on 8.1, 8.2, 8.3, 8.4 and 8.5 |
| `integration-*` | Integration, end-to-end over real HTTP, and the WP-CLI suite, against WP 6.4/PHP 8.1, WP latest/PHP 8.3, and WP nightly on both PHP 8.4 and 8.5 |
| `versions` | `build/check-versions.sh`: the plugin header, `BASIC_FIREWALL_VERSION` and `readme.txt`'s `Stable tag` agree. On a tag, the tag and the newest CHANGELOG heading must agree too |
| `package` | Builds the zip, then `tests/package/smoke.sh` on a clean WordPress with the Composer binary removed from `PATH`: installs and activates the zip, checks it loaded scoped, imports a block rule, asserts over HTTP that an unmatched request gets 200 and the matched one a 403 with the configured message, then deactivates and uninstalls and checks both exit 0 and leave nothing behind |
| `release` | Tags only, after every job above has passed. Publishes the zip `package` tested to a GitHub Release; see [Releasing](#releasing) |

The two nightly rows differ only in PHP, which is the point: a failure on 8.5
that passes on 8.4 says "PHP 8.5" rather than "WordPress trunk moved".

`static` runs on the floor deliberately: the lock is resolved for PHP 8.1 by
`config.platform`, and `check-platform-reqs` there is what stops a dependency
bump quietly raising the version the plugin claims to support. `package` runs on
8.3 because PHP-Scoper needs it — the builder's PHP never reaches the zip, since
the tree it rewrites comes from the plugin's own lock.

Every job can be reproduced locally in the image CI uses:

```bash
docker run --rm -v "$PWD":/src:ro cimg/php:8.1 bash -c \
  'cp -a /src/. /w/ && cd /w && composer install && composer lint && composer analyse'
```

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

The build proves the zip's classes resolve; it does not prove the zip works as
a plugin. `tests/package/smoke.sh` does, and CI runs it on every push. To run it
yourself you need a WordPress you can throw away, with no copy of this plugin,
served over HTTP — the script installs the zip, changes the site's settings, and
uninstalls at the end:

```bash
BFW_WP="wp --path=/tmp/clean" BFW_SMOKE_URL=http://127.0.0.1:8081 \
  bash tests/package/smoke.sh build/dist/basic-firewall-1.0.0.zip
```

Not against the ddev site: it is the one you develop on, and the plugin is
already on it.

## Releasing

Releases are published to
[GitHub Releases](https://github.com/kanopi/basic-firewall-wp/releases), with
the zip attached and the changelog entry as the notes, by CircleCI when a
version tag is pushed. Composer users get the same release from the tag itself
(see [With Composer](#with-composer)). Nothing is published to wordpress.org;
see [Deliberately out of scope](#deliberately-out-of-scope).

### Procedure

1. **Bump every stated version, together**, on a branch, to the new version
   (`1.1.0`, or `1.1.0-rc.1` for a pre-release):
   - `Version:` in the header of `basic-firewall.php`
   - `define( 'BASIC_FIREWALL_VERSION', ... )` in the same file
   - `Stable tag:` in `readme.txt`
2. **Changelog.** In `CHANGELOG.md`, rename `## [Unreleased]` to `## [1.1.0]`
   (a trailing ` - YYYY-MM-DD` is fine) and start a fresh, empty
   `## [Unreleased]` above it. Update `== Changelog ==` in `readme.txt` to match.
   The `## [1.1.0]` section, up to the next heading, becomes the release notes
   word for word.
3. **Check it** before opening the pull request:

   ```bash
   bash build/check-versions.sh --release 1.1.0
   bash build/release-notes.sh 1.1.0     # the notes, as they will be published
   ```

4. **Merge** once CI is green.
5. **Tag the merge commit on `main` and push the tag:**

   ```bash
   git checkout main && git pull
   git tag -a v1.1.0 -m "Basic Firewall 1.1.0"
   git push origin v1.1.0
   ```

   `1.1.0` and `v1.1.0` both work. Anything matching `/^v?\d+\.\d+\.\d+.*/`
   is a release tag.

### What CI does with the tag

The tag runs the whole workflow again, on the tagged commit: `versions`,
`static`, the full unit and integration matrix, and `package`. Then, only if
every one of them passed, `release`:

- runs `build/check-versions.sh` against the tag, and refuses if the tag, the
  header, the constant, the Stable tag and the newest CHANGELOG heading do not
  all say the same version — the usual cause is a tag pushed before the bump;
- takes the zip `package` just built and exercised, byte for byte, rather than
  rebuilding it;
- cuts the notes with `build/release-notes.sh`;
- creates the GitHub Release with `gh`, attaching the zip twice: as
  `basic-firewall-<version>.zip`, and as `basic-firewall.zip` so the
  `releases/latest/download/basic-firewall.zip` URL in
  [With WP-CLI](#with-wp-cli-recommended) always means the current release.
  A version with a pre-release suffix (`1.1.0-rc.1`) is published as a GitHub
  **pre-release**, so it is never shown as Latest and that URL never serves it. Re-running the job for a tag
  that already has a release replaces the zip and the notes instead of failing.

A branch build never publishes: the `release` job's filters ignore every branch,
and the job itself refuses to run without `CIRCLE_TAG`.

A red nightly-WordPress job holds a release like any other job. Re-run the
workflow once trunk settles rather than releasing past it.

### One-time setup: the token

The `release` job reads a GitHub token from a CircleCI **context** named
`basic-firewall-release`. Until that exists, every tag build fails at the
`release` job, with everything before it still green.

1. Create a token that can write this repository's releases — either a
   fine-grained personal access token (or GitHub App token) scoped to
   `kanopi/basic-firewall-wp` with **Contents: Read and write**, or a classic
   token with the `repo` scope. Prefer the fine-grained one, owned by a bot or
   service account rather than a person.
2. In CircleCI, **Organization Settings → Contexts → Create Context**, named
   exactly `basic-firewall-release`.
3. Add an environment variable to it named exactly **`GITHUB_TOKEN`** with the
   token as its value.
4. Restrict the context to the security group allowed to cut releases, so a
   pull request cannot reach the token.

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
