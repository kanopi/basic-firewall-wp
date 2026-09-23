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

The Dashboard always prints the snippet with your site's real private path
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
| Rate limit | Requests per address, per time window, per pattern |
| ASN | Autonomous system number or organisation. Needs a MaxMind ASN database |
| Geolocation | Country, continent, city, postal code, timezone. MaxMind database or CDN headers |
| Vulnerability score | Method, country, network, attack patterns, user agent — summed |
| IP reputation | AbuseIPDB confidence score. Free API key, one cached lookup per visitor per day, fails open |
| OWASP Core Rule Set | The full CRS ruleset, via `kanopi/crs-engine` |

### Responses

Six, evaluated in order, and a match ends evaluation. Within a group, lower
weights run first.

| Response | What happens | Recorded? |
|---|---|---|
| **Allow** | Let the request through and stop evaluating | no |
| **Challenge** | Serve an interstitial the visitor must solve | no |
| **Mark** | Let the request through, and flag it | only if you say so |
| **Record** | Let the request through, and block them next time | yes |
| **Redirect** | Send the visitor somewhere else | only if you say so |
| **Block** | Reject the request | yes, unless you say not to |

The last four need `kanopi/firewall` 2.26.0 or later. On an older library they
are not offered, and a rule carrying one is skipped at compile time with a
warning rather than compiled into something the library would never evaluate.

**Refusing and recording are separate.** That split is what makes two common
setups possible:

- **A honeypot.** A rule catching a scanner on a bait URL wants it blocked
  *next* time, not to refuse the fetch it is already answering — refusing tells
  the scanner exactly which URL is wired, which is the one thing a honeypot must
  not do. That is `record`, or `mark` if you only want the signal.
- **A lockdown.** A rule that refuses everybody and records them leaves a block
  list full of customers once it is lifted, each on an escalating ban nobody
  asked for. Set **Record the client** to *No* on the block rule.

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
stripped from an export like every other credential the plugin holds. Prefer an
`%env()%` token over the literal value. Two things are refused outright when you
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

Not offered on rate limiting, IP reputation, vulnerability score or the Core
Rule Set: none of those matches a list of values. The rule screen asks each type
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

**`%env(NAME)%` tokens are references, not secrets, and survive intact.** A token
names an environment variable rather than holding one, so stripping it would
break the receiving site and protect nothing.

**An empty credential on import means "not carried", never "set to nothing".**
This is the direction that does damage: writing a stripped export over a
receiving site would erase its challenge secret — and a firewall that cannot
start fails open, so every rule silently stops being enforced while the interface
goes on reporting "Blocking".

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

The Dashboard prints it with your site's real private path filled in. You cannot
write it yourself: the directory carries a random per-site suffix.

### Everything else

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

// Which forwarding headers a trusted proxy may set. Defaults to
// X-Forwarded-For, -Proto and -Port; deliberately NOT -Host, because the host
// decides which site a request belongs to and which URLs get generated, and
// trusting a forwarded host is how cache poisoning and malicious
// password-reset links start. Only override it if your proxy needs something
// else, and pass Symfony's Request::HEADER_* bitmask.
define( 'BASIC_FIREWALL_TRUSTED_HEADERS', Request::HEADER_X_FORWARDED_FOR );

// Let rule sources fetch over the network during a request. Off unless
// explicitly false: a firewall that makes an outbound HTTP call while a
// visitor waits is a firewall that fails when the network does.
define( 'BASIC_FIREWALL_SOURCES_OFFLINE', false );
```

Both of the last two are read on **both** evaluation paths, so they belong above
the bootstrap snippet like the rest.

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

There is no network-wide settings screen. Configuring 200 sites means
`wp site list --field=url` and a loop.

## Continuous integration

CircleCI, in `.circleci/config.yml`. Eleven jobs, and none of them advisory:

| Job | Runs |
|---|---|
| `static` | `check-platform-reqs --no-dev`, PHPCS, PHPStan — on 8.1, the declared floor |
| `unit-php-*` | The unit suite on 8.1, 8.2, 8.3, 8.4 and 8.5 |
| `integration-*` | Integration, end-to-end over real HTTP, and the WP-CLI suite, against WP 6.4/PHP 8.1, WP latest/PHP 8.3, and WP nightly on both PHP 8.4 and 8.5 |
| `package` | Builds the zip and installs it on a clean WordPress with the Composer binary removed from `PATH` |

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
