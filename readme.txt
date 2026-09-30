=== Basic Firewall ===
Contributors: kanopistudios
Tags: security, firewall, rate limiting, bot protection, waf
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 8.1
Stable tag: 1.0.0-rc.5
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Evaluates every request against a set of rules and allows, challenges or blocks
it, as early in the request as WordPress can act.

== Description ==

Basic Firewall evaluates every incoming request against rules you configure and
allows, challenges or blocks it before WordPress loads its theme, starts a
session or authenticates anyone. Traffic you reject costs almost nothing to
serve.

It is the WordPress port of the Drupal module `basic_firewall`, built on the
`kanopi/firewall` library, and it keeps that module's habit of writing down what
does not work as well as what does.

**Ten rule types**

* IP address — single addresses, CIDR blocks, ranges, IPv4 and IPv6
* Request / URL — method, host, path, port, query parameters, posted fields, headers, cookies
* User agent — parsed, not string-matched
* Rate limit — requests per address or per account, per pattern, per window
* Edge signal — the TLS fingerprint or bot score your CDN computed
* ASN — turn away a whole hosting provider or VPN
* Geolocation — from a MaxMind database or your CDN's headers
* IP reputation — AbuseIPDB, cached, fails open
* Vulnerability score — adds up method, attack pattern, user agent, country and network scores, and matches at the risk levels you set
* OWASP Core Rule Set

**What it costs**

Evaluation is additive to every request, cached or not. On the reference
measurements that is single-digit milliseconds — around 3.8 ms for six rules and
two presets. This is a correctness tool, not a throughput one: you are buying
protection with latency. The readme has the full table, including the two ways
people usually measure it wrong.

**What it cannot do**

No PHP firewall can touch a host edge cache. On Pantheon, WP Engine, Kinsta or
anything behind a CDN, requests served by the platform's cache never reach PHP
and are never evaluated. Database-backed block storage on the optional
wp-config.php evaluation path needs the snippet below the `DB_` constants, where
the credentials already exist; placed above them, the site fails open while
reporting itself as blocking, and Site Health says so.

**Safe by default**

The plugin installs in log-only mode with no rules. Nothing is blocked and
nothing matches until you say so. Add your own address as an Allow rule, read
the log for a few days, then switch to Block.

If you do lock yourself out, `define( 'BASIC_FIREWALL_ENABLED', false );` in
wp-config.php takes effect on the next request and needs no database access.

== Installation ==

With WP-CLI, which always installs the current release:

`wp plugin install https://github.com/kanopi/basic-firewall-wp/releases/latest/download/basic-firewall.zip --activate`

Run it again with `--force` to upgrade. The plugin is not on wordpress.org, so
`wp plugin update` has nowhere to look for a newer version.

Or through the admin:

1. Download `basic-firewall.zip` from the GitHub Releases page,
   https://github.com/kanopi/basic-firewall-wp/releases
2. Upload it through Plugins → Add New → Upload Plugin, and activate it.

Either way, then visit Firewall → Status and read the checks.

The zip ships with the firewall library vendored and namespace-scoped, so no
Composer, shell access or build step is needed on the server, and it cannot
collide with another plugin bundling the same library.

Composer installation also works. The package is not on Packagist yet, so
point Composer at the repository first:

`composer config repositories.basic-firewall vcs https://github.com/kanopi/basic-firewall-wp`

`composer require kanopi/basic-firewall-wp:^1.0`

In that mode the library is resolved normally and is not scoped.

== Frequently Asked Questions ==

= Site Health says my private directory is readable over the web. =

It probably is. WordPress has no private file system. The plugin writes
.htaccess and web.config guards, and nginx reads neither — index.php only
prevents a directory listing, not a direct request for a file. The directory
name carries a random suffix to make it hard to guess, but the real fix is a
rule in your web server configuration or moving the directory outside the web
root with the `basic_firewall_private_path` filter. Site Health prints the nginx
snippet.

= Why is my rule not matching anything? =

Two causes account for almost all of it. A geolocation or edge signal rule
reading your CDN's headers on a site that has not declared its trusted proxies:
the headers are ignored, and the rule warns. Or a user agent rule using `bot`
rather than `automated`: `bot` is a curated crawler database that does not
classify sqlmap, curl or python-requests. Use the Test screen; it shows
exactly what was compared against what. A rule with an activity window matches
nothing while it is asleep, and the rule list says when that is.

= Why did the firewall block me? =

Almost certainly you tested it against your own site. A rate limit counts your
requests, records an offense and adds your address to the block list.
`wp basic-firewall clear-blocked --yes` releases everything.

= Does it work behind Cloudflare? =

Yes, but you must declare your trusted proxies in wp-config.php or every visitor
appears to come from the CDN — one visitor's offense then blocks everybody.
Site Health raises this, and detects DDEV, Lando and Docksal locally, which
proxy too.

== Screenshots ==

1. The Status screen, with the Site Health checks inline.
2. The rule list, in evaluation order.
3. Testing a request without recording anything.
4. Blocked clients, with an address lookup that works on every backend.

== Changelog ==

= 1.0.0-rc.5 =
* Diagnostics for the wp-config.php early path: the last web request's report and the last anomaly (including failed rules and mode or compiled-file mismatches) in wp basic-firewall status, the new wp basic-firewall early-report and Site Health.
* A request the firewall lets through because it failed is logged to the PHP error log (rate-limited), as is an early path that is called but does not evaluate. BASIC_FIREWALL_DEBUG adds an X-Basic-Firewall-Early response header for troubleshooting.
* Credentials in the Advanced settings YAML are redacted on screen and in exports; the Redis password can be supplied by BASIC_FIREWALL_REDIS_PASSWORD so it is never written to the compiled file.
* The early path no longer loads a second Composer autoloader when the library is already loaded.
* Bundles kanopi/firewall 2.35.1, which changes what some existing rules do: ASN equality rules start matching (and asn not_equals stops matching that network), paths are normalised, the WordPress presets match at any depth, and rate-limit paths ignore case. See the changelog's What changes on upgrade.
* The "verification cookie did not come back" notice now shows in block mode too.

= 1.0.0-rc.4 =
* In exception mode, a challenge, redirect or block on the wp-config.php path can no longer serve the page: any failure to answer it ends in a 503 and is logged.
* The pass cookie name on the Challenge screen is what both evaluation paths issue and check; set it to a name your host forwards if a solved challenge keeps coming back.
* Every response the firewall writes carries the full no-cache header set; bundles kanopi/firewall 2.34.1.

= 1.0.0-rc.3 =
* Rules see the path of a directly requested PHP file (wp-login.php, xmlrpc.php, /wp-admin/*.php), which previously reached them as "/": login rate limits count, admin and xmlrpc rules match, and a URL spelled differently cannot get past them.
* Bundles kanopi/firewall 2.34.0; bot equals true now matches Nikto.
* With WordPress in its own directory, rules on WordPress's own files need that directory's prefix (e.g. /wp/wp-login.php); Site Health says when one is missing it.

= 1.0.0-rc.2 =
* Bundles kanopi/firewall 2.33.2: a rate-limit key keeps the case of a form field, cookie or query parameter name.
* The wp-config.php early path finds a Composer autoloader in a custom vendor-dir: an 'autoloader' option or BASIC_FIREWALL_AUTOLOADER constant, or a library wp-config.php already loaded.

= 1.0.0-rc.1 =
* First release. The WordPress port of the Drupal basic_firewall module, built on kanopi/firewall ^2.33.1; the zip bundles 2.33.1, scoped.
* Nine rule types, six responses (allow, mark, record, challenge, redirect, block), observe-only rules and activity windows.
* Two evaluation paths: an mu-plugin installed on activation, and an optional wp-config.php bootstrap that runs before a page cache.
* Block list in files, the database or Redis; a cache backend in files, the object cache or APCu.
* Fifteen admin screens, fifteen WP-CLI subcommands and seventeen Site Health tests.
* Lockdown and a panic file for incidents; every decision announced as a WordPress action.
* Export and import with credentials stripped; an uninstall that removes what the plugin wrote.
* Upgrading from a pre-release build: stored settings are rewritten automatically; see CHANGELOG.md for the five things to check by hand.
