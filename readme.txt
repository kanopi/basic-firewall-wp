=== Basic Firewall ===
Contributors: kanopistudios
Tags: security, firewall, rate limiting, bot protection, waf
Requires at least: 6.4
Tested up to: 6.9
Requires PHP: 8.1
Stable tag: 1.0.0
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

**Nine rule types**

* IP address — single addresses, CIDR blocks, ranges, IPv4 and IPv6
* Request / URL — method, host, path, query, body, headers, cookies
* User agent — parsed, not string-matched
* Rate limit — requests per address, per pattern, per window
* ASN — turn away a whole hosting provider or VPN
* Geolocation — from a MaxMind database or your CDN's headers
* Vulnerability score — signals that are only suspicious in combination
* IP reputation — AbuseIPDB, cached, fails open
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
and are never evaluated. Database-backed block storage cannot be used on the
optional wp-config.php evaluation path, because that path runs before WordPress
exists and has nothing to read credentials from — a site combining the two fails
open while reporting itself as blocking, and Site Health says so.

**Safe by default**

The plugin installs in log-only mode with no rules. Nothing is blocked and
nothing matches until you say so. Add your own address as an Allow rule, read
the log for a few days, then switch to Block.

If you do lock yourself out, `define( 'BASIC_FIREWALL_ENABLED', false );` in
wp-config.php takes effect on the next request and needs no database access.

== Installation ==

1. Upload the zip through Plugins → Add New → Upload Plugin.
2. Activate it.
3. Visit Firewall → Dashboard and read the checks.

The zip ships with the firewall library vendored and namespace-scoped, so no
Composer, shell access or build step is needed on the server, and it cannot
collide with another plugin bundling the same library.

Composer installation also works:

`composer require kanopi/basic-firewall-wp`

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

Two causes account for almost all of it. A regular expression without delimiters
— write `#^/wp-admin#`, not `^/wp-admin` — which the library silently rejects.
Or a user agent rule using `bot` rather than `automated`: `bot` is a curated
crawler database that does not classify sqlmap, nikto, curl or python-requests.
Use the Test screen; it shows exactly what was compared against what.

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

1. The dashboard, with the Site Health checks inline.
2. The rule list, in evaluation order.
3. Testing a request without recording anything.
4. Blocked clients, with an address lookup that works on every backend.

== Changelog ==

= 1.0.0 =
* First release. WordPress port of the Drupal basic_firewall module.
