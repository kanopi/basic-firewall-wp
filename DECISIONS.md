# Decisions

The six questions the build brief asked to answer in writing, plus the one it
did not ask that turned out to matter most. Each is written as the decision, the
reason, and what it costs — so that reversing one later is a decision rather
than a discovery.

Status: settled for 1.0. Revisit any of them with a reason, not a preference.

---

## 0. Scoping the vendored library breaks presets, silently

This is not one of the six. It is written first because it changes the answer to
question 1, and because the failure it describes is invisible from the outside.

The brief recommended scoping the vendored library and added a condition:
*"Verify the library has no reflection or string-literal class references that
scoping breaks."* It does. Extensively, and in the worst possible place.

`kanopi/firewall` resolves class names **out of configuration data** at runtime:

| Factory | Reads | Then |
|---|---|---|
| `Plugins\PluginManager::create()` | the config key itself | `class_exists($plugin)` → `new $plugin(...)` |
| `Storage\StorageFactory` | `storage.type` | `class_exists($type)` → `new $type(...)` |
| `RateLimitStorage\RateLimitStorageFactory` | `type` | same |
| `Challenge\ChallengeProviderFactory` | `class` | same |
| `Logging\LoggingFactory` | `handler.class`, `formatter.class` | same |

And **15 of the library's own shipped preset YAML files hard-code those class
names as strings**:

```yaml
# vendor/kanopi/firewall/presets/wordpress.yml
- plugin: "Kanopi\\Firewall\\Plugins\\Url"
```

PHP-Scoper rewrites PHP source. It does not rewrite YAML data files. So a naive
scoped build produces this:

1. The real class is now `Kanopi\BasicFirewallWP\Vendor\Kanopi\Firewall\Plugins\Url`.
2. `presets/wordpress.yml` still says `Kanopi\Firewall\Plugins\Url`.
3. `PluginManager::create()` calls `class_exists()` on that, gets `false`.
4. The plugin is **skipped**, with `reason => 'class_not_found'`, and evaluation
   continues without it.

The library does not throw. The preset stays ticked in the admin screen. The
status page reports a healthy firewall. Every rule in every enabled preset
contributes nothing. This is precisely the failure mode the module's README
keeps returning to — *"the plugin looked fine and protected nothing"* — and it
would have been introduced by the build system rather than by the library.

**So scoping is only safe with three additional pieces, and all three are
required:**

1. **A PHP-Scoper patcher rewrites class-name strings in vendored non-PHP data
   files** (`presets/*.yml`, `config/*.yml`) using the same prefix map applied to
   the source.
2. **A build gate fails the release** if any unscoped `Kanopi\Firewall\`,
   `Monolog\`, `Doctrine\` or `Symfony\` FQCN survives anywhere under `vendor/`,
   in any file type. A scoping miss must break the build, never the firewall.
3. **A post-build smoke test enables a preset and asserts rules actually
   loaded** — asserting a non-zero rule count and an empty `skippedPlugins`,
   because "enabled" and "working" are different claims and only the second one
   matters.

Without all three, guarded autoload is the safer choice. With them, scoping is.

---

## 1. Vendor scoping — scope, or guarded autoload?

**Decision: scope, with the three safeguards above.**

**Why.** WordPress has no dependency resolution, and the collision is not
hypothetical for this plugin's actual audience. A Bedrock or Radicle site runs
`composer require` at the site root and registers that autoloader from
`wp-config.php`, before any plugin loads. Such a site that also requires
`kanopi/firewall` — for a CLI tool, a companion plugin, or the same library at a
different version — wins the race every time, and this plugin then runs against
a library version it was never tested on. Guarded autoload turns that into a
refusal to run, which is honest but is still an outage of the firewall.

**What it costs.** A build step that must not be skipped, stack traces that read
`Kanopi\BasicFirewallWP\Vendor\Monolog\...`, and the standing obligation to
re-run the gate on every library bump. A library release that adds a preset
referencing a newly-added class is caught by the gate, not by a user.

**What would reverse it.** If the patcher turns out to need per-release hand
maintenance, guarded autoload plus a loud Site Health error is the fallback. The
guarded-autoload code path is written and tested either way, because it is also
what protects against a *scoped* build being loaded twice.

---

## 2. Configuration storage — one option array, or a custom table?

**Decision: one option, `basic_firewall_settings`, `autoload = no`.**

**Why.** It mirrors `basic_firewall.settings` exactly — one document, one
validator, one thing to export. It backs up with the database, survives
migration tools, and needs no schema management. `autoload = no` is the whole
reason this is safe: the option is read once per admin request and never on a
front-end request, because the front end reads the *compiled file*, not the
option. A large rule set therefore costs nothing on the hot path.

**What it costs.** A very large rule set makes one large row, and WordPress has
no config-diffing story, so the export/import screens carry more weight here
than they do in Drupal. The brief's own note applies: with no `drush cim`
equivalent, the plugin's export/import *is* the deployment story.

**What would reverse it.** A rule set large enough that a single `LONGTEXT` row
is the wrong shape — which, for firewall rules, means thousands. Presets are
enabled by reference and never expand into the option, so this is far off.

Blocked-client data and the log table are **not** in the option. They are
operational data with different lifecycles, and they get their own tables.

---

## 3. Multisite — per-site, network-wide, or both?

**Decision: per-site for 1.0. No network-wide settings screen.**

**Why.** It is what the module does, and the reasoning carries over intact: each
site gets its own firewall, its own block list, its own counters. WordPress makes
this fall out naturally, because the three things that need separating are
already per-site:

| What | Separated by |
|---|---|
| Settings | `get_option()` on the site's own options table |
| Compiled config, file storage, logs, counters | `wp_upload_dir()`, which is `uploads/sites/N/` |
| Database tables | `$wpdb->prefix`, which carries the blog id |

The module has to apply Drupal's table prefix by hand because the library reaches
the database through Doctrine DBAL rather than the CMS layer. The same is true
here, and for the same reason: `$wpdb->prefix` must be applied explicitly, and
must not be doubled if an administrator already typed it.

**What it costs.** A network of 200 sites is 200 rule sets to configure. The
export/import screens and `wp basic-firewall import` are the answer, and
`wp site list | xargs` is a documented recipe rather than a feature.

**What would reverse it.** Demand for one policy across a network. That is a
network-admin screen writing a site meta option that per-site settings inherit
from — additive, and deliberately not in 1.0.

---

## 4. WordPress.org, or self-hosted updates?

**Decision: self-hosted via GitHub Releases for 1.0. Ship `readme.txt` anyway,
and keep the SVN job written but manually dispatched.**

**Why.** Three reasons, in order of weight:

1. **The release cadence is tied to the library.** A plugin release is how a
   `kanopi/firewall` update reaches sites. Coupling security-relevant releases
   to a review queue is the wrong dependency.
2. **PHP 8.1 floor.** The `.org` directory's audience skews to exactly the hosts
   that cannot run it, and the plugin would be installed and then refuse to run.
3. **The audience is developer-operated sites**, which is where the
   `wp-config.php` deployment and WP-CLI matter — and those are the same sites
   that can consume a GitHub release.

Naming is not a blocker: "Basic Firewall" carries no third-party trademark, so
the `.org` guidelines would permit it.

**What it costs.** An update mechanism to write and secure — signed release
metadata, checked over TLS — and no `.org` discovery. `readme.txt` is maintained
from day one so the decision stays cheap to reverse.

**What would reverse it.** Wanting the install base. The SVN step is written and
the trunk layout with a built `vendor/` is understood; it is a workflow
dispatch, not a re-architecture.

---

## 5. Minimum PHP

**Decision: PHP 8.1.**

**Why.** It is the library's own floor and every transitive dependency agrees:

| Dependency | Floor |
|---|---|
| `kanopi/firewall` | `>=8.1` |
| `symfony/*` `~6.4` | 8.1 |
| `doctrine/dbal` `^4.2` | 8.1 |
| `monolog/monolog` `^3.9` | 8.1 |

Raising it further would be a preference. The Drupal module requires 8.3 because
*Drupal 11.2* does, not because the library does — that constraint does not
travel to WordPress, so it is not carried over.

**What it costs.** WordPress's own floor is far lower, and a real share of the
install base is below 8.1. That is why the plugin does not merely declare
`Requires PHP: 8.1` and hope: it carries a runtime guard in the main file,
written in PHP-5-compatible syntax so it can *run* on the version it is
rejecting, which deactivates the plugin and explains why rather than fataling. A
white screen on activation would be the worst possible first impression for a
security tool.

**What would reverse it.** The library raising its own floor. This tracks it, and
does not lead it.

---

## 6. Is the `wp-config.php` path the default, or an advanced option?

**Decision: the mu-plugin is the default. The `wp-config.php` bootstrap is
documented as the deployment that actually protects a cached site, and Site
Health says so when it detects one.**

**Why.** This is the hardest translation in the brief and it does not have a
clean answer, so the plugin gives the honest one instead of a tidy one.

The ordering reality, earliest first:

```
host edge cache (Varnish/CDN)   ← no PHP runs at all. Unreachable. Full stop.
  wp-config.php                 ← our early path. No WordPress yet.
    advanced-cache.php drop-in  ← Batcache, W3TC, WP Super Cache serve and exit
      mu-plugins                ← our normal path
        plugins
```

An mu-plugin is the earliest hook a *plugin* can own, and on a site with no page
cache it is early enough. But `advanced-cache.php` loads before mu-plugins and
serves a cached response without ever reaching them — so on exactly the busy,
cached site that most needs a firewall, the mu-plugin never runs. That is the
same relationship the module describes between middleware 280 and `page_cache`
200, arrived at from the opposite direction.

So: the mu-plugin ships and is installed on activation, because it works with no
configuration and is what most sites need. The `wp-config.php` require is not
buried as an expert curiosity — Site Health **detects** `WP_CACHE`, an
`advanced-cache.php` drop-in, and known host caching, and raises the
recommendation with the exact snippet and path when any is present.

**What it costs.** Two supported evaluation paths, and one honest limitation
carried over verbatim from the module: the early path has no CMS, so it cannot
read database credentials, and **database-backed storage must not be used
there**. That is the module's one known fail-open. It is documented, it is
reported in Site Health, and it is the only one — no second fail-open is added.

The part the module does not have to say, and this one does: **no PHP-level
firewall can touch a host edge cache.** On Pantheon, WP Engine or Kinsta,
requests served by the platform's own cache layer never reach PHP, and nothing
in this plugin evaluates them. Saying otherwise would be the most consequential
lie the readme could tell.
