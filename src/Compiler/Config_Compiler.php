<?php
/**
 * Compiles settings into the library's native configuration.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Compiler;

use Kanopi\BasicFirewall\Cache\Cache_Backend;
use Kanopi\BasicFirewall\Challenge\Pass_Cookie;
use Kanopi\BasicFirewall\Database_Credentials;
use Kanopi\BasicFirewall\Library_Capabilities;
use Kanopi\BasicFirewall\Logging\Redaction;
use Kanopi\BasicFirewall\Install\Challenge_Secret;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Redis_Password;
use Kanopi\BasicFirewall\RuleType\Condition_Rule_Type_Base;
use Kanopi\BasicFirewall\RuleType\Response_Settings;
use Kanopi\BasicFirewall\RuleType\Rule_Type;
use Kanopi\BasicFirewall\RuleType\Rule_Type_Base;
use Kanopi\BasicFirewall\RuleType\Types\Edge_Signal;
use Kanopi\BasicFirewall\RuleType\Types\User_Agent;
use Kanopi\BasicFirewall\RuleType\Types\Vulnerability_Score;
use Kanopi\BasicFirewall\Runtime\Lockdown;
use Kanopi\BasicFirewall\Runtime\Role_Bypass;
use Kanopi\BasicFirewall\Support\Page_Settings;
use Kanopi\BasicFirewall\Support\Reverse_Dns;
use Kanopi\BasicFirewall\Support\Schema;
use Kanopi\BasicFirewall\Support\Site_Layout;
use Kanopi\Firewall\Utility\RequestPath;
use Kanopi\Firewall\Utility\Schedule;
use Symfony\Component\Yaml\Yaml;

/**
 * Turns the settings option into the library's own configuration format.
 *
 * The compiled result is written to one file in the private directory and that
 * file is what the firewall reads at runtime, so evaluating a request costs one
 * file read -- no option lookup, no database query, no rule objects rebuilt from
 * an array on every hit.
 *
 * **The compiled file is a cache.** It is regenerated whenever settings are
 * saved, whenever a document is imported, and on demand. It is safe to delete,
 * and it carries a DO NOT EDIT header because anything changed in it is
 * overwritten on the next rebuild.
 *
 * The one part worth reading closely is what does *not* go in it. WordPress's
 * database credentials are never written here. The compiler records the
 * property-access paths where a connection belongs and the runner injects live
 * credentials at those paths on every request. See Database_Credentials for why
 * that is a requirement rather than a nicety.
 */
final class Config_Compiler {

	/**
	 * What dig() returns for a path a document does not have.
	 */
	private const ABSENT = "\0absent";

	/**
	 * The runtime sidecar's contents when nothing in it differs from a default.
	 *
	 * The bootstrap assumes exactly this when the sidecar is absent, which is
	 * why the file is not written at all in that case. runtime() returns its
	 * keys in this order, so the two compare strictly.
	 *
	 * @var array<string, mixed>
	 */
	public const RUNTIME_DEFAULTS = array(
		'enabled'     => true,
		'redact'      => array(),
		'defer_login' => false,
		'pass_cookie' => Pass_Cookie::DEFAULT_NAME,
	);

	/**
	 * Paths in the compiled array where live credentials must be injected.
	 *
	 * Symfony property-access syntax, which is what the library's runtime
	 * override mechanism takes.
	 *
	 * @var list<string>
	 */
	private array $connection_paths = array();

	/**
	 * Where a Redis connection's `auth` belongs, with the username that goes with it.
	 *
	 * Symfony property-access paths, like the connection paths. The runner and
	 * the wp-config.php path inject BASIC_FIREWALL_REDIS_PASSWORD at each; see
	 * Redis_Password.
	 *
	 * @var array<string, string>
	 */
	private array $redis_auth_paths = array();

	/**
	 * Paths where the object cache pool for agent detection belongs.
	 *
	 * @var list<string>
	 */
	private array $cache_pool_paths = array();

	/**
	 * Paths where the object cache pool for reverse-DNS verdicts belongs.
	 *
	 * @var list<string>
	 */
	private array $verify_cache_paths = array();

	/**
	 * Problems encountered while compiling.
	 *
	 * @var list<string>
	 */
	private array $problems = array();

	/**
	 * Compile the current settings.
	 *
	 * @return array<string, mixed>
	 */
	public function compile(): array {
		$this->connection_paths   = array();
		$this->redis_auth_paths   = array();
		$this->cache_pool_paths   = array();
		$this->verify_cache_paths = array();
		$this->problems           = array();

		$plugin   = Plugin::instance();
		$settings = $plugin->settings();

		$challenge = (array) $settings->get( 'challenge', array() );

		$rules = $this->compile_rules( (array) $settings->get( 'rules', array() ) );
		$rules = $this->drop_unbuildable_challenges( $rules, $challenge );

		$compiled = array();

		/*
		 * Presets are included by reference rather than copied in. The library's
		 * loader appends their plugin entries to ours rather than replacing
		 * them, so locally configured rules survive alongside a preset's, and an
		 * exported document records only which presets are on -- a preset's
		 * several hundred patterns never appear in a diff.
		 */
		$presets = $plugin->presets()->resolve_paths( (array) $settings->get( 'presets', array() ) );

		foreach ( $plugin->presets()->problems() as $problem ) {
			$this->problems[] = $problem;
		}

		if ( array() !== $presets ) {
			$compiled['configs'] = $presets;
		}

		$rules = $this->apply_cache_backend( $rules );

		/*
		 * A rate limit's counter connection is emitted by its rule type, which
		 * has no idea what index it will occupy in the plugin list. That index
		 * only exists here, so this is where a WordPress-backed connection is
		 * lifted out of the file and recorded for the runner to inject.
		 */
		foreach ( $rules as $delta => $rule ) {
			$storage = $rule['metadata']['storage'] ?? null;

			if ( ! is_array( $storage ) || true !== ( $storage['config']['connection']['__wordpress'] ?? false ) ) {
				continue;
			}

			unset( $rules[ $delta ]['metadata']['storage']['config']['connection'] );

			$this->connection_paths[] = sprintf( '[plugins][%d][metadata][storage][config][connection]', $delta );
		}

		$compiled += array(
			'global'  => $this->compile_global( (array) $settings->get( 'global', array() ) ),
			'storage' => $this->compile_storage( (array) $settings->get( 'storage', array() ) ),
			'plugins' => array_values( $rules ),
		);

		$logger = $this->compile_logger( (array) $settings->get( 'logger', array() ) );

		if ( array() !== $logger ) {
			$compiled['logger'] = $logger;
		}

		/*
		 * The library throws at startup when a challenge plugin exists without a
		 * secret, and this plugin fails open on that -- which would leave the
		 * site with no firewall running at all rather than one broken rule. So
		 * the section is emitted only when something actually needs it, and
		 * presets count: one of them ships `response: challenge`.
		 */
		if ( $this->needs_challenge( $rules, (array) $settings->get( 'presets', array() ) ) ) {
			$compiled['challenge'] = $this->compile_challenge( $challenge, $rules, (array) $settings->get( 'global.pages', array() ) );
		}

		$compiled = $this->apply_advanced_yaml( $compiled, (string) $settings->get( 'advanced_yaml', '' ) );

		/*
		 * After the advanced YAML, so a provider or resolver typed there is
		 * checked as well. The library refuses to start on a `reverse_dns` it
		 * cannot use, and this plugin fails open when it refuses; see
		 * Reverse_Dns::repair().
		 */
		$compiled = Reverse_Dns::repair( $compiled, $this->problems );
		$compiled = $this->apply_redis_password( $compiled, trim( (string) $settings->get( 'storage.redis.username', '' ) ) );

		return $this->apply_enabled( $compiled, (bool) $settings->get( 'enabled', true ) );
	}

	/**
	 * Record where each Redis connection's password belongs, and keep it out of the file when a constant supplies it.
	 *
	 * After the advanced YAML, so a connection written there -- or a rate limit
	 * whose index it changed -- is found where it actually ended up. Both uses
	 * are covered: the block list's `storage.config.redis`, and every plugin's
	 * `metadata.storage.config.redis`, which is where a rate limit keeps its
	 * counters.
	 *
	 * The paths are recorded whether or not the constant is defined today, so
	 * defining it later takes effect on the next request rather than the next
	 * rebuild -- only the literal left in the file waits for a rebuild, and
	 * Site Health says so. The password itself is removed only when the
	 * constant is defined: otherwise the file is still the only place the
	 * wp-config.php path can get it from. See Redis_Password.
	 *
	 * @param array<string, mixed> $compiled The compiled configuration.
	 * @param string               $username The block list's ACL username.
	 *
	 * @return array<string, mixed>
	 */
	private function apply_redis_password( array $compiled, string $username ): array {
		$overridden = Redis_Password::is_overridden();

		if ( is_array( $compiled['storage']['config']['redis'] ?? null ) ) {
			$this->redis_auth_paths['[storage][config][redis][auth]'] = self::redis_username( $compiled['storage']['config']['redis'], $username );

			if ( $overridden ) {
				unset( $compiled['storage']['config']['redis']['auth'] );
			}
		}

		foreach ( (array) ( $compiled['plugins'] ?? array() ) as $index => $plugin ) {
			if ( ! is_array( $plugin ) || ! is_array( $plugin['metadata']['storage']['config']['redis'] ?? null ) ) {
				continue;
			}

			$this->redis_auth_paths[ sprintf( '[plugins][%s][metadata][storage][config][redis][auth]', $index ) ] = self::redis_username( $plugin['metadata']['storage']['config']['redis'], '' );

			if ( $overridden ) {
				unset( $compiled['plugins'][ $index ]['metadata']['storage']['config']['redis']['auth'] );
			}
		}

		return $compiled;
	}

	/**
	 * The ACL username a Redis connection authenticates as, if any.
	 *
	 * The one already in its `auth` pair when there is one -- typed in the
	 * advanced YAML, say -- and otherwise the one the settings give.
	 *
	 * @param array<string, mixed> $redis    The connection's options.
	 * @param string               $fallback The username the settings give.
	 */
	private static function redis_username( array $redis, string $fallback ): string {
		$auth = $redis['auth'] ?? null;

		if ( is_array( $auth ) && 2 === count( $auth ) && is_string( reset( $auth ) ) ) {
			return (string) reset( $auth );
		}

		return $fallback;
	}

	/**
	 * Compile "Enable the firewall" unticked as a firewall that evaluates nothing.
	 *
	 * The runner checks the setting before it calls the library, but the
	 * wp-config.php path cannot: it runs before there are options to read, and
	 * the compiled file is all it has. Leaving the setting out of the file
	 * meant a site switched off in the admin went on being enforced on every
	 * request that path answered -- which, on a site with a page cache, is most
	 * of them.
	 *
	 * So it is written twice. Here, as `mode: disabled` with the panic file
	 * dropped, so the file on its own says "evaluate nothing" to anything that
	 * reads it; and in the runtime sidecar, which the bootstrap reads before it
	 * builds a firewall at all, so a mode pinned by BASIC_FIREWALL_MODE does not
	 * switch back on a firewall somebody switched off. Last, after the advanced
	 * YAML, so a `mode:` typed there cannot undo it either.
	 *
	 * @param array<string, mixed> $compiled The compiled configuration.
	 * @param bool                 $enabled  Whether the firewall is enabled.
	 *
	 * @return array<string, mixed>
	 */
	private function apply_enabled( array $compiled, bool $enabled ): array {
		if ( $enabled ) {
			return $compiled;
		}

		$global = is_array( $compiled['global'] ?? null ) ? $compiled['global'] : array();

		$global['mode'] = 'disabled';
		unset( $global['panic_file'] );

		$compiled['global'] = $global;

		return $compiled;
	}

	/**
	 * What the wp-config.php path needs to know that the compiled file cannot say.
	 *
	 * The library's configuration has no key for these, and that path has no
	 * options to read them from, so they travel in a sidecar beside the
	 * compiled file -- see Compiled_Config_Cache::write_runtime(). Nothing here
	 * is a secret.
	 *
	 * @return array<string, mixed>
	 */
	public function runtime(): array {
		$settings = Plugin::instance()->settings();

		return array(
			'enabled'     => (bool) $settings->get( 'enabled', true ),

			// Names the log redacts as well as the library's own; see Redaction.
			'redact'      => Redaction::clean( (array) $settings->get( 'logging.redact_extra', array() ) ),

			// A role is exempt, so a request carrying a login cookie is left
			// for the runner, which can validate it; see Role_Bypass.
			'defer_login' => array() !== Role_Bypass::clean( (array) $settings->get( 'global.bypass_roles', array() ) ),

			// The pass cookie's name, as compiled, so the dispatcher on that
			// path can see a pass that did not come back; see Decision_Dispatcher.
			'pass_cookie' => Pass_Cookie::name( (string) $settings->get( 'challenge.cookie_name', '' ) ),
		);
	}

	/**
	 * Aim every rule that caches at the site-wide cache backend.
	 *
	 * Here rather than in each rule type, because this loop is the one place
	 * that knows every plugin's final index -- which is what an override path
	 * needs -- and because where the firewall caches is one site-wide choice:
	 * rules disagreeing about it would be several caches to keep warm and
	 * several places to look when one is on slow storage.
	 *
	 * Where the object cache belongs is recorded for every rule that caches,
	 * whatever backend is chosen, so switching to it takes effect without
	 * waiting for a recompile.
	 *
	 * @param array<int|string, array<string, mixed>> $rules Compiled rules.
	 *
	 * @return array<int|string, array<string, mixed>>
	 */
	private function apply_cache_backend( array $rules ): array {
		$agents   = Cache_Backend::compiled_pool( Cache_Backend::AGENTS );
		$verdicts = Cache_Backend::compiled_pool( Cache_Backend::VERDICTS );

		$directory = Cache_Backend::directory();

		/*
		 * Created rather than assumed: the library carries on uncached when a
		 * cache directory is unwritable, and uncached agent detection is about
		 * 600 ms a request -- a regression that announces itself only in the log.
		 */
		if ( null !== $agents && 'filesystem' === Cache_Backend::configured() && null !== $directory
			&& ! is_dir( $directory ) && ! wp_mkdir_p( $directory ) ) {
			$this->problems[] = sprintf(
				/* translators: %s: directory path. */
				__( 'The cache directory %s could not be created, so the firewall caches in the private directory instead.', 'basic-firewall' ),
				$directory
			);

			$agents   = null;
			$verdicts = null;
		}

		foreach ( $rules as $delta => $rule ) {
			$class    = (string) ( $rule['plugin'] ?? '' );
			$metadata = (array) ( $rule['metadata'] ?? array() );

			// The whole value: a user agent rule's `cache` is its cache
			// configuration and nothing else. `false` is the rule opting out.
			if ( str_ends_with( $class, '\UserAgent' ) && false !== ( $metadata['cache'] ?? null ) ) {
				$this->cache_pool_paths[] = sprintf( '[plugins][%d][metadata][cache]', $delta );

				if ( null !== $agents ) {
					$rules[ $delta ]['metadata']['cache'] = $agents;
				}
			}

			// Any rule can verify, and since library 2.33.0 `verify_cache`
			// takes the same shapes as every other cache setting.
			if ( isset( $metadata['verify'] ) ) {
				$this->verify_cache_paths[] = sprintf( '[plugins][%d][metadata][verify_cache]', $delta );

				if ( null !== $verdicts ) {
					$rules[ $delta ]['metadata']['verify_cache'] = $verdicts;
				}
			}
		}

		return $rules;
	}

	/**
	 * Compile the global section.
	 *
	 * @param array<string, mixed> $section Stored global settings.
	 *
	 * @return array<string, mixed>
	 */
	private function compile_global( array $section ): array {
		$compiled = array(
			'mode'                    => $this->resolve_mode( $section ),
			'banning_status_code'     => (int) ( $section['banning_status_code'] ?? 403 ),
			'banning_message'         => (string) ( $section['banning_message'] ?? 'Request blocked.' ),
			'require_trusted_proxies' => (bool) ( $section['require_trusted_proxies'] ?? false ),

			/*
			 * Without this the library logs a failed config load and starts with
			 * whatever parsed -- which for a single-file setup like ours means an
			 * empty ruleset that allows every request and looks like success.
			 * With it, the library refuses to start, which the runner catches,
			 * logs as an error, and then fails open on. Traffic is treated the
			 * same either way; this decides whether anybody finds out.
			 */
			'require_config'          => (bool) ( $section['require_config'] ?? true ),

			/*
			 * Match the file the web server ran, not the path relative to it.
			 *
			 * WordPress serves wp-login.php, xmlrpc.php, wp-cron.php and every
			 * wp-admin screen as files of their own. Under the library's
			 * default, `pathinfo`, each of them is `/`, so a `/wp-login.php`
			 * rate limit never counted and a negated path condition matched
			 * every admin screen (#30). `script_name` is `SCRIPT_NAME` plus
			 * `PATH_INFO`, falling back to `getPathInfo()` for the front
			 * controller -- the file the server chose after decoding and
			 * normalising the URL, so `/./wp-login.php`, `/%77p-login.php`
			 * and `//wp-login.php` are all `/wp-login.php`. Reading the raw
			 * URL instead, as the request rewrite this replaces (#31) did,
			 * let each of those spellings past the same limit.
			 *
			 * Always written, not a setting: there is no WordPress site the
			 * default is right for.
			 */
			'path_source'             => RequestPath::SCRIPT_NAME,
		);

		/*
		 * Where the front controller is, which only the compiler can say: the
		 * wp-config.php path runs before there are options to read, and a
		 * direct-file request does not carry it. Site_Layout explains the
		 * layouts, including why WordPress in its own directory gets none.
		 * Left out at the web root, where it would strip nothing.
		 */
		$base_path = Site_Layout::base_path();

		if ( '' !== $base_path ) {
			$compiled['base_path'] = $base_path;
		}

		/*
		 * Three states, and "absent" is one of them. The library reads an absent
		 * key as "posture unknown" and keeps warning, FALSE as "asserted: no
		 * proxy" and goes silent, TRUE as "asserted: there is one" and escalates
		 * a missing trusted-proxy list to an error.
		 *
		 * Emitting FALSE for somebody who never answered would silence a
		 * security warning on their behalf, so the key is written only once they
		 * have answered.
		 */
		$behind = (string) ( $section['behind_proxy'] ?? 'unknown' );

		if ( 'no' === $behind || 'yes' === $behind ) {
			$compiled['behind_proxy'] = 'yes' === $behind;
		}

		$this->compile_lockdown( $section, $compiled );

		/*
		 * Only when set. An empty key would have the library stat a path on
		 * every request for a switch nobody armed, and the point of the feature
		 * is that it costs nothing until it is needed.
		 *
		 * Resolved to an absolute path here rather than written as typed, which
		 * is the opposite of what the storage files get. The library resolves
		 * those two against the directory holding the compiled file; it reads
		 * this one with a bare is_file(), which resolves a relative path against
		 * whatever the working directory happens to be -- the web root under
		 * php-fpm, somewhere else entirely under WP-CLI. The same setting would
		 * then arm a different file depending on who asked.
		 */
		$panic_file = trim( (string) ( $section['panic_file'] ?? '' ) );

		if ( '' !== $panic_file ) {
			$compiled['panic_file'] = Plugin::instance()->paths()->resolve( $panic_file );
		}

		$repeat = (int) ( $section['repeat_offender_status'] ?? 0 );

		if ( $repeat > 0 ) {
			$compiled['repeat_offender_status'] = $repeat;
		}

		/*
		 * Positive or nothing, because nothing else can be said. The library
		 * array_filter()s its global section before reading it, so a zero is
		 * gone before it is seen, and an absent key means 3600. There is no way
		 * to ask for "extend by nothing", which is why the General screen's
		 * minimum is one second. A zero stored by an earlier build or an import
		 * is reported rather than passed on as though it meant something.
		 */
		$add_to_expire = (int) ( $section['add_to_expire'] ?? 3600 );

		if ( $add_to_expire > 0 ) {
			$compiled['add_to_expire'] = $add_to_expire;
		} else {
			$this->problems[] = __( 'Seconds added when a blocked client returns is 0, which the firewall library cannot honour: it reads 0 as unset and adds 3600 seconds instead. Set it to the number of seconds you want added; the smallest is 1.', 'basic-firewall' );
		}

		$escalation = $this->compile_escalation( (array) ( $section['blocking_escalation'] ?? array() ) );

		if ( array() !== $escalation ) {
			$compiled['blocking_escalation'] = $escalation;
		}

		/*
		 * A page instead of one line of text, each only when switched on
		 * (library 2.37.0, kanopi/firewall#452). Left out, the refusal is the
		 * plain-text message, exactly as before. Page_Settings writes only
		 * values the library accepts, because it refuses to start on one it
		 * does not -- and this plugin fails open when it refuses.
		 */
		$pages = (array) ( $section['pages'] ?? array() );

		foreach ( array(
			'block_page'    => array( 'title', 'heading' ),
			'lockdown_page' => array( 'title', 'heading', 'message' ),
		) as $key => $text_keys ) {
			$page = Page_Settings::refusal( (array) ( $section[ $key ] ?? array() ), $pages, $text_keys );

			if ( null !== $page ) {
				$compiled[ $key ] = $page;
			}
		}

		// Only a client whose first preference is JSON gets it; a browser
		// still gets the page or the message.
		if ( true === ( $section['banning_json'] ?? false ) ) {
			$compiled['banning_json'] = true;
		}

		/*
		 * Who makes the lookups behind crawler verification (library 2.38.0,
		 * kanopi/firewall#473). Nothing unless a provider or a time limit is
		 * set, so a site that chose neither keeps PHP's own lookups and sends
		 * nothing to anyone.
		 */
		$reverse_dns = Reverse_Dns::compile( (array) ( $section['reverse_dns'] ?? array() ) );

		if ( array() !== $reverse_dns ) {
			$compiled['reverse_dns'] = $reverse_dns;
		}

		return $compiled;
	}

	/**
	 * Compile lockdown, which is written only when it is armed.
	 *
	 * The library reads an absent or empty `lockdown_allow` as "serve nobody".
	 * That is the honest reading of a mode called lockdown, and it is also the
	 * quickest way to lock an administrator out of the site they are defending
	 * -- the General screen refuses to save it for that reason. This is the
	 * same refusal for every other way a document arrives: an import, WP-CLI,
	 * or a hand-edited option. Refused means not applied and reported, which is
	 * this plugin's posture everywhere else too: the site stays reachable, and
	 * somebody is told why the lockdown is not in force.
	 *
	 * @param array<string, mixed> $section  Stored global settings.
	 * @param array<string, mixed> $compiled The global section being built.
	 */
	private function compile_lockdown( array $section, array &$compiled ): void {
		if ( true !== ( $section['lockdown'] ?? false ) ) {
			return;
		}

		$allow = Lockdown::sort( (array) ( $section['lockdown_allow'] ?? array() ) );

		foreach ( $allow['invalid'] as $entry ) {
			$this->problems[] = sprintf(
				/* translators: %s: the rejected allowlist entry. */
				__( 'The lockdown allowlist entry "%s" is not an address, a CIDR block or a start-end range, so it was left out.', 'basic-firewall' ),
				$entry
			);
		}

		if ( array() === $allow['valid'] ) {
			$this->problems[] = __( 'Lockdown is switched on with no usable address on its allowlist, which would refuse everybody — including whoever is trying to switch it off. It was not applied.', 'basic-firewall' );

			return;
		}

		$compiled['lockdown']       = true;
		$compiled['lockdown_allow'] = $allow['valid'];
	}

	/**
	 * Resolve the operating mode, honouring a wp-config.php override.
	 *
	 * @param array<string, mixed> $section Stored global settings.
	 */
	private function resolve_mode( array $section ): string {
		if ( defined( 'BASIC_FIREWALL_MODE' ) ) {
			$override = constant( 'BASIC_FIREWALL_MODE' );

			if ( is_string( $override ) && isset( Library_Map::MODES[ $override ] ) ) {
				return $override;
			}
		}

		$mode = (string) ( $section['mode'] ?? 'log' );

		return isset( Library_Map::MODES[ $mode ] ) ? $mode : 'log';
	}

	/**
	 * Compile the escalation stages.
	 *
	 * @param array<int, mixed> $stages Stored stages.
	 *
	 * @return list<array<string, int>>
	 */
	private function compile_escalation( array $stages ): array {
		$compiled = array();

		foreach ( $stages as $stage ) {
			if ( ! is_array( $stage ) ) {
				continue;
			}

			$window = (int) ( $stage['window'] ?? 0 );

			if ( $window <= 0 ) {
				// The library skips a stage without a window, so dropping it
				// here keeps the compiled file honest about what will run.
				continue;
			}

			$entry = array(
				'window'  => $window,
				'offense' => (int) ( $stage['offense'] ?? 0 ),
			);

			/*
			 * Omitting `duration` makes the library fall back to the matching
			 * rule's own duration, which is meaningfully different from zero --
			 * zero means block permanently.
			 */
			if ( empty( $stage['use_plugin_default'] ) ) {
				$entry['duration'] = (int) ( $stage['duration'] ?? 0 );
			}

			$compiled[] = $entry;
		}

		usort( $compiled, static fn ( array $a, array $b ): int => $a['window'] <=> $b['window'] );

		return $compiled;
	}

	/**
	 * Compile the blocked-client storage section.
	 *
	 * @param array<string, mixed> $storage Stored storage settings.
	 *
	 * @return array<string, mixed>
	 */
	private function compile_storage( array $storage ): array {
		$compiled = $this->compile_storage_backend( $storage );

		/*
		 * Applied here rather than inside each backend, because it is the same
		 * policy whichever store holds the record and the library reads it from
		 * `storage.config` for all of them.
		 */
		$compiled['config'] = ( $compiled['config'] ?? array() )
			+ array( 'record_request' => $this->compile_record_request( (array) ( $storage['record_request'] ?? array() ) ) );

		return $compiled;
	}

	/**
	 * What a block record keeps about the request that caused it.
	 *
	 * All four buckets are written out. The library would default any bucket
	 * left absent, and three of its four defaults are what this plugin wants --
	 * but a textarea cannot say "absent", only "empty", and empty means keep
	 * nothing. Writing all four means the compiled file says what the screen
	 * says, which is the same reason `challenge.ttl` is written out.
	 *
	 * @param array<string, mixed> $declared Stored record_request settings.
	 *
	 * @return array<string, list<string>>
	 */
	private function compile_record_request( array $declared ): array {
		$buckets  = array();
		$defaults = Schema::defaults()['storage']['record_request'] ?? array();

		foreach ( array( 'cookies', 'headers', 'query', 'body' ) as $bucket ) {
			/*
			 * Absent and empty are different answers, and only one of them is
			 * the operator's. A site upgrading from before this setting existed
			 * has no value stored, and reading that as "keep nothing" would
			 * silently strip the user agent and the query string out of every
			 * record it writes next. Absent takes the default; empty is a choice
			 * somebody made in the form.
			 */
			$stored = array_key_exists( $bucket, $declared )
				? $declared[ $bucket ]
				: ( $defaults[ $bucket ] ?? '' );

			$names = preg_split( '/\R/', (string) $stored );
			$names = array_values(
				array_filter(
					array_map( 'trim', is_array( $names ) ? $names : array() ),
					static fn( string $name ): bool => '' !== $name
				)
			);

			/*
			 * Header names are matched lowercased by the library and everything
			 * else is not, because the others are the application's own names
			 * and `Token` and `token` are two of them.
			 */
			$buckets[ $bucket ] = 'headers' === $bucket
				? array_map( 'strtolower', $names )
				: $names;
		}

		return $buckets;
	}

	/**
	 * The backend half of the storage section.
	 *
	 * @param array<string, mixed> $storage Stored storage settings.
	 *
	 * @return array<string, mixed>
	 */
	private function compile_storage_backend( array $storage ): array {
		$backend = (string) ( $storage['backend'] ?? 'file' );

		if ( 'redis' === $backend ) {
			$capabilities = new Library_Capabilities();

			/*
			 * A library without the class would skip a storage type it cannot
			 * find, so the fallback is chosen here where it can be said.
			 *
			 * A missing *extension* is not compiled around. The compiled file
			 * is written by whichever PHP saved the settings -- often WP-CLI on
			 * a box that is not a web node -- and read by every web node, so
			 * the extension being absent here says nothing about whether it is
			 * absent where requests are served. The library degrades on a node
			 * without it, and Site Health says so on that node.
			 */
			if ( $capabilities->has_redis_storage_class() ) {
				if ( ! Library_Capabilities::has_redis_extension() ) {
					$this->problems[] = __( 'Redis block list storage is selected, but this PHP does not have the redis extension loaded. Any web node without it keeps no block list at all: rules still run, but no client is recorded and repeat offenders are never recognised.', 'basic-firewall' );
				}

				return array(
					'type'   => Library_Map::STORAGE['redis'],
					'config' => array( 'redis' => self::redis_storage_options( (array) ( $storage['redis'] ?? array() ) ) ),
				);
			}

			$this->problems[] = __( 'Redis block list storage is selected but the installed library cannot provide it. Falling back to file storage so blocks are still recorded.', 'basic-firewall' );

			$backend = 'file';
		}

		if ( 'database' === $backend ) {
			$compiled = $this->compile_database_storage( (array) ( $storage['database'] ?? array() ) );

			if ( null !== $compiled ) {
				return $compiled;
			}

			$this->problems[] = __( 'Database storage is selected but no usable connection could be built. Falling back to file storage so the firewall still starts.', 'basic-firewall' );

			$backend = 'file';
		}

		if ( 'file' === $backend ) {
			$paths = Plugin::instance()->paths();
			$file  = (array) ( $storage['file'] ?? array() );

			/*
			 * Written as the administrator typed it. A relative filename stays
			 * relative: the library resolves these two keys against the
			 * directory holding the file that named them, which is the private
			 * directory, so the result is identical and the document says what
			 * the form said. See Paths::portable().
			 */
			$storage_file = $paths->portable( (string) ( $file['storage_file'] ?? 'blocked.data' ) );

			if ( '' === $storage_file ) {
				$storage_file = 'blocked.data';
			}

			$offense_file = $paths->portable( (string) ( $file['offense_file'] ?? '' ) );

			$config = array( 'storage_file' => $storage_file );

			/*
			 * Derived rather than omitted when the field is blank. Leaving the
			 * key out hands the decision to whatever default the library
			 * currently has -- and that default moved in 2.22.0: it used to come
			 * from the *directory* holding the storage file, which meant two
			 * stores in one directory shared a single offense history and
			 * escalated each other's clients.
			 */
			$config['offense_file'] = '' !== $offense_file
				? $offense_file
				: $storage_file . '.offenses';

			return array(
				'type'   => Library_Map::STORAGE['file'],
				'config' => $config,
			);
		}

		/*
		 * In-memory. Not offered as a choice on the storage screen -- it
		 * discards every block when the request ends, so the firewall would
		 * evaluate rules and throw the result away while reporting itself as
		 * enabled. The backend still exists because the request tester uses it
		 * deliberately, which is how a test leaves no trace.
		 */
		return array( 'type' => Library_Map::STORAGE['memory'] );
	}

	/**
	 * The options the Redis block list connects with.
	 *
	 * Public because the block list screen and WP-CLI open the same backend
	 * the firewall writes to, and two copies of this would drift the first time
	 * one of them learned about a new key.
	 *
	 * The keys are `ext-redis`'s own spelling, because it skips an option it
	 * does not recognise with a warning rather than refusing it: a misspelled
	 * key looks configured and does nothing.
	 *
	 * @param array<string, mixed> $redis Stored `storage.redis` settings.
	 * @param bool                 $live  For a connection opened now, rather than for the compiled file.
	 *
	 * @return array<string, mixed>
	 */
	public static function redis_storage_options( array $redis, bool $live = false ): array {
		$host = trim( (string) ( $redis['host'] ?? '' ) );

		$options = array(
			'host' => '' !== $host ? $host : '127.0.0.1',

			// An integer, because a string port is an option `ext-redis` skips.
			'port' => (int) ( $redis['port'] ?? 6379 ),
		);

		/*
		 * Always written, and derived from the site when left empty. Omitting
		 * it hands the choice to the library's bare `firewall:`, which is one
		 * block list for every site of a network sharing the server.
		 */
		$prefix = trim( (string) ( $redis['prefix'] ?? '' ) );

		$options['prefix'] = '' !== $prefix ? $prefix : ( new Database_Credentials() )->block_list_key_prefix();

		/*
		 * A password alone is the ordinary `requirepass` case. Only a username
		 * with a password becomes the pair ACL authentication needs, and a
		 * username on its own is not a credential the server accepts -- so it
		 * is not written as one.
		 */
		$username = trim( (string) ( $redis['username'] ?? '' ) );
		$password = (string) ( $redis['password'] ?? '' );

		/*
		 * Opening a connection now, the password is the one in force: the
		 * constant, or a token resolved. Compiling, it is what is stored --
		 * a token stays a token for the library to resolve, and the compiler
		 * removes it altogether when the constant supplies it.
		 */
		if ( $live ) {
			$password = Redis_Password::live( $password );
		}

		if ( '' !== $password ) {
			$options['auth'] = Redis_Password::auth( $username, $password );
		}

		return $options;
	}

	/**
	 * Compile database storage, or null if no connection can be built.
	 *
	 * @param array<string, mixed> $database Stored database settings.
	 *
	 * @return array<string, mixed>|null
	 */
	private function compile_database_storage( array $database ): ?array {
		$source      = (string) ( $database['connection_source'] ?? 'wordpress' );
		$credentials = new Database_Credentials();
		$uses_wp     = 'wordpress' === $source;

		$storage_table  = (string) ( $database['storage_table'] ?? 'basic_firewall_blocked' );
		$offenses_table = (string) ( $database['offenses_table'] ?? 'basic_firewall_offenses' );

		/*
		 * A preset supplies the connection itself. Emitting one here would be
		 * merged over by nothing -- this plugin's file is the base of the merge,
		 * so any key it writes survives whatever the preset sets alongside it --
		 * and injecting WordPress's credentials would replace the preset's
		 * connection outright, because overrides are applied after every file
		 * has been merged. Contributing nothing is the only way the preset's
		 * connection actually reaches the backend.
		 */
		if ( 'preset' === $source ) {
			return array(
				'type'   => Library_Map::STORAGE['database'],
				'config' => array(
					'storage_table'  => $storage_table,
					'offenses_table' => $offenses_table,
				),
			);
		}

		$connection = match ( $source ) {
			'wordpress'  => $credentials->get_connection_parameters(),
			'parameters' => $this->compile_connection_parameters( (array) ( $database['parameters'] ?? array() ) ),
			default      => '' === trim( (string) ( $database['dsn'] ?? '' ) )
				? array()
				: array( 'dsn' => trim( (string) $database['dsn'] ) ),
		};

		if ( array() === $connection ) {
			return null;
		}

		$config = array(
			// Prefixed only when the tables live in WordPress's own database. A
			// supplied DSN points at a schema somebody named themselves, and
			// prefixing it would rename a table they created.
			'storage_table'  => $uses_wp ? $credentials->prefix_table( $storage_table ) : $storage_table,
			'offenses_table' => $uses_wp ? $credentials->prefix_table( $offenses_table ) : $offenses_table,
		);

		if ( $uses_wp ) {
			// Recorded, not written. See the class docblock.
			$this->connection_paths[] = '[storage][config][connection]';
		} else {
			$config['connection'] = $connection;
		}

		return array(
			'type'   => Library_Map::STORAGE['database'],
			'config' => $config,
		);
	}

	/**
	 * Compile individual connection parameters.
	 *
	 * @param array<string, mixed> $parameters Stored parameters.
	 *
	 * @return array<string, mixed>
	 */
	private function compile_connection_parameters( array $parameters ): array {
		$compiled = array();

		foreach ( array( 'driver', 'host', 'dbname', 'user', 'password' ) as $key ) {
			$value = trim( (string) ( $parameters[ $key ] ?? '' ) );

			if ( '' !== $value ) {
				$compiled[ $key ] = $value;
			}
		}

		$port = (int) ( $parameters['port'] ?? 0 );

		if ( $port > 0 ) {
			$compiled['port'] = $port;
		}

		// A driver and a database name are the minimum that can open anything.
		return isset( $compiled['driver'], $compiled['dbname'] ) ? $compiled : array();
	}

	/**
	 * Compile the rules into library plugin entries.
	 *
	 * @param array<int, mixed> $rules Stored rules.
	 *
	 * @return list<array<string, mixed>>
	 */
	private function compile_rules( array $rules ): array {
		$registry     = Plugin::instance()->rule_types();
		$capabilities = new Library_Capabilities();
		$compiled     = array();

		foreach ( $rules as $rule ) {
			if ( ! is_array( $rule ) ) {
				continue;
			}

			/*
			 * A vulnerability score rule still in the shape the withdrawn type
			 * saved: `{threshold, weights}`, neither of which the library reads.
			 * Upgrade routine 12 translates every one it soundly can, and
			 * switches the rest off -- so this is named whether it is enabled
			 * or not, or a rule the upgrade switched off would disappear from
			 * the Status screen and Site Health without anybody being told.
			 * Enabled, it is skipped rather than compiled as new settings with
			 * every field missing, which would be the default rule nobody wrote.
			 */
			if ( 'vulnerability_score' === ( $rule['type'] ?? '' ) && Vulnerability_Score::is_legacy( (array) ( $rule['settings'] ?? array() ) ) ) {
				$this->problems[] = sprintf(
					/* translators: %s: rule identifier. */
					__( 'Rule "%s" is a vulnerability score rule saved before the rule type was rebuilt, as a threshold and weights the firewall library never read. Its weights have no equivalent in the library\'s scoring, so it could not be translated: it is skipped, and kept as it is. Open it, set its scores and risk levels, save it and switch it on, or delete it.', 'basic-firewall' ),
					(string) ( $rule['id'] ?? '?' )
				);

				continue;
			}

			if ( empty( $rule['enabled'] ) ) {
				continue;
			}

			$type = $registry->get( (string) ( $rule['type'] ?? '' ) );

			if ( null === $type ) {
				$this->problems[] = sprintf(
					/* translators: 1: rule identifier, 2: rule type. */
					__( 'Rule "%1$s" has an unknown type "%2$s" and was skipped.', 'basic-firewall' ),
					(string) ( $rule['id'] ?? '?' ),
					(string) ( $rule['type'] ?? '?' )
				);

				continue;
			}

			/*
			 * A rule whose type the installed library cannot provide is skipped
			 * with a warning rather than compiled into a plugin entry naming a
			 * class that does not exist. The library would skip such an entry
			 * silently, which is the failure this plugin exists to avoid.
			 */
			if ( ! $type->is_available() ) {
				$this->problems[] = sprintf(
					/* translators: 1: rule identifier, 2: rule type name. */
					__( 'Rule "%1$s" needs the %2$s rule type, which the installed firewall library cannot provide. It was skipped, so it is not being enforced.', 'basic-firewall' ),
					(string) ( $rule['id'] ?? '?' ),
					$type->label()
				);

				continue;
			}

			/*
			 * The rule's settings in the shape its type compiles from.
			 *
			 * Every settings write puts each rule through its type's validator,
			 * but a document can reach the compiler without one: a hand-edited
			 * option, a deploy writing it directly, a restore. A type handed a
			 * shape it never produces threw a TypeError from inside the
			 * compiler, or -- worse -- compiled quietly wrong: addresses typed
			 * as one string became one junk entry, and a rate limit written as
			 * a line compiled with no limits at all.
			 */
			$settings = $this->normalised_settings( $type, $rule );

			if ( null === $settings ) {
				continue;
			}

			$rule['settings'] = $settings;

			/*
			 * A response the installed library cannot honour is skipped, loudly.
			 *
			 * `redirect` and `mark` arrived in library 2.26.0. An older library
			 * partitions plugins by response and simply has no bucket for
			 * either, so a rule carrying one is not rejected -- it is never
			 * evaluated. That is the silent-no-op this plugin exists to avoid,
			 * and it is reachable without anybody making a mistake: importing a
			 * document from a site on a newer library does it.
			 */
			$response = (string) ( $rule['response'] ?? 'block' );

			if ( in_array( $response, array( 'redirect', 'mark', 'record' ), true ) && ! $capabilities->has_soft_responses() ) {
				$this->problems[] = sprintf(
					/* translators: 1: rule identifier, 2: response name. */
					__( 'Rule "%1$s" responds with "%2$s", which needs kanopi/firewall 2.26.0 or later. The installed library would never evaluate it, so it was skipped rather than compiled into a rule that silently does nothing.', 'basic-firewall' ),
					(string) ( $rule['id'] ?? '?' ),
					$response
				);

				continue;
			}

			/*
			 * An observing rule the library cannot observe with is skipped.
			 *
			 * Without observe mode the `mode` key is ignored and the rule
			 * enforces. Skipping it errs towards doing nothing, which is what
			 * the administrator asked this rule to do to traffic anyway;
			 * compiling it would refuse visitors while the screen said the rule
			 * was only watching.
			 */
			if ( true === ( $rule['observe'] ?? false ) && ! $capabilities->has_observe_mode() ) {
				$this->problems[] = sprintf(
					/* translators: %s: rule identifier. */
					__( 'Rule "%s" is set to observe only, which the installed firewall library cannot do — it would enforce instead. It was skipped.', 'basic-firewall' ),
					(string) ( $rule['id'] ?? '?' )
				);

				continue;
			}

			/*
			 * A rule asking to verify crawlers, on a library that cannot, is
			 * skipped.
			 *
			 * The library would ignore the key and match on the agent string
			 * alone -- and verification is asked for on allow rules, where that
			 * lets through everybody who claims to be Googlebot. Skipping errs
			 * towards the rule matching nobody, which is what a verifying rule
			 * does to anybody it cannot verify anyway.
			 */
			if ( ! empty( $rule['settings']['verify'] ) && 'user_agent' === (string) ( $rule['type'] ?? '' ) && ! $capabilities->has_identity_verification() ) {
				$this->problems[] = sprintf(
					/* translators: %s: rule identifier. */
					__( 'Rule "%s" verifies crawlers by reverse DNS, which the installed firewall library cannot do — it would believe every client claiming to be one. It was skipped.', 'basic-firewall' ),
					(string) ( $rule['id'] ?? '?' )
				);

				continue;
			}

			/*
			 * A rule asking to verify crawlers with no domain to verify against
			 * is skipped too, for the same reason. The rule screen refuses it,
			 * but an import or WP-CLI stores `verify` with the list emptied of
			 * everything that was not a domain, and compiling that without its
			 * verification is an allow rule for anybody claiming to be Googlebot.
			 */
			if ( 'user_agent' === (string) ( $rule['type'] ?? '' ) && User_Agent::verification_unusable( $settings ) ) {
				$this->problems[] = sprintf(
					/* translators: %s: rule identifier. */
					__( 'Rule "%s" verifies crawlers by reverse DNS but lists no domain to accept — anything that is not a plain domain, such as *.googlebot.com, is dropped. It was skipped rather than compiled into a rule that believes every client claiming to be a crawler.', 'basic-firewall' ),
					(string) ( $rule['id'] ?? '?' )
				);

				continue;
			}

			/*
			 * An edge signal rule for a custom CDN naming no header it can read
			 * is skipped. The library refuses to start on one, and a firewall
			 * that cannot start fails open on every rule -- so compiling it
			 * would trade this rule's absence for all of theirs.
			 */
			if ( 'edge_signal' === (string) ( $rule['type'] ?? '' ) && 'custom' === ( $rule['settings']['provider'] ?? '' ) && array() === Edge_Signal::header_map( (array) $rule['settings'] ) ) {
				$this->problems[] = sprintf(
					/* translators: %s: rule identifier. */
					__( 'Rule "%s" reads edge signals from a custom CDN but names no header the firewall can read, which would stop the firewall starting. It was skipped.', 'basic-firewall' ),
					(string) ( $rule['id'] ?? '?' )
				);

				continue;
			}

			$problem = $this->schedule_problem( $rule, $capabilities );

			if ( null !== $problem ) {
				$this->problems[] = $problem;

				continue;
			}

			/*
			 * A redirect naming nowhere, or somewhere it should not, is skipped.
			 *
			 * The rule screen refuses to save one. This is the same refusal for
			 * every other way a document arrives -- an import, WP-CLI, a
			 * hand-edited option -- because the library does not reject such a
			 * rule when it loads: it throws when the rule *matches*, which turns
			 * each of those requests into a firewall failure that is failed open
			 * on, with any block rule below never reached.
			 */
			if ( 'redirect' === $response && null !== Response_Settings::redirect_problem( (string) ( $rule['redirect_to'] ?? '' ) ) ) {
				$this->problems[] = sprintf(
					/* translators: %s: rule identifier. */
					__( 'Rule "%s" redirects, but not to a path on this site or an http(s) URL. It was skipped rather than compiled into a rule that fails every request it matches.', 'basic-firewall' ),
					(string) ( $rule['id'] ?? '?' )
				);

				continue;
			}

			/*
			 * A condition on a variable the library cannot read is reported,
			 * and the rule compiled as it stands. Skipping it would stop its
			 * other conditions enforcing; dropping the one condition would
			 * widen an "all" rule. Either is a change nobody asked for. What
			 * was wrong was the silence -- the rule reported itself healthy.
			 */
			if ( $type instanceof Condition_Rule_Type_Base ) {
				/*
				 * An equality against a referenced list on a variable the
				 * library reads as an integer is skipped, not reported and
				 * compiled. Unlike an unreadable condition, this one fails in
				 * the dangerous direction: "is not equal to" a list matches
				 * every request, so a block rule would refuse every visitor,
				 * and "is equal to" one never matches while reporting itself
				 * active. The rule screen refuses it; this is the same refusal
				 * for an import, WP-CLI or a hand-edited option.
				 */
				$strict = $type->strict_list_comparisons( $settings );

				if ( array() !== $strict ) {
					$this->problems[] = sprintf(
						/* translators: 1: rule identifier, 2: why. */
						__( 'Rule "%1$s" compares a referenced list for equality in a way that can never work, so it was skipped and is not being enforced: %2$s', 'basic-firewall' ),
						(string) ( $rule['id'] ?? '?' ),
						implode( ' ', array_unique( $strict ) )
					);

					continue;
				}

				foreach ( $type->unreadable_variables( $settings ) as $variable ) {
					$this->problems[] = sprintf(
						/* translators: 1: rule identifier, 2: variable name. */
						__( 'Rule "%1$s" has a condition on %2$s, which the firewall library cannot read. That condition compares against nothing on every request. Edit the rule to remove it.', 'basic-firewall' ),
						(string) ( $rule['id'] ?? '?' ),
						$variable
					);
				}
			}

			/*
			 * A MaxMind database of the wrong type is reported the same way.
			 * The reader throws on every lookup and the library swallows it,
			 * so the rule matches nothing while loading cleanly -- which is
			 * exactly what the Status screen and Site Health are for.
			 */
			if ( method_exists( $type, 'reader_database_problem' ) ) {
				$mismatch = $type->reader_database_problem( $settings );

				if ( is_string( $mismatch ) ) {
					$this->problems[] = sprintf(
						/* translators: 1: rule identifier, 2: what is wrong with its database. */
						__( 'Rule "%1$s": %2$s', 'basic-firewall' ),
						(string) ( $rule['id'] ?? '?' ),
						$mismatch
					);
				}
			}

			try {
				$compiled[] = $type->compile( $rule );
			} catch ( \Throwable $e ) {
				$this->problems[] = sprintf(
					/* translators: 1: rule identifier, 2: the error. */
					__( 'Rule "%1$s" could not be compiled, so it was skipped and is not being enforced: %2$s', 'basic-firewall' ),
					(string) ( $rule['id'] ?? '?' ),
					$e->getMessage()
				);
			}
		}

		// Lower weights first, matching the order the library evaluates in.
		usort(
			$compiled,
			static fn ( array $a, array $b ): int => ( $a['weight'] ?? 0 ) <=> ( $b['weight'] ?? 0 )
		);

		return $compiled;
	}

	/**
	 * A rule's settings as its type's validator leaves them, or null to skip it.
	 *
	 * Settings that are already the validator's output come back unchanged:
	 * every type is required to read back its own output, and a test across
	 * all of them holds it to that. Anything else is compiled from what the
	 * validator makes of it -- which is what the next save of the document
	 * would store -- unless the validator also objected. Then something was
	 * dropped or defaulted to get there, and compiling it would enforce a
	 * rule other than the one stored, possibly a wider one: a condition
	 * dropped out of an "all" rule widens it. Such a rule is skipped and
	 * reported instead, the way every other rule this compiler cannot compile
	 * faithfully is.
	 *
	 * @param Rule_Type            $type The rule's type.
	 * @param array<string, mixed> $rule The stored rule.
	 *
	 * @return array<string, mixed>|null
	 */
	private function normalised_settings( Rule_Type $type, array $rule ): ?array {
		$id     = (string) ( $rule['id'] ?? '?' );
		$stored = $rule['settings'] ?? array();

		if ( ! is_array( $stored ) ) {
			$this->problems[] = sprintf(
				/* translators: %s: rule identifier. */
				__( 'Rule "%s" has settings that are not a set of values at all, so it was skipped and is not being enforced. Open the rule and save it.', 'basic-firewall' ),
				$id
			);

			return null;
		}

		$errors = array();

		try {
			$clean = $type->validate_settings( $stored, $errors );
		} catch ( \Throwable $e ) {
			$this->problems[] = sprintf(
				/* translators: 1: rule identifier, 2: the error. */
				__( 'Rule "%1$s" has settings its type cannot read, so it was skipped and is not being enforced: %2$s', 'basic-firewall' ),
				$id,
				$e->getMessage()
			);

			return null;
		}

		// phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual -- key order is not a difference.
		if ( $clean == $stored ) {
			return $stored;
		}

		/*
		 * An objection counts only where the validator changed the value it
		 * objected to. Some are advisory and leave the value as it was -- a
		 * geolocation rule with no database path is one, and compiles to a
		 * rule the library skips, as it always did -- and so is one about a
		 * value the document never held, which the validator filled in with
		 * its default. A condition the validator dropped, or a list it
		 * emptied, is exactly the change that would enforce something else.
		 */
		$material = array_filter(
			$errors,
			static function ( string $path ) use ( $stored, $clean ): bool {
				$was = self::dig( $stored, $path );

				return self::ABSENT !== $was && self::dig( $clean, $path ) !== $was;
			},
			ARRAY_FILTER_USE_KEY
		);

		if ( array() === $material ) {
			return $clean;
		}

		$this->problems[] = sprintf(
			/* translators: 1: rule identifier, 2: what the validator objected to. */
			__( 'Rule "%1$s" is stored in a shape the rule screen never saves, and reading it would change what it matches (%2$s). It was skipped rather than compiled into a different rule; open it, correct it, and save it.', 'basic-firewall' ),
			$id,
			implode( ' ', array_map( 'strval', $material ) )
		);

		return null;
	}

	/**
	 * The value at a dotted path, or a marker saying there is none.
	 *
	 * @param array<array-key, mixed> $values Document.
	 * @param string                  $path   Dotted path, as a validator names an error.
	 *
	 * @return mixed
	 */
	private static function dig( array $values, string $path ) {
		$cursor = $values;

		foreach ( explode( '.', $path ) as $segment ) {
			if ( ! is_array( $cursor ) || ! array_key_exists( $segment, $cursor ) ) {
				return self::ABSENT;
			}

			$cursor = $cursor[ $segment ];
		}

		return $cursor;
	}

	/**
	 * Why a rule's activity window stops it being compiled, or null.
	 *
	 * The rule screen checks a window with the library before saving it. This
	 * is the same check for every other way a document arrives, and for a
	 * library too old to read one at all.
	 *
	 * Skipped in both cases rather than compiled. A library without windows
	 * would ignore the key and run the rule at all hours; one that cannot read
	 * the window fails the rule at startup anyway, and this way it is named on
	 * the Status screen instead of discovered by its absence.
	 *
	 * @param array<string, mixed> $rule         The stored rule.
	 * @param Library_Capabilities $capabilities What the library can do.
	 */
	private function schedule_problem( array $rule, Library_Capabilities $capabilities ): ?string {
		$declaration = Rule_Type_Base::schedule_declaration( (array) ( $rule['schedule'] ?? array() ) );

		if ( array() === $declaration ) {
			return null;
		}

		if ( ! $capabilities->has_rule_schedule() ) {
			return sprintf(
				/* translators: %s: rule identifier. */
				__( 'Rule "%s" has an activity window, which the installed firewall library cannot keep — it would run at all hours instead. It was skipped.', 'basic-firewall' ),
				(string) ( $rule['id'] ?? '?' )
			);
		}

		try {
			Schedule::fromMetadata( $declaration );
		} catch ( \InvalidArgumentException $e ) {
			return sprintf(
				/* translators: 1: rule identifier, 2: the library's complaint. */
				__( 'Rule "%1$s" has an activity window the firewall library cannot read, so the rule would not start. It was skipped: %2$s', 'basic-firewall' ),
				(string) ( $rule['id'] ?? '?' ),
				$e->getMessage()
			);
		}

		return null;
	}

	/**
	 * Skip challenge rules that name a provider the library cannot build.
	 *
	 * The library constructs every provider a challenge rule names while it
	 * starts, so one rule sending visitors to Turnstile without Turnstile's
	 * keys -- easy to reach by importing a rule from another site -- stops the
	 * firewall starting, and this plugin fails open on that. Skipping the one
	 * rule, loudly, keeps every other rule enforcing.
	 *
	 * Here rather than in compile_rules() because it has to run before the
	 * loops that record each rule's final index for runtime overrides.
	 *
	 * @param list<array<string, mixed>> $rules     Compiled rules.
	 * @param array<string, mixed>       $challenge Stored challenge settings.
	 *
	 * @return list<array<string, mixed>>
	 */
	private function drop_unbuildable_challenges( array $rules, array $challenge ): array {
		foreach ( $rules as $delta => $rule ) {
			$provider = (string) ( $rule['metadata']['challenge_provider'] ?? '' );

			if ( 'challenge' !== ( $rule['response'] ?? '' ) || '' === $provider ) {
				continue;
			}

			$problem = self::challenge_provider_problem( $provider, $challenge );

			if ( null === $problem ) {
				continue;
			}

			$this->problems[] = sprintf(
				/* translators: 1: rule identifier, 2: provider name, 3: what is wrong with it. */
				__( 'Rule "%1$s" challenges with %2$s, %3$s It was skipped: the firewall refuses to start with a challenge provider it cannot build, and every other rule would stop being enforced.', 'basic-firewall' ),
				(string) ( $rule['metadata']['name'] ?? '?' ),
				$provider,
				$problem
			);

			unset( $rules[ $delta ] );
		}

		return array_values( $rules );
	}

	/**
	 * Why the library could not build a challenge provider, or null.
	 *
	 * @param string               $provider  Provider name.
	 * @param array<string, mixed> $challenge Stored challenge settings.
	 */
	private static function challenge_provider_problem( string $provider, array $challenge ): ?string {
		if ( ! isset( Library_Map::CHALLENGE_PROVIDERS[ $provider ] ) ) {
			return __( 'which is not a provider the firewall library has.', 'basic-firewall' );
		}

		if ( ! in_array( $provider, Library_Map::REMOTE_CHALLENGE_PROVIDERS, true ) ) {
			return null;
		}

		$options = (array) ( $challenge['provider_options'][ $provider ] ?? array() );

		if ( '' === trim( (string) ( $options['site_key'] ?? '' ) ) || '' === trim( (string) ( $options['secret_key'] ?? '' ) ) ) {
			return __( 'which needs a site key and a secret key and does not have both.', 'basic-firewall' );
		}

		return null;
	}

	/**
	 * Whether a challenge section has to be emitted.
	 *
	 * @param list<array<string, mixed>> $rules   Compiled rules.
	 * @param list<string>               $presets Enabled preset names.
	 */
	private function needs_challenge( array $rules, array $presets ): bool {
		foreach ( $rules as $rule ) {
			if ( 'challenge' === ( $rule['response'] ?? '' ) ) {
				return true;
			}
		}

		return Plugin::instance()->presets()->requires_challenge( $presets );
	}

	/**
	 * Compile the challenge section.
	 *
	 * @param array<string, mixed>       $challenge Stored challenge settings.
	 * @param list<array<string, mixed>> $rules     Compiled rules, for the providers they name.
	 * @param array<string, mixed>       $pages     Stored `global.pages`: the language and styling every page shares.
	 *
	 * @return array<string, mixed>
	 */
	private function compile_challenge( array $challenge, array $rules, array $pages = array() ): array {
		$provider = (string) ( $challenge['provider'] ?? 'math' );

		/*
		 * The same refusal as drop_unbuildable_challenges(), for the default.
		 * The Challenge screen will not save a remote provider without its
		 * keys, but an import or WP-CLI can. Every challenge rule that names no
		 * provider of its own uses this one, so the choice is between the
		 * firewall not starting at all and challenging with arithmetic until
		 * somebody adds the keys -- and it says so.
		 */
		$problem = self::challenge_provider_problem( $provider, $challenge );

		if ( null !== $problem ) {
			$this->problems[] = sprintf(
				/* translators: 1: provider name, 2: what is wrong with it. */
				__( 'The challenge provider is %1$s, %2$s The arithmetic challenge is used instead, because the firewall refuses to start with a provider it cannot build.', 'basic-firewall' ),
				$provider,
				$problem
			);

			$provider = 'math';
		}

		$compiled = array(
			'provider'    => $provider,
			'path'        => (string) ( $challenge['path'] ?? '/basic-firewall/challenge' ),

			/*
			 * Always written out, never left to the library's own default
			 * (`fw_challenge_pass`), so the compiled file names the cookie
			 * both evaluation paths read and the runner sets: the name on the
			 * Challenge screen, trimmed, or `bfw_pass`. See Pass_Cookie.
			 */
			'cookie_name' => Pass_Cookie::name( (string) ( $challenge['cookie_name'] ?? '' ) ),
			'header_name' => (string) ( $challenge['header_name'] ?? 'X-Firewall-Pass' ),

			/*
			 * A ceiling as well as a default, which is the whole point of it.
			 *
			 * Needs library 2.30.0. Before it, the lifetime that signs a pass
			 * token was whatever the interstitial's POST body asked for --
			 * solve one arithmetic puzzle, post a lifetime of thirty-one years,
			 * and hold a signed exemption from every challenge rule for three
			 * decades. The signature was valid; it covered the number the
			 * client chose.
			 *
			 * Written out rather than left to the library's own default so the
			 * value is visible in the compiled file and on the screen that sets
			 * it, because a rule asking for longer than this is silently
			 * granted this instead.
			 */
			'ttl'         => max( 60, (int) ( $challenge['ttl'] ?? 3600 ) ),
		);

		/*
		 * Where the interstitial posts its answer, named rather than left to
		 * the library.
		 *
		 * Left alone, the library builds the form's action from the request's
		 * base path, which on a direct file is the file's directory: a
		 * challenge on `/wp-admin/edit.php` posted to
		 * `/wp-admin/basic-firewall/challenge`. The web server routes that
		 * through index.php, where the path is not the challenge path, so the
		 * answer was never recognised and the visitor was challenged again.
		 * The challenge path is matched through the front controller, so the
		 * answer belongs under the front controller's directory -- the same
		 * base path the compiled `global.base_path` names. Only for a rooted
		 * path; anything else is already an address the browser resolves.
		 */
		if ( 0 === strpos( $compiled['path'], '/' ) ) {
			$compiled['submit_url'] = Site_Layout::base_path() . $compiled['path'];
		}

		$secret = Challenge_Secret::resolve();

		if ( null === $secret ) {
			$this->problems[] = __( 'A rule is set to challenge but there is no signing secret. The firewall will refuse to start, and every rule stops being enforced.', 'basic-firewall' );
		} else {
			$compiled['secret'] = $secret;
		}

		$audience = trim( (string) ( $challenge['audience'] ?? '' ) );

		if ( '' !== $audience ) {
			$compiled['audience'] = $audience;
		}

		/*
		 * Keyed by provider, under `provider_options`, which is where the
		 * library reads them. This used to write a flat `options` key the
		 * library has never read, so no provider received anything: Turnstile
		 * and reCAPTCHA refused to construct without their keys, the library
		 * refused to start, and the plugin failed open -- nothing enforced,
		 * every screen saying configured. ALTCHA's widget settings were
		 * dropped the same way, only quietly.
		 *
		 * Nested rather than flat, and for every provider in play: the default
		 * and each one a rule overrides to. The library hands a flat block to
		 * the default provider only, so a rule sending visitors to reCAPTCHA
		 * while Turnstile is the default would get no keys at all. Providers
		 * nothing uses are left out, so a credential nothing reads is not
		 * written into the compiled file.
		 */
		$providers = array( $provider );

		foreach ( $rules as $rule ) {
			if ( 'challenge' === ( $rule['response'] ?? '' ) && '' !== (string) ( $rule['metadata']['challenge_provider'] ?? '' ) ) {
				$providers[] = (string) $rule['metadata']['challenge_provider'];
			}
		}

		$provider_options = array();

		foreach ( array_unique( $providers ) as $name ) {
			$options = self::provider_options( (array) ( $challenge['provider_options'][ $name ] ?? array() ) );

			if ( array() !== $options ) {
				$provider_options[ $name ] = $options;
			}
		}

		if ( array() !== $provider_options ) {
			$compiled['provider_options'] = $provider_options;
		}

		/*
		 * The interstitial's wording, language and styling (library 2.37.0,
		 * kanopi/firewall#451). Only what is set: an empty key keeps the
		 * library's own wording, and an absent `page` is the page as before.
		 */
		$page = Page_Settings::challenge( (array) ( $challenge['page'] ?? array() ), $pages );

		if ( array() !== $page ) {
			$compiled['page'] = $page;
		}

		/*
		 * Plain text shown on every challenge page, above the form (library
		 * 2.35.0): a help address, or why visitors are being asked. Blank
		 * lines are dropped rather than shown as empty boxes.
		 */
		$notices = array_values(
			array_filter(
				array_map( static fn ( $notice ): string => trim( (string) $notice ), (array) ( $challenge['notice'] ?? array() ) ),
				static fn ( string $notice ): bool => '' !== $notice
			)
		);

		if ( array() !== $notices ) {
			$compiled['notice'] = $notices;
		}

		return $compiled;
	}

	/**
	 * One provider's options, in the library's vocabulary.
	 *
	 * Public and static because it is the whole of the translation between
	 * what the Challenge screen stores and what a provider reads, and a unit
	 * test can pin it without a site.
	 *
	 * @param array<string, mixed> $options Stored options for one provider.
	 *
	 * @return array<string, mixed>
	 */
	public static function provider_options( array $options ): array {
		$options = array_filter(
			$options,
			static fn ( $value ): bool => '' !== $value && null !== $value
		);

		/*
		 * The screen stores `fail` and `pass`; Turnstile and reCAPTCHA read
		 * `block` and `allow`, and treat anything else as `block`. So "let the
		 * visitor through" was silently "reject them". Translated here rather
		 * than rewritten in storage, so a value saved by any build keeps
		 * working, and the library's own spelling passes through unchanged.
		 */
		if ( isset( $options['on_error'] ) ) {
			$options['on_error'] = in_array( $options['on_error'], array( 'pass', 'allow' ), true ) ? 'allow' : 'block';
		}

		/*
		 * The providers clamp this to Library_Map::CHALLENGE_TIMEOUT_MAX. The
		 * screen caps it there too; a larger value from an older build or an
		 * import is written as what will actually happen.
		 */
		if ( isset( $options['timeout'] ) ) {
			$options['timeout'] = max( 1, min( Library_Map::CHALLENGE_TIMEOUT_MAX, (int) $options['timeout'] ) );
		}

		return $options;
	}

	/**
	 * Compile the log handlers.
	 *
	 * @param array<int, mixed> $handlers Stored handlers.
	 *
	 * @return list<array<string, mixed>>
	 */
	private function compile_logger( array $handlers ): array {
		$compiled    = array();
		$levels      = Library_Map::log_levels();
		$paths       = Plugin::instance()->paths();
		$credentials = new Database_Credentials();

		foreach ( $handlers as $handler ) {
			if ( ! is_array( $handler ) || empty( $handler['enabled'] ) ) {
				continue;
			}

			$type = (string) ( $handler['type'] ?? 'rotating_file' );

			if ( ! isset( Library_Map::LOG_HANDLERS[ $type ] ) ) {
				continue;
			}

			$level = $levels[ (string) ( $handler['level'] ?? 'warning' ) ] ?? $levels['warning'];

			if ( in_array( $type, Library_Map::LOG_HANDLERS_KEYED, true ) ) {
				/*
				 * Every key here is the library's own spelling, and two of them
				 * were not.
				 *
				 * The handler reads `buffer` and `retention_days`; this wrote
				 * `buffered` and `retain_days`. A declaration is read with array
				 * keys, so neither was an error -- both were ignored and the
				 * defaults applied. The Buffering checkbox therefore did
				 * nothing and the handler always buffered, and "Keep history
				 * for" did nothing and retention stayed at zero, which is the
				 * table that only grows the field's own help text warns about.
				 */
				$options = array(
					'table'                    => 'wordpress' === ( $handler['connection_source'] ?? 'wordpress' )
						? $credentials->prefix_table( (string) ( $handler['table'] ?? 'basic_firewall_log' ) )
						: (string) ( $handler['table'] ?? 'basic_firewall_log' ),
					'level'                    => $level,
					'buffer'                   => ! empty( $handler['buffered'] ),
					'retention_days'           => (int) ( $handler['retain_days'] ?? 30 ),

					/*
					 * The retention delete, in batches (library 2.37.0,
					 * kanopi/firewall#459, #464). Before it, the first prune
					 * after retention was switched on or lowered deleted the
					 * whole backlog in one statement, inside a visitor's
					 * request, locking the table every other request writes to.
					 */
					'prune_batch_size'         => max( 1, (int) ( $handler['prune_batch_size'] ?? 1000 ) ),
					'prune_max_batches'        => max( 1, (int) ( $handler['prune_max_batches'] ?? 10 ) ),

					/*
					 * The library checks its schema on one write in a hundred,
					 * which is the right cost on a table that exists and the
					 * wrong behaviour on one that does not: a fresh install
					 * loses roughly its first hundred events while the handler
					 * waits for its turn to notice there is nowhere to put
					 * them. Checked on every write for the first few instead --
					 * the check is one query against a table this handler is
					 * about to write to anyway.
					 */
					'schema_check_probability' => 1.0,
				);

				$entry = array(
					'class' => Library_Map::LOG_HANDLERS[ $type ],
					'args'  => array( $options ),
				);

				$deferred = ! empty( $handler['deferred'] );

				if ( 'wordpress' === ( $handler['connection_source'] ?? 'wordpress' ) ) {
					/*
					 * The injection path has to follow the wrapping. A deferred
					 * handler holds the real one as its own first argument, so
					 * the connection moves a level down -- and a path that
					 * misses injects the credentials nowhere, silently, leaving
					 * the handler with no connection at all.
					 */
					$this->connection_paths[] = sprintf(
						$deferred
							? '[logger][%d][args][0][args][0][connection]'
							: '[logger][%d][args][0][connection]',
						count( $compiled )
					);
				} elseif ( 'parameters' === ( $handler['connection_source'] ?? '' ) ) {
					/*
					 * Compiled like the block list's. This branch used not to
					 * exist, so a handler set to individual parameters was
					 * written with no connection at all and disabled itself on
					 * its first record.
					 */
					$parameters = $this->compile_connection_parameters( (array) ( $handler['parameters'] ?? array() ) );

					if ( array() !== $parameters ) {
						$entry['args'][0]['connection'] = $parameters;
					} else {
						$this->problems[] = __( 'A database log handler is set to connect with individual parameters but has no driver and database name, so it cannot connect and records nothing.', 'basic-firewall' );
					}
				} elseif ( '' !== trim( (string) ( $handler['dsn'] ?? '' ) ) ) {
					$entry['args'][0]['connection'] = array( 'dsn' => trim( (string) $handler['dsn'] ) );
				}

				$compiled[] = $deferred ? self::defer( $entry, $level ) : $entry;

				continue;
			}

			/*
			 * Positional constructor arguments, ordered per handler.
			 *
			 * The path is written as typed, for the same reason the storage
			 * file is: the library resolves a relative `args.0` on a stream or
			 * rotating-file handler against the directory holding the config
			 * that named it, missing file and all. See Paths::portable().
			 */
			$log_path = $paths->portable( (string) ( $handler['path'] ?? 'logs/firewall.log' ) );

			if ( '' === $log_path ) {
				$log_path = 'logs/firewall.log';
			}

			$args = match ( $type ) {
				'rotating_file' => array(
					$log_path,
					(int) ( $handler['max_files'] ?? 14 ),
					$level,
				),
				'stream'        => array(
					$log_path,
					$level,
				),
				// ErrorLogHandler takes a message type first, then the level.
				default         => array( 0, $level ),
			};

			$entry = array(
				'class' => Library_Map::LOG_HANDLERS[ $type ],
				'args'  => $args,
			);

			$compiled[] = empty( $handler['deferred'] ) ? $entry : self::defer( $entry, $level );
		}

		return $compiled;
	}

	/**
	 * Wrap a handler so it writes after the visitor has been served.
	 *
	 * Needs library 2.31.0 twice over: for `DeferredHandler` itself, and for
	 * `logger:` being able to carry a nested `{class, args}` at all. Before it,
	 * a wrapping handler could not be expressed in configuration -- the args
	 * list took scalars, and the documented answer was to write PHP.
	 *
	 * @param array<string, mixed> $entry The handler to wrap.
	 * @param string               $level Minimum level, as a Monolog enum reference.
	 *
	 * @return array<string, mixed>
	 */
	private static function defer( array $entry, string $level ): array {
		return array(
			'class' => Library_Map::LOG_HANDLER_DEFERRED,
			'args'  => array(
				$entry,

				/*
				 * Zero, meaning hold every record until shutdown. Any other
				 * limit flushes the moment it is reached, which is mid-request,
				 * which is the thing being avoided.
				 */
				0,
				$level,
			),
		);
	}

	/**
	 * Merge the advanced YAML over the compiled configuration.
	 *
	 * For conditions the forms cannot express -- groups nested inside groups --
	 * and for anything the library gains before this plugin has a screen for it.
	 *
	 * @param array<string, mixed> $compiled Compiled configuration.
	 * @param string               $yaml     Raw YAML.
	 *
	 * @return array<string, mixed>
	 */
	private function apply_advanced_yaml( array $compiled, string $yaml ): array {
		if ( '' === trim( $yaml ) ) {
			return $compiled;
		}

		try {
			$parsed = Yaml::parse( $yaml );
		} catch ( \Throwable $e ) {
			$this->problems[] = sprintf(
				/* translators: %s: parser error message. */
				__( 'The advanced YAML could not be parsed and was ignored: %s', 'basic-firewall' ),
				$e->getMessage()
			);

			return $compiled;
		}

		if ( ! is_array( $parsed ) ) {
			return $compiled;
		}

		return self::merge_deep( $compiled, $parsed );
	}

	/**
	 * Recursively merge, with the override winning.
	 *
	 * A list is replaced rather than concatenated: somebody writing a `plugins`
	 * list in the advanced screen means "these", not "these as well as the ones
	 * I configured elsewhere".
	 *
	 * @param array<mixed> $base     Base array.
	 * @param array<mixed> $override Override array.
	 *
	 * @return array<mixed>
	 */
	private static function merge_deep( array $base, array $override ): array {
		foreach ( $override as $key => $value ) {
			if ( is_array( $value ) && isset( $base[ $key ] ) && is_array( $base[ $key ] ) && ! array_is_list( $value ) ) {
				$base[ $key ] = self::merge_deep( $base[ $key ], $value );

				continue;
			}

			$base[ $key ] = $value;
		}

		return $base;
	}

	/**
	 * Property-access paths where live credentials must be injected.
	 *
	 * @return list<string>
	 */
	public function connection_paths(): array {
		return $this->connection_paths;
	}

	/**
	 * Where a Redis password belongs, with the username that goes with it.
	 *
	 * @return array<string, string> Property-access path => ACL username, or empty.
	 */
	public function redis_auth_paths(): array {
		return $this->redis_auth_paths;
	}

	/**
	 * Paths where an object cache pool for agent detection belongs.
	 *
	 * Recorded during the compile rather than worked out later, because only
	 * the compile knows which rule became which plugin index once disabled and
	 * skipped rules are dropped -- the same reason the connection paths are.
	 *
	 * @return list<string>
	 */
	public function cache_pool_paths(): array {
		return $this->cache_pool_paths;
	}

	/**
	 * Paths where an object cache pool for reverse-DNS verdicts belongs.
	 *
	 * @return list<string>
	 */
	public function verify_cache_paths(): array {
		return $this->verify_cache_paths;
	}

	/**
	 * Problems encountered during the last compile.
	 *
	 * @return list<string>
	 */
	public function problems(): array {
		return $this->problems;
	}
}
