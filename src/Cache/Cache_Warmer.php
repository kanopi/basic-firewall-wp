<?php
/**
 * Builds the agent corpus before a visitor has to.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Cache;

use Kanopi\BasicFirewall\Plugin;
use Kanopi\Firewall\Plugins\UserAgent;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Yaml\Yaml;

/**
 * Fills the agent corpus cache, so a visitor is not the one who pays for it.
 *
 * Identifying an agent means compiling a 1.7 MB pattern set. The first request
 * to reach a user agent rule after a deploy, a cache clear or a PHP restart
 * pays for it -- the better part of a second. This pays it ahead of time.
 *
 * **Only the agent corpus can be built ahead of time.** The other caches --
 * reverse-DNS verdicts, AbuseIPDB verdicts -- are keyed on the visitor's
 * address. There is nothing to work out for an address that has not arrived,
 * and prefetching reputation would spend API quota on addresses that may
 * never visit.
 *
 * It warms through the library's own plugin, built from the compiled rule,
 * rather than by driving a cache pool directly. The pool a rule uses depends
 * on the backend, and reproducing that choice here would be one more copy to
 * keep in step with the compiler, the clearer and the runner. And the plugin
 * stops parsing at the deepest phase the configured conditions read: a rule
 * that only asks `bot` has no use for brand and model detection, so warming
 * anything else would fill corpora the site never reads and leave the ones it
 * does read cold.
 *
 * Reached three ways: `wp basic-firewall warm-cache`, a button on the Storage
 * screen, and a one-off cron event after each rebuild -- which is how a deploy,
 * an activation or an upgrade warms the corpus without anybody remembering to.
 */
final class Cache_Warmer {

	/**
	 * The one-off event scheduled after a rebuild.
	 */
	public const HOOK = 'basic_firewall_warm_cache';

	/**
	 * Agents to parse, chosen for what they make the detector compile.
	 *
	 * Two, because they cost very different things. A bot agent fills the bot
	 * corpus alone and is quick. A browser agent walks the client, OS and
	 * device corpora, which is most of the work and most of what real traffic
	 * asks for. Warming only a bot would look like it had worked and leave the
	 * cost where it was.
	 */
	private const AGENTS = array(
		'bot'     => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
		'browser' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
	);

	/**
	 * Hook the scheduled warm, and schedule one after every rebuild.
	 */
	public static function register(): void {
		add_action( self::HOOK, array( self::class, 'run_scheduled' ) );
		add_action( 'basic_firewall_compiled', array( self::class, 'schedule' ) );
	}

	/**
	 * Schedule a warm shortly, if the compiled rules give it anything to do.
	 *
	 * On cron rather than inline, because a rebuild follows every settings
	 * save and the warm is the better part of a second: an administrator
	 * saving a form should not pay what this exists to spare a visitor.
	 * WP-Cron runs in a web request where it can, which also makes it the one
	 * route that reaches APCu.
	 */
	public static function schedule(): void {
		if ( false !== wp_next_scheduled( self::HOOK ) || array() === self::agent_rules() ) {
			return;
		}

		wp_schedule_single_event( time() + 30, self::HOOK );
	}

	/**
	 * The scheduled warm. Never throws: a cache that stays cold is slow, not broken.
	 */
	public static function run_scheduled(): void {
		try {
			( new self() )->warm();
		} catch ( \Throwable $e ) {
			return;
		}
	}

	/**
	 * Warm the agent corpus for every user agent rule that caches.
	 *
	 * Safe to run repeatedly: a warm cache is read rather than rewritten, so
	 * the second run costs a lookup.
	 *
	 * @return array{rules: int, agents: int, ms: int} How many rules were warmed,
	 *         with how many agents each, and how long it took. A site with no
	 *         user agent rules warms nothing and says so with a rule count of
	 *         zero, rather than reporting a success that did nothing.
	 */
	public function warm(): array {
		/*
		 * The same constant the runner defines before evaluating. Warming runs
		 * from WP-CLI and cron, neither of which need have evaluated anything,
		 * and without it a files-backed warm fills the library's fallback in
		 * the system temporary directory, which no request will ever read.
		 */
		if ( ! defined( 'KANOPI_FIREWALL_CACHE_DIR' ) ) {
			define( 'KANOPI_FIREWALL_CACHE_DIR', Plugin::instance()->paths()->library_cache_dir() );
		}

		$pool    = Cache_Backend::agent_pool();
		$started = microtime( true );
		$warmed  = 0;

		foreach ( self::agent_rules() as $plugin ) {
			$metadata = (array) ( $plugin['metadata'] ?? array() );

			// The object cache cannot be written into the file, so it is handed
			// over here exactly as the runner hands it over.
			if ( null !== $pool ) {
				$metadata['cache'] = $pool;
			}

			$class = (string) $plugin['plugin'];
			$rule  = new $class( $metadata, (array) ( $plugin['config'] ?? array() ) );

			foreach ( self::AGENTS as $agent ) {
				/*
				 * The verdict is discarded. This is here to make the detector
				 * compile its corpus and store it, and a rule matching this
				 * agent has nothing to act on: there is no visitor, and the
				 * plugin records nothing by being evaluated on its own.
				 */
				$rule->evaluate(
					Request::create(
						'/',
						'GET',
						array(),
						array(),
						array(),
						array(
							'REMOTE_ADDR'     => '127.0.0.1',
							'HTTP_USER_AGENT' => $agent,
						)
					)
				);
			}

			++$warmed;
		}

		return array(
			'rules'  => $warmed,
			'agents' => count( self::AGENTS ),
			'ms'     => (int) round( ( microtime( true ) - $started ) * 1000 ),
		);
	}

	/**
	 * The compiled user agent rules that cache.
	 *
	 * Read from the compiled file rather than from settings, because that is
	 * what carries the pool each rule was given. A rule that turned its cache
	 * off is left out: warming it would write a corpus it will not read, and
	 * the site said not to. A preset's rules are included by reference and are
	 * not read here; the corpus they share is warmed by any rule of the site's
	 * own that asks as deeply.
	 *
	 * @return list<array<string, mixed>>
	 */
	private static function agent_rules(): array {
		$path = Plugin::instance()->paths()->compiled_file();

		if ( ! is_readable( $path ) ) {
			return array();
		}

		try {
			$compiled = Yaml::parseFile( $path );
		} catch ( \Throwable $e ) {
			return array();
		}

		$rules = array();

		foreach ( (array) ( is_array( $compiled ) ? ( $compiled['plugins'] ?? array() ) : array() ) as $plugin ) {
			if ( ! is_array( $plugin ) || ! is_a( (string) ( $plugin['plugin'] ?? '' ), UserAgent::class, true ) ) {
				continue;
			}

			if ( false === ( $plugin['metadata']['cache'] ?? null ) ) {
				continue;
			}

			$rules[] = $plugin;
		}

		return $rules;
	}
}
