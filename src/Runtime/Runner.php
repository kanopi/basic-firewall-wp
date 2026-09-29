<?php
/**
 * Builds the firewall and evaluates the request.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Runtime;

use Kanopi\BasicFirewall\Cache\Cache_Backend;
use Kanopi\BasicFirewall\Database_Credentials;
use Kanopi\BasicFirewall\Library_Loader;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\Firewall\Firewall;
use Symfony\Component\HttpFoundation\Request;

/**
 * The normal evaluation path.
 *
 * **Failure posture: always fail open.** If the compiled file is missing,
 * unreadable or invalid, the request is allowed through and the problem is
 * reported in Site Health. A firewall misconfiguration will never be the reason
 * a site is unreachable. That is a deliberate choice with a cost -- a broken
 * firewall enforces nothing -- and the whole reason `require_config` defaults to
 * on is to make sure the failure is loud rather than silent.
 */
final class Runner {

	/**
	 * The wp-config.php constant that switches the firewall off entirely.
	 */
	public const ENABLED_CONSTANT = 'BASIC_FIREWALL_ENABLED';

	/**
	 * Where a mark is mirrored for code that reads request headers.
	 *
	 * `X-Firewall-Mark`, as PHP names a request header in `$_SERVER`.
	 */
	public const MARK_SERVER_KEY = 'HTTP_X_FIREWALL_MARK';

	/**
	 * Why evaluation did not happen, or null.
	 *
	 * @var string|null
	 */
	private static ?string $failure = null;

	/**
	 * Marks the firewall applied to this request.
	 *
	 * @var list<string>
	 */
	private static array $marks = array();

	/**
	 * Evaluate the current request.
	 *
	 * Never throws. Returns true when the request may continue -- which includes
	 * every failure case.
	 *
	 * @param Request|null $request Request to evaluate, or null for the current one.
	 */
	public function evaluate( ?Request $request = null ): bool {
		/*
		 * Before anything else, and on every branch: an `X-Firewall-Mark` the
		 * client sent is not a mark. The header is where this plugin mirrors
		 * the marks it applies, and code reading it has no way to tell the
		 * two apart -- so a scanner could otherwise mark itself as whatever a
		 * downstream check trusts, or pass itself off as unmarked. Only when
		 * evaluating the current request: a request handed in by a caller is
		 * not the one $_SERVER describes.
		 */
		if ( null === $request ) {
			self::forget_client_marks();
		}

		if ( defined( 'BASIC_FIREWALL_EVALUATED' ) ) {
			/*
			 * The wp-config.php path already dealt with this request -- but it
			 * did so before WordPress existed, so anything it wants to announce
			 * has been waiting in a global for somewhere to announce it, and
			 * anything it could not answer has been waiting to be answered.
			 */
			$this->adopt_early_marks();

			return $this->answer_early_outcome();
		}

		if ( ! $this->is_enabled() ) {
			return true;
		}

		if ( ! Library_Loader::is_usable() ) {
			self::$failure = Library_Loader::failure() ?? __( 'The firewall library is not available.', 'basic-firewall' );

			return true;
		}

		define( 'BASIC_FIREWALL_EVALUATED', true );

		$compiled = Plugin::instance()->paths()->compiled_file();

		if ( ! is_readable( $compiled ) ) {
			self::$failure = __( 'There is no compiled configuration, so no rules were evaluated. Rebuild the firewall.', 'basic-firewall' );

			return true;
		}

		$this->define_cache_constants();

		/*
		 * Before the firewall is built, because every address-based rule depends
		 * on it. Symfony only honours a forwarding header once this is
		 * established; until then every visitor behind the proxy shares one
		 * address, and one visitor's offense blocks the lot.
		 */
		Trusted_Proxies::apply();

		try {
			/*
			 * The dispatcher is what makes a decision reachable from WordPress
			 * at all -- see Decision_Dispatcher for why it announces later than
			 * it is told.
			 */
			$firewall = Firewall::create( array( $compiled ), $this->overrides(), new Decision_Dispatcher() );
		} catch ( \Throwable $e ) {
			/*
			 * With require_config on, the library refuses to start rather than
			 * running with a partial ruleset that allows everything and looks
			 * like success. This is where that refusal lands: logged, reported,
			 * and then failed open on. Traffic is treated the same as it would
			 * have been; the difference is that somebody finds out.
			 */
			self::$failure = sprintf(
				/* translators: %s: error message. */
				__( 'The firewall could not start, so no rules were evaluated: %s', 'basic-firewall' ),
				$e->getMessage()
			);

			return true;
		}

		/*
		 * The request is built here rather than left to the library, so that
		 * the marks can be read back off it afterwards.
		 *
		 * A `mark` response sets `firewall.marks` as an attribute on the Symfony
		 * Request, for the application downstream to act on. WordPress has no
		 * idea that object exists -- so without this, `mark` is a response type
		 * the rule screen offers and nothing on the site can ever observe.
		 */
		$request = $request ?? Request::createFromGlobals();

		try {
			$allowed = $firewall->evaluate( $request );

			$this->publish_marks( $request );

			return $allowed;
		} catch ( \Throwable $e ) {
			// A blocking exception is the library's way of saying "rejected" in
			// exception mode. The responder decides what the visitor sees.
			return ( new Outcome_Responder() )->respond( $e, $request );
		}
	}

	/**
	 * Answer an `exception` mode verdict the wp-config.php path left behind.
	 *
	 * The bootstrap answers refusals itself, before a page cache can serve the
	 * page. What it leaves here is a solved challenge, which needs settings to
	 * set the pass cookie -- and, only if this copy of the plugin is missing
	 * its responder, a refusal it had no way to answer. Either way it is
	 * answered here, at `muplugins_loaded` when the loader is installed, and
	 * at `plugins_loaded` when it is not. Late, but answered: dropping it would
	 * serve a refused visitor the page.
	 *
	 * Taken out of the global before it is answered, so nothing answers it
	 * twice.
	 */
	private function answer_early_outcome(): bool {
		$early = self::early_outcome();

		if ( null === $early ) {
			return true;
		}

		unset( $GLOBALS['basic_firewall_outcome'] );

		return ( new Outcome_Responder() )->respond( $early['outcome'], $early['request'] );
	}

	/**
	 * The verdict the wp-config.php path left for WordPress to answer, if any.
	 *
	 * @return array{outcome: \Throwable, request: Request|null}|null
	 */
	public static function early_outcome(): ?array {
		$stash = $GLOBALS['basic_firewall_outcome'] ?? null;

		if ( ! is_array( $stash ) || ! ( ( $stash['outcome'] ?? null ) instanceof \Throwable ) ) {
			return null;
		}

		return array(
			'outcome' => $stash['outcome'],
			'request' => ( $stash['request'] ?? null ) instanceof Request ? $stash['request'] : null,
		);
	}

	/**
	 * Announce marks the wp-config.php path recorded before WordPress loaded.
	 */
	private function adopt_early_marks(): void {
		$marks = $GLOBALS['basic_firewall_marks'] ?? null;

		if ( ! is_array( $marks ) || array() === $marks || array() !== self::$marks ) {
			return;
		}

		self::$marks = array_values( array_map( 'strval', $marks ) );

		foreach ( self::$marks as $mark ) {
			$_SERVER[ self::MARK_SERVER_KEY ] = $mark;
		}

		/** This filter is documented in src/Runtime/Runner.php */
		do_action( 'basic_firewall_request_marked', self::$marks, null );
	}

	/**
	 * Hand any marks the firewall set to WordPress.
	 *
	 * A marked request is allowed through and flagged -- the honeypot case,
	 * where you want to know who tripped a rule without telling them they did.
	 * The library records that on the Symfony Request; this makes it reachable
	 * from a theme, a plugin, or a logging hook.
	 *
	 * @param Request $request The evaluated request.
	 */
	private function publish_marks( Request $request ): void {
		$marks = $request->attributes->get( 'firewall.marks' );

		if ( ! is_array( $marks ) || array() === $marks ) {
			return;
		}

		self::$marks = array_values( array_map( 'strval', $marks ) );

		/*
		 * Mirrored into $_SERVER so that code reading headers the ordinary way
		 * sees it, which is how a mark reaches something that was never written
		 * to know this plugin exists.
		 */
		foreach ( self::$marks as $mark ) {
			$_SERVER[ self::MARK_SERVER_KEY ] = $mark;
		}

		/**
		 * Fires when the firewall marked this request without refusing it.
		 *
		 * @param list<string> $marks   The marks applied, each a rule identifier
		 *                              or the rule's configured mark name.
		 * @param Request      $request The evaluated request.
		 */
		do_action( 'basic_firewall_request_marked', self::$marks, $request );
	}

	/**
	 * Drop any `X-Firewall-Mark` header the client sent.
	 *
	 * The header is the plugin's to set, so one that arrived with the request
	 * is removed before evaluation rather than left for code downstream to
	 * mistake for a mark. The wp-config.php path does the same in
	 * bootstrap.php, before WordPress exists to call this.
	 */
	public static function forget_client_marks(): void {
		unset( $_SERVER[ self::MARK_SERVER_KEY ] );
	}

	/**
	 * The marks the firewall applied to this request.
	 *
	 * @return list<string>
	 */
	public static function marks(): array {
		return self::$marks;
	}

	/**
	 * Whether the firewall marked this request with a given name.
	 *
	 * @param string $mark Mark name.
	 */
	public static function is_marked( string $mark ): bool {
		return in_array( $mark, self::$marks, true );
	}

	/**
	 * Whether the firewall should run at all.
	 *
	 * The constant is checked first and needs no database access, which is what
	 * makes it the documented way out of a lockout.
	 */
	public function is_enabled(): bool {
		if ( defined( self::ENABLED_CONSTANT ) && false === constant( self::ENABLED_CONSTANT ) ) {
			return false;
		}

		return (bool) Plugin::instance()->settings()->get( 'enabled', true );
	}

	/**
	 * Runtime overrides applied over the compiled file.
	 *
	 * @return array<string, mixed>
	 */
	private function overrides(): array {
		$overrides = array();

		/*
		 * A mode pinned in wp-config.php stays pinned, panic file or not. The
		 * compiler already writes the constant's mode into the file, but the
		 * library applies a panic file over whatever mode the configuration
		 * arrived at -- so an environment that pins its mode would otherwise
		 * have it changed by a file nobody deployed. The bootstrap does the
		 * same on the other path.
		 */
		if ( defined( 'BASIC_FIREWALL_MODE' ) ) {
			$overrides['[global][panic_file]'] = '';
		}

		/*
		 * Live database credentials, injected at the paths the compiler
		 * recorded. They are never written into the compiled file -- see
		 * Database_Credentials for why a baked snapshot goes stale silently on a
		 * platform that rotates them.
		 */
		$paths = Plugin::instance()->compiled()->connection_paths();

		if ( array() !== $paths ) {
			$credentials = ( new Database_Credentials() )->get_connection_parameters();

			if ( array() !== $credentials ) {
				foreach ( $paths as $path ) {
					$overrides[ $path ] = $credentials;
				}
			}
		}

		/*
		 * The object cache, if that is where the site caches. Handed over
		 * live because YAML cannot carry an object; the other backends are in
		 * the compiled file already and add nothing here.
		 */
		$overrides += Cache_Backend::overrides();

		/**
		 * Filters the runtime overrides applied over the compiled configuration.
		 *
		 * Overrides are applied at runtime and never written to disk, which
		 * makes this the right place to vary the firewall per environment --
		 * the equivalent of the module's `basic_firewall_config_overrides`.
		 *
		 * @param array<string, mixed> $overrides Symfony property-access paths to values.
		 */
		return apply_filters( 'basic_firewall_config_overrides', $overrides );
	}

	/**
	 * Point the library's parse cache somewhere writable and persistent.
	 *
	 * This is the single biggest performance factor in the whole plugin: 0.08 ms
	 * to read the compiled configuration from the parse cache against 42 ms to
	 * parse the YAML. Left to its own devices the library falls back to the
	 * system temporary directory, which gets cleared -- and every clear costs
	 * that 42 ms again, on every php-fpm worker.
	 */
	private function define_cache_constants(): void {
		if ( ! defined( 'KANOPI_FIREWALL_CACHE_DIR' ) ) {
			define( 'KANOPI_FIREWALL_CACHE_DIR', Plugin::instance()->paths()->library_cache_dir() );
		}

		if ( ! defined( 'KANOPI_FIREWALL_SOURCES_OFFLINE' ) ) {
			/*
			 * Only an explicit false opts out. Anything else, the constant being
			 * absent included, keeps network access off the request path -- a
			 * firewall that makes an outbound HTTP call while a visitor waits is
			 * a firewall that fails when the network does.
			 */
			define(
				'KANOPI_FIREWALL_SOURCES_OFFLINE',
				! ( defined( 'BASIC_FIREWALL_SOURCES_OFFLINE' ) && false === constant( 'BASIC_FIREWALL_SOURCES_OFFLINE' ) )
			);
		}
	}

	/**
	 * Backends that built but could not reach what they were configured with.
	 *
	 * Never throws. A firewall that cannot be built at all is a different
	 * problem, reported by a different check, and this one returning nothing is
	 * the right answer to "what degraded" when the answer is "everything".
	 *
	 * Needs library 2.28.0, which composer.json now requires. Before it these
	 * backends did not degrade -- they stopped the firewall starting, which on
	 * a blocking site meant no protection rather than less.
	 *
	 * @return list<array<string, mixed>>
	 */
	public function degraded_backends(): array {
		$firewall = $this->build_for_reporting();

		if ( null === $firewall ) {
			return array();
		}

		return array_values( $firewall->getDegradedBackends() );
	}

	/**
	 * An armed panic switch, as the library sees it.
	 *
	 * A panic file is not in the compiled configuration -- it is a path the
	 * library stats on each request -- so asking a firewall is the only way to
	 * know whether one is in force. Reading the mode out of settings, or out
	 * of the compiled file, cannot see it at all, which is exactly how a site
	 * comes to be reported as blocking three weeks after somebody wrote `log`
	 * into a file during an incident and went to bed.
	 *
	 * @return array{active: bool, path: string|null, problem: string|null, configured: string, effective: string}|null
	 *         Null when nothing is armed, or it is armed with no file present.
	 */
	public function panic_switch(): ?array {
		$firewall = $this->build_for_reporting();

		if ( null === $firewall ) {
			return null;
		}

		$switch  = $firewall->getPanicSwitch();
		$active  = (bool) ( $switch['active'] ?? false );
		$problem = $switch['problem'] ?? null;

		/*
		 * A path with nothing at it is the ordinary state of an armed switch,
		 * and reporting it would make the signal worthless. A file that exists
		 * and cannot be used is worth reporting: somebody wrote it expecting it
		 * to do something.
		 */
		if ( ! $active && ( ! is_string( $problem ) || '' === $problem ) ) {
			return null;
		}

		return array(
			'active'     => $active,
			'path'       => is_string( $switch['path'] ?? null ) ? $switch['path'] : null,
			'problem'    => is_string( $problem ) && '' !== $problem ? $problem : null,

			// Both, so a report can say what changed and what comes back when
			// the file goes, rather than leaving an operator to work it out.
			'configured' => $firewall->getConfiguredMode()->value,
			'effective'  => $this->effective_mode( $firewall, $switch['mode'] ?? null ),
		);
	}

	/**
	 * The mode a panic file put the firewall in, as somebody would name it.
	 *
	 * `lockdown` in the file is shorthand the library unpacks into lockdown
	 * delivered the way `block` delivers, so the firewall itself reports
	 * `block`. Repeating that back -- "a panic file is forcing block mode, the
	 * configured mode is block" -- would describe a site that is refusing
	 * every visitor as though nothing had changed.
	 *
	 * @param Firewall $firewall  The firewall that read the file.
	 * @param mixed    $requested What the file asked for.
	 */
	private function effective_mode( Firewall $firewall, $requested ): string {
		if ( $requested instanceof \BackedEnum && 'lockdown' === $requested->value ) {
			return 'lockdown';
		}

		return $firewall->getMode()->value;
	}

	/**
	 * Whether the firewall is refusing everyone but the lockdown allowlist.
	 *
	 * Asked of the library rather than read from settings, because there are
	 * three ways in and only one is the setting: `global.lockdown`, `mode:
	 * lockdown` in the Advanced YAML, and a panic file naming `lockdown`. A
	 * status page reading settings alone would miss the two most likely to be
	 * in force during an incident.
	 */
	public function is_locked_down(): bool {
		$firewall = $this->build_for_reporting();

		return null !== $firewall && $firewall->isLockedDown();
	}

	/**
	 * A firewall built to be asked questions, never to evaluate.
	 *
	 * Asked of a firewall built for the purpose rather than of the one that
	 * evaluated this request, because on an admin screen there was no such
	 * request: the early path answered it before WordPress existed, or this is
	 * WP-CLI. Building one costs a parse the library has already cached.
	 *
	 * Never throws. A configuration the library refuses outright is reported
	 * by the compiled-configuration check, so a failure here is null rather
	 * than a second report of the same thing.
	 */
	private function build_for_reporting(): ?Firewall {
		if ( ! Library_Loader::is_usable() ) {
			return null;
		}

		$compiled = Plugin::instance()->paths()->compiled_file();

		if ( ! is_readable( $compiled ) ) {
			return null;
		}

		$this->define_cache_constants();

		try {
			return Firewall::create( array( $compiled ), $this->overrides() );
		} catch ( \Throwable $e ) {
			return null;
		}
	}

	/**
	 * Why the last evaluation did not happen, or null.
	 */
	public static function failure(): ?string {
		return self::$failure;
	}

	/**
	 * Clear the recorded failure. Test seam.
	 *
	 * @internal
	 */
	public static function reset(): void {
		self::$failure = null;
		self::$marks   = array();
	}
}
