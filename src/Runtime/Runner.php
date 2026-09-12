<?php
/**
 * Builds the firewall and evaluates the request.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Runtime;

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
	 * Why evaluation did not happen, or null.
	 *
	 * @var string|null
	 */
	private static ?string $failure = null;

	/**
	 * Evaluate the current request.
	 *
	 * Never throws. Returns true when the request may continue -- which includes
	 * every failure case.
	 *
	 * @param Request|null $request Request to evaluate, or null for the current one.
	 */
	public function evaluate( ?Request $request = null ): bool {
		if ( defined( 'BASIC_FIREWALL_EVALUATED' ) ) {
			// The wp-config.php path already dealt with this request.
			return true;
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
			$firewall = Firewall::create( array( $compiled ), $this->overrides() );
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

		try {
			return $firewall->evaluate( $request );
		} catch ( \Throwable $e ) {
			// A blocking exception is the library's way of saying "rejected" in
			// exception mode. The responder decides what the visitor sees.
			return ( new Outcome_Responder() )->respond( $e );
		}
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
			define( 'KANOPI_FIREWALL_CACHE_DIR', Plugin::instance()->paths()->base() . '/cache' );
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
	}
}
