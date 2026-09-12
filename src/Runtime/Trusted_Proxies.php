<?php
/**
 * Establishes which proxies may declare the client address.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Runtime;

use Symfony\Component\HttpFoundation\Request;

/**
 * Tells Symfony which addresses are allowed to say who the client is.
 *
 * **Every rule that looks at an address depends on this.** Symfony only honours
 * `X-Forwarded-For` once trusted proxies have been set, and until they are, two
 * things are true at once and both are bad:
 *
 * - Every visitor appears to come from the proxy, so they share one address.
 *   One visitor's offense blocks everybody, and a per-IP rate limit counts the
 *   whole site as a single client.
 * - If trusted proxies are later set too widely, anything on that network can
 *   forge the header and walk straight through IP allow-lists, block-lists and
 *   rate limits.
 *
 * Drupal has `$settings['reverse_proxy_addresses']` and the firewall module
 * simply reuses it. **WordPress has no equivalent**, so this plugin defines one
 * rather than guessing -- guessing here means either trusting nothing (address
 * rules silently do not work) or trusting everything (address rules are
 * forgeable), and there is no safe default between them.
 *
 * In `wp-config.php`:
 *
 *     define( 'BASIC_FIREWALL_TRUSTED_PROXIES', array( '10.0.0.0/8' ) );
 *
 * Narrow that to the proxies that actually front the site. Every address in it
 * is permitted to declare who the client is, so a range wider than the proxy
 * fleet hands that power to whatever else shares the network.
 *
 * Local development is the case people miss. DDEV, Lando and Docksal all route
 * through a router container, so PHP sees the router's address and the real
 * client only in `X-Forwarded-For` -- the same shape as production, and none of
 * them configure this. Measured on this plugin's own DDEV site: a single blocked
 * request recorded `172.20.0.5`, the router, and every subsequent request from
 * any client was refused.
 */
final class Trusted_Proxies {

	/**
	 * wp-config.php constant naming the trusted proxy addresses.
	 */
	public const PROXIES_CONSTANT = 'BASIC_FIREWALL_TRUSTED_PROXIES';

	/**
	 * Apply the configured trusted proxies to Symfony.
	 *
	 * Returns true when something was established.
	 */
	public static function apply(): bool {
		$proxies = self::configured();

		if ( array() === $proxies ) {
			return false;
		}

		/*
		 * Deliberately not HEADER_X_FORWARDED_HOST. The host is what decides
		 * which site a request belongs to and which URLs get generated, and
		 * trusting a forwarded host from anything less than a fully locked-down
		 * proxy is how cache-poisoning and password-reset-link attacks start.
		 * The three headers below are what address, scheme and port detection
		 * actually need.
		 */
		$headers = Request::HEADER_X_FORWARDED_FOR
			| Request::HEADER_X_FORWARDED_PROTO
			| Request::HEADER_X_FORWARDED_PORT;

		if ( defined( 'BASIC_FIREWALL_TRUSTED_HEADERS' ) ) {
			$override = constant( 'BASIC_FIREWALL_TRUSTED_HEADERS' );

			if ( is_int( $override ) ) {
				$headers = $override;
			}
		}

		Request::setTrustedProxies( $proxies, $headers );

		return true;
	}

	/**
	 * The configured trusted proxies.
	 *
	 * @return list<string>
	 */
	public static function configured(): array {
		$configured = array();

		if ( defined( self::PROXIES_CONSTANT ) ) {
			$value = constant( self::PROXIES_CONSTANT );

			if ( is_string( $value ) ) {
				$value = explode( ',', $value );
			}

			if ( is_array( $value ) ) {
				$configured = $value;
			}
		}

		/**
		 * Filters the addresses permitted to declare the client address.
		 *
		 * Not available on the wp-config.php evaluation path, which runs before
		 * any filter exists -- use the constant there, and note that the
		 * constant works on both paths while this filter works on one.
		 *
		 * @param list<string> $configured Addresses or CIDR blocks.
		 */
		if ( function_exists( 'apply_filters' ) ) {
			$configured = apply_filters( 'basic_firewall_trusted_proxies', $configured );
		}

		$clean = array();

		foreach ( (array) $configured as $entry ) {
			$entry = trim( (string) $entry );

			if ( '' === $entry ) {
				continue;
			}

			/*
			 * `REMOTE_ADDR` is Symfony's own spelling for "trust whatever is
			 * directly connected", which is correct behind exactly one proxy and
			 * is passed through rather than validated as an address.
			 */
			if ( 'REMOTE_ADDR' === $entry || self::looks_like_address( $entry ) ) {
				$clean[] = $entry;
			}
		}

		return $clean;
	}

	/**
	 * Whether an entry is an address or a CIDR block.
	 *
	 * @param string $entry Candidate entry.
	 */
	private static function looks_like_address( string $entry ): bool {
		if ( false !== strpos( $entry, '/' ) ) {
			list( $address, $bits ) = array_pad( explode( '/', $entry, 2 ), 2, '' );

			return false !== filter_var( $address, FILTER_VALIDATE_IP ) && ctype_digit( $bits );
		}

		return false !== filter_var( $entry, FILTER_VALIDATE_IP );
	}

	/**
	 * Whether trusted proxies have been established.
	 */
	public static function are_configured(): bool {
		return array() !== self::configured();
	}

	/**
	 * Whether this request arrived carrying a forwarding header.
	 *
	 * Used by Site Health to catch the contradiction the module describes:
	 * somebody answered "no proxy", which silences the warning, and a forwarding
	 * header turned up anyway. Either something is proxying the site after all,
	 * or a client sent the header speculatively.
	 */
	public static function request_carries_forwarding_header(): bool {
		foreach ( array( 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_FORWARDED', 'HTTP_CF_CONNECTING_IP' ) as $key ) {
			if ( ! empty( $_SERVER[ $key ] ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * A suggested configuration for a recognised local development stack.
	 *
	 * Returns null when the environment is not recognised. The suggestion is
	 * shown in Site Health rather than applied: a plugin that silently decided
	 * to trust a /12 would be doing exactly the thing this class warns against.
	 *
	 * @return array{stack: string, range: string}|null
	 */
	public static function detect_local_stack(): ?array {
		if ( 'true' === getenv( 'IS_DDEV_PROJECT' ) ) {
			return array(
				'stack' => 'DDEV',
				// The Docker range rather than the router's address: container
				// addresses are reassigned when containers are recreated, so
				// pinning the one you see today works until the next restart.
				'range' => '172.16.0.0/12',
			);
		}

		if ( false !== getenv( 'LANDO_INFO' ) ) {
			return array(
				'stack' => 'Lando',
				'range' => '172.16.0.0/12',
			);
		}

		if ( false !== getenv( 'DOCKSAL_STACK' ) ) {
			return array(
				'stack' => 'Docksal',
				'range' => '192.168.64.0/18',
			);
		}

		return null;
	}
}
