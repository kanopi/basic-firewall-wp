<?php
/**
 * Who makes the DNS lookups behind crawler verification.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Support;

use Kanopi\Firewall\Utility\ReverseDns\BuiltinProviders;
use Kanopi\Firewall\Utility\ReverseDns\DnsOverHttpResolver;
use Kanopi\Firewall\Utility\ReverseDns\ReverseDnsSettings;
use Kanopi\Firewall\Utility\ReverseDns\SystemResolver;

/**
 * Turns the stored lookup settings into `global.reverse_dns` and a rule's
 * `verify_provider` / `verify_timeout_ms` (kanopi/firewall 2.38.0, #473).
 *
 * PHP's own lookups take no timeout, so on a host without a local caching
 * resolver one slow nameserver holds a worker for up to ten seconds. A
 * provider -- Cloudflare's or Google's DNS over HTTPS -- limits each lookup to
 * `timeout_ms`, connecting included. **Naming one is the opt-in**: from then
 * on the reverse-DNS names of visitors' addresses, which are their IP
 * addresses written backwards, go to that provider. So nothing is selected by
 * default, and an empty setting compiles to nothing at all.
 *
 * The library refuses to start on a `reverse_dns` it cannot use -- an unknown
 * provider, `provider` and `resolver` both set, a provider on a PHP without
 * curl -- and this plugin fails open when it refuses. Two things stand between
 * the two, as for the pages (see Page_Settings):
 *
 * - the settings validator asks the library about the provider as it is
 *   saved, so the screen reports the problem in the library's words;
 * - the compiler asks again of the finished file, advanced YAML included, and
 *   leaves out what the library would refuse. Verification then falls back to
 *   PHP's own lookups -- slower, but it still verifies, where a firewall that
 *   did not start would verify nothing and block nothing.
 */
final class Reverse_Dns {

	/**
	 * The time limit the library uses when none is given, in milliseconds.
	 */
	public const DEFAULT_TIMEOUT_MS = 300;

	/**
	 * Rule metadata keys that choose a rule's resolver.
	 */
	private const RULE_KEYS = array( 'verify_provider', 'verify_timeout_ms', 'verify_resolver', 'verify_resolver_options' );

	/**
	 * The longest time limit the library accepts, in milliseconds.
	 */
	public static function max_timeout_ms(): int {
		return DnsOverHttpResolver::MAX_TIMEOUT_MS;
	}

	/**
	 * The built-in providers' names.
	 *
	 * @return list<string>
	 */
	public static function providers(): array {
		return BuiltinProviders::names();
	}

	/**
	 * Labels for the providers a select offers, keyed by stored value.
	 *
	 * @param string $none The label for the empty value.
	 *
	 * @return array<string, string>
	 */
	public static function choices( string $none ): array {
		$labels = array(
			'cloudflare' => __( 'Cloudflare (1.1.1.1) — DNS over HTTPS', 'basic-firewall' ),
			'google'     => __( 'Google Public DNS (8.8.8.8) — DNS over HTTPS', 'basic-firewall' ),
		);

		$choices = array( '' => $none );

		foreach ( self::providers() as $name ) {
			$choices[ $name ] = $labels[ $name ] ?? $name;
		}

		return $choices;
	}

	/**
	 * What the library says is wrong with choosing a provider, if anything.
	 *
	 * Mostly that it does not exist, or that this PHP has no curl extension,
	 * which DNS over HTTPS needs.
	 *
	 * @param string $value A provider name.
	 */
	public static function provider_problem( string $value ): ?string {
		$problems = ReverseDnsSettings::problems( array( 'reverse_dns' => array( 'provider' => $value ) ) );

		return $problems[0] ?? null;
	}

	/**
	 * The compiled `global.reverse_dns`, empty when nothing is set.
	 *
	 * `timeout_ms` is written only when it differs from the library's own
	 * default, so a site that sets nothing compiles exactly what it did before
	 * 2.38.0. It is written even without a global provider, because a rule can
	 * name one of its own and takes the global limit with it.
	 *
	 * @param array<string, mixed> $section Stored `global.reverse_dns`.
	 *
	 * @return array<string, mixed>
	 */
	public static function compile( array $section ): array {
		$compiled = array();
		$provider = trim( (string) ( $section['provider'] ?? '' ) );

		if ( '' !== $provider ) {
			$compiled['provider'] = $provider;
		}

		$timeout = (int) ( $section['timeout_ms'] ?? self::DEFAULT_TIMEOUT_MS );

		if ( $timeout > 0 && self::DEFAULT_TIMEOUT_MS !== $timeout ) {
			$compiled['timeout_ms'] = $timeout;
		}

		return $compiled;
	}

	/**
	 * Leave out of a compiled configuration whatever the library would refuse to start on.
	 *
	 * After the advanced YAML, so a `reverse_dns` or `verify_provider` typed
	 * there is checked too. On any problem the whole of `global.reverse_dns`
	 * and every rule's choice of resolver are dropped, not just the value
	 * named: the library reports one problem per value, and a half-applied
	 * choice -- a rule's provider kept while the global definition it names is
	 * dropped -- would be refused all over again.
	 *
	 * @param array<string, mixed> $compiled The compiled configuration.
	 * @param list<string>         $problems Problems found, appended to.
	 *
	 * @return array<string, mixed>
	 */
	public static function repair( array $compiled, array &$problems ): array {
		$global  = is_array( $compiled['global'] ?? null ) ? $compiled['global'] : array();
		$plugins = is_array( $compiled['plugins'] ?? null ) ? array_values( $compiled['plugins'] ) : array();

		$found = ReverseDnsSettings::problems( $global, $plugins );

		if ( array() === $found ) {
			return $compiled;
		}

		foreach ( $found as $problem ) {
			$problems[] = sprintf(
				/* translators: %s: the firewall library's description of the problem. */
				__( 'Crawler verification lookups: %s. The firewall would refuse to start with this, so the lookup settings were left out and verification uses PHP\'s own lookups instead.', 'basic-firewall' ),
				$problem
			);
		}

		unset( $global['reverse_dns'] );

		if ( isset( $compiled['global'] ) ) {
			$compiled['global'] = $global;
		}

		foreach ( (array) ( $compiled['plugins'] ?? array() ) as $index => $plugin ) {
			if ( ! is_array( $plugin ) || ! is_array( $plugin['metadata'] ?? null ) ) {
				continue;
			}

			foreach ( self::RULE_KEYS as $key ) {
				unset( $compiled['plugins'][ $index ]['metadata'][ $key ] );
			}
		}

		return $compiled;
	}

	/**
	 * Where one rule's lookups go, in words, for Site Health.
	 *
	 * @param array<string, mixed> $section   The compiled `global:` section.
	 * @param array<string, mixed> $metadata The rule's compiled metadata.
	 */
	public static function destination( array $section, array $metadata ): string {
		try {
			$where = ReverseDnsSettings::fromGlobal( $section )->describeFor( $metadata );
		} catch ( \Throwable $e ) {
			return __( 'nowhere: its provider is not defined', 'basic-firewall' );
		}

		if ( SystemResolver::class === ltrim( $where['resolver'], '\\' ) && null === $where['provider'] ) {
			return __( 'PHP\'s own lookups, through this host\'s resolver', 'basic-firewall' );
		}

		$host = implode(
			', ',
			array_filter( array( (string) ( $where['endpoint'] ?? '' ), (string) ( $where['address'] ?? '' ) ) )
		);

		$name = null !== $where['provider'] ? $where['provider'] : $where['resolver'];

		return '' === $host ? $name : sprintf( '%1$s (%2$s)', $name, $host );
	}

	/**
	 * Whether a rule's lookups go to a third party rather than this host's resolver.
	 *
	 * @param array<string, mixed> $section   The compiled `global:` section.
	 * @param array<string, mixed> $metadata The rule's compiled metadata.
	 */
	public static function uses_provider( array $section, array $metadata ): bool {
		try {
			$where = ReverseDnsSettings::fromGlobal( $section )->describeFor( $metadata );
		} catch ( \Throwable $e ) {
			return false;
		}

		return null !== $where['provider'];
	}
}
