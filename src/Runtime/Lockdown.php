<?php
/**
 * The lockdown allowlist.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Runtime;

use Symfony\Component\HttpFoundation\IpUtils;

/**
 * Reads, checks and matches the addresses a lockdown keeps serving.
 *
 * Lockdown refuses every client not on one list, before any rule is consulted,
 * and records none of them. It is the most dangerous switch the plugin offers,
 * and the ways to get it wrong all end the same way -- the administrator
 * refused along with everybody else, from the page they would use to undo it.
 *
 * **Addresses, CIDR blocks and `start-end` ranges**, the same three forms an IP
 * rule takes. Ranges needed kanopi/firewall 2.33.1: before it the library handed
 * each entry to Symfony's `IpUtils`, which knows nothing of ranges, so a range
 * was kept and matched nobody -- on this list quite possibly the one entry
 * naming the person who typed it. That is why the plugin requires ^2.33.1, and
 * why the parsing below copies the library's rather than approximating it: an
 * entry this class accepts has to be one the firewall matches, and one it
 * refuses has to be one the firewall would ignore.
 */
final class Lockdown {

	/**
	 * Split a textarea into entries.
	 *
	 * @param string|array<mixed> $value One entry per line, or already a list.
	 *
	 * @return list<string>
	 */
	public static function lines( $value ): array {
		if ( is_array( $value ) ) {
			$lines = $value;
		} else {
			$split = preg_split( '/\R/', (string) $value );
			$lines = is_array( $split ) ? $split : array();
		}

		$out = array();

		foreach ( $lines as $line ) {
			$line = is_scalar( $line ) ? trim( (string) $line ) : '';

			if ( '' !== $line ) {
				$out[] = $line;
			}
		}

		return array_values( array_unique( $out ) );
	}

	/**
	 * Whether an entry is something the library will actually match.
	 *
	 * The same test the library applies before matching, so the answer here
	 * and the behaviour at the door cannot disagree: a single address, a CIDR
	 * block whose prefix fits the address family, or a `start-end` range. A
	 * `/33` on IPv4 is a typo rather than a range, and treating it as a cap
	 * would quietly turn a network into one host.
	 *
	 * @param string $entry Candidate entry.
	 */
	public static function is_valid_entry( string $entry ): bool {
		$entry = trim( $entry );

		if ( '' === $entry ) {
			return false;
		}

		if ( null !== self::range_bounds( $entry ) ) {
			return true;
		}

		if ( false === strpos( $entry, '/' ) ) {
			return false !== filter_var( $entry, FILTER_VALIDATE_IP );
		}

		list( $subnet, $prefix ) = array_pad( explode( '/', $entry, 2 ), 2, '' );

		if ( false === filter_var( $subnet, FILTER_VALIDATE_IP ) || ! ctype_digit( $prefix ) ) {
			return false;
		}

		$maximum = false !== filter_var( $subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ? 128 : 32;

		return (int) $prefix <= $maximum;
	}

	/**
	 * The packed bounds of a `start-end` range, or null when it is not one.
	 *
	 * The library's `AddressMatchTrait::rangeBounds()`, rule for rule: two
	 * addresses of one family joined by a single `-`, lowest first. Backwards
	 * bounds are refused rather than swapped, as the library refuses them --
	 * swapping here would accept an entry the firewall then ignores.
	 *
	 * @param string $entry Candidate entry.
	 *
	 * @return array{0: string, 1: string}|null
	 */
	private static function range_bounds( string $entry ): ?array {
		if ( 1 !== substr_count( $entry, '-' ) ) {
			return null;
		}

		list( $start, $end ) = array_map( 'trim', explode( '-', $entry, 2 ) );

		if ( false === filter_var( $start, FILTER_VALIDATE_IP ) || false === filter_var( $end, FILTER_VALIDATE_IP ) ) {
			return null;
		}

		$start = (string) inet_pton( $start );
		$end   = (string) inet_pton( $end );

		if ( strlen( $start ) !== strlen( $end ) || strcmp( $start, $end ) > 0 ) {
			return null;
		}

		return array( $start, $end );
	}

	/**
	 * Separate the entries the library can match from the ones it cannot.
	 *
	 * @param string|array<mixed> $value One entry per line, or already a list.
	 *
	 * @return array{valid: list<string>, invalid: list<string>}
	 */
	public static function sort( $value ): array {
		$sorted = array(
			'valid'   => array(),
			'invalid' => array(),
		);

		foreach ( self::lines( $value ) as $entry ) {
			$sorted[ self::is_valid_entry( $entry ) ? 'valid' : 'invalid' ][] = $entry;
		}

		return $sorted;
	}

	/**
	 * Whether an address is on the list.
	 *
	 * Matched the way the library matches it -- the same Symfony utility for
	 * addresses and CIDR blocks, the same packed-byte comparison for ranges --
	 * so a warning that says "you are not on this list" is describing what the
	 * firewall will do rather than an approximation of it.
	 *
	 * @param string       $address Client address.
	 * @param list<string> $allow   Allowlist entries.
	 */
	public static function covers( string $address, array $allow ): bool {
		if ( false === filter_var( $address, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		$packed = (string) inet_pton( $address );

		foreach ( $allow as $entry ) {
			$bounds = self::range_bounds( trim( $entry ) );

			if ( null !== $bounds ) {
				// A different family is outside the range, not an error: an
				// IPv6 visitor is simply not in an IPv4 office's range.
				if ( strlen( $packed ) === strlen( $bounds[0] ) && strcmp( $packed, $bounds[0] ) >= 0 && strcmp( $packed, $bounds[1] ) <= 0 ) {
					return true;
				}

				continue;
			}

			if ( self::is_valid_entry( $entry ) && IpUtils::checkIp( $address, $entry ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * What is wrong with arming lockdown against this list, if anything.
	 *
	 * The two ways to get it wrong are not equally wrong, so they get different
	 * answers.
	 *
	 * An **empty list serves nobody**, and neither does an unmatchable entry.
	 * That is an error: saving it would take the site off the internet, this
	 * page included, and it is never what somebody arming lockdown from a form
	 * means.
	 *
	 * A list that does not include *your* address might be deliberate --
	 * somebody configuring from a laptop and allowlisting the office range is
	 * doing it on purpose. So that is a warning, which says what is about to
	 * happen and lets them proceed.
	 *
	 * @param bool                                              $armed  Whether lockdown is being switched on.
	 * @param array{valid: list<string>, invalid: list<string>} $sorted The list, as sort() returned it.
	 * @param string                                            $client The address the firewall sees for the person saving.
	 *
	 * @return array{error: string|null, warning: string|null}
	 */
	public static function review( bool $armed, array $sorted, string $client ): array {
		$review = array(
			'error'   => null,
			'warning' => null,
		);

		/*
		 * Refused whether or not lockdown is armed. The list is kept while it
		 * is off precisely so it is ready mid-incident, and discovering then
		 * that one of its entries never matched is the worst time to find out.
		 */
		if ( array() !== $sorted['invalid'] ) {
			$review['error'] = sprintf(
				/* translators: %s: comma-separated rejected entries. */
				__( 'The lockdown allowlist takes single addresses, CIDR blocks and start-end ranges (lowest address first, one address family), and these are none of those: %s. The firewall would keep them and never match them, and on this list that could be the entry naming you.', 'basic-firewall' ),
				implode( ', ', $sorted['invalid'] )
			);

			return $review;
		}

		if ( ! $armed ) {
			return $review;
		}

		if ( array() === $sorted['valid'] ) {
			$review['error'] = __( 'Lockdown with an empty allowlist refuses everybody, including you and this page. Name at least one address, or untick lockdown.', 'basic-firewall' );

			return $review;
		}

		if ( '' !== $client && ! self::covers( $client, $sorted['valid'] ) ) {
			$review['warning'] = sprintf(
				/* translators: %s: the client address. */
				__( 'Your address, %s, is not on the lockdown allowlist, so this refuses you along with everybody else. That may be deliberate — a list naming only the office range, configured from somewhere else — but it is worth being sure before you leave this page. define( \'BASIC_FIREWALL_ENABLED\', false ) in wp-config.php is the way back in.', 'basic-firewall' ),
				$client
			);
		}

		return $review;
	}

	/**
	 * The address the firewall sees for the current request.
	 *
	 * Not REMOTE_ADDR. Behind a proxy that is the proxy, and telling somebody
	 * "your address is 172.20.0.5" while the firewall matches the address in
	 * X-Forwarded-For would have them allowlist the wrong thing. So the trusted
	 * proxies are applied first, exactly as they are before a request is
	 * evaluated, and the request is built the way the firewall builds it.
	 */
	public static function client_address(): string {
		Trusted_Proxies::apply();

		return (string) Request_Factory::from_globals()->getClientIp();
	}
}
