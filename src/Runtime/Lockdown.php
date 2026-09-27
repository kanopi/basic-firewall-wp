<?php
/**
 * The lockdown allowlist.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Runtime;

use Symfony\Component\HttpFoundation\IpUtils;
use Symfony\Component\HttpFoundation\Request;

/**
 * Reads, checks and matches the addresses a lockdown keeps serving.
 *
 * Lockdown refuses every client not on one list, before any rule is consulted,
 * and records none of them. It is the most dangerous switch the plugin offers,
 * and the ways to get it wrong all end the same way -- the administrator
 * refused along with everybody else, from the page they would use to undo it.
 *
 * **Addresses and CIDR blocks only, not `start-end` ranges.** An IP rule
 * accepts ranges, so it is natural to expect this list to. The library does not
 * match them here: it hands each entry to Symfony's `IpUtils`, which knows
 * nothing of ranges, so a range would be saved, compiled, shown back as though
 * it applied, and never match anybody. On this list, an entry that silently
 * matches nobody is quite possibly the one entry naming the person who typed
 * it, so ranges are refused where they are entered rather than discovered by
 * being locked out.
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
	 * and the behaviour at the door cannot disagree: a single address, or a
	 * CIDR block whose prefix fits the address family. A `/33` on IPv4 is a
	 * typo rather than a range, and treating it as a cap would quietly turn a
	 * network into one host.
	 *
	 * @param string $entry Candidate entry.
	 */
	public static function is_valid_entry( string $entry ): bool {
		$entry = trim( $entry );

		if ( '' === $entry ) {
			return false;
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
	 * Matched the way the library matches it, through the same Symfony
	 * utility, so a warning that says "you are not on this list" is describing
	 * what the firewall will do rather than an approximation of it.
	 *
	 * @param string       $address Client address.
	 * @param list<string> $allow   Allowlist entries.
	 */
	public static function covers( string $address, array $allow ): bool {
		if ( false === filter_var( $address, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		foreach ( $allow as $entry ) {
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
				__( 'The lockdown allowlist takes single addresses and CIDR blocks, and these are neither: %s. A start-end range is accepted by an IP rule but not here — the firewall would keep it and never match it, and on this list that could be the entry naming you.', 'basic-firewall' ),
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
	 * evaluated.
	 */
	public static function client_address(): string {
		Trusted_Proxies::apply();

		return (string) Request::createFromGlobals()->getClientIp();
	}
}
