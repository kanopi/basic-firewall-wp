<?php
/**
 * The IP address rule type.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\RuleType\Types;

use Kanopi\BasicFirewall\RuleType\Rule_Type_Base;
use Kanopi\Firewall\Plugins\IpAddress;

/**
 * Matches the client IP against addresses, CIDR blocks and ranges.
 *
 * The cheapest rule type there is, and the one to reach for when an address
 * must be allowed or refused regardless of what anything else thinks -- it
 * consults no database, no third party and no header beyond the client address
 * itself.
 */
final class Ip_Address extends Rule_Type_Base {

	/**
	 * {@inheritDoc}
	 */
	public function id(): string {
		return 'ip_address';
	}

	/**
	 * {@inheritDoc}
	 */
	public function label(): string {
		return __( 'IP address', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function description(): string {
		return __( 'Matches the client IP against single addresses, CIDR blocks or start-end ranges. IPv4 and IPv6.', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function library_class(): string {
		return IpAddress::class;
	}

	/**
	 * {@inheritDoc}
	 */
	public function weight(): int {
		return -100;
	}

	/**
	 * {@inheritDoc}
	 */
	public function supports_sources(): bool {
		return true;
	}

	/**
	 * {@inheritDoc}
	 */
	public function default_settings(): array {
		return array( 'addresses' => array() );
	}

	/**
	 * {@inheritDoc}
	 */
	public function validate_settings( array $settings, array &$errors ): array {
		$addresses = self::lines_to_list( $settings['addresses'] ?? array() );
		$clean     = array();

		foreach ( $addresses as $address ) {
			if ( ! self::is_valid_address( $address ) ) {
				$errors['addresses'] = sprintf(
					/* translators: %s: the rejected entry. */
					__( '%s is not an address, a CIDR block or a start-end range. An entry the firewall cannot parse is ignored, so the rule would silently cover less than it appears to.', 'basic-firewall' ),
					$address
				);

				continue;
			}

			$clean[] = $address;
		}

		return array( 'addresses' => $clean );
	}

	/**
	 * Whether an entry is an address, a CIDR block, or a start-end range.
	 *
	 * @param string $entry Candidate entry.
	 */
	public static function is_valid_address( string $entry ): bool {
		$entry = trim( $entry );

		if ( '' === $entry ) {
			return false;
		}

		// start-end range. Checked before CIDR because an IPv6 range contains colons.
		if ( false !== strpos( $entry, '-' ) ) {
			$parts = explode( '-', $entry, 2 );

			return false !== filter_var( trim( $parts[0] ), FILTER_VALIDATE_IP )
				&& false !== filter_var( trim( $parts[1] ), FILTER_VALIDATE_IP );
		}

		// CIDR block.
		if ( false !== strpos( $entry, '/' ) ) {
			list( $address, $bits ) = array_pad( explode( '/', $entry, 2 ), 2, '' );

			if ( false === filter_var( $address, FILTER_VALIDATE_IP ) || ! ctype_digit( $bits ) ) {
				return false;
			}

			$max = false !== filter_var( $address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ? 128 : 32;

			return (int) $bits >= 0 && (int) $bits <= $max;
		}

		return false !== filter_var( $entry, FILTER_VALIDATE_IP );
	}

	/**
	 * {@inheritDoc}
	 */
	public function compile( array $rule ): array {
		$entry = $this->base_entry( $rule );

		// array_values() because the library reads this as a list, and a gap in
		// the keys after validation dropped an entry would make it an object in
		// YAML rather than a sequence.
		$entry['config'] = array_values( $rule['settings']['addresses'] ?? array() );

		return $entry;
	}

	/**
	 * {@inheritDoc}
	 */
	public function summarize( array $settings ): array {
		$addresses = $settings['addresses'] ?? array();

		if ( array() === $addresses ) {
			return array( __( 'No addresses configured, so this rule matches nothing.', 'basic-firewall' ) );
		}

		$preview = array_slice( $addresses, 0, 5 );
		$summary = implode( ', ', $preview );

		if ( count( $addresses ) > count( $preview ) ) {
			$summary .= sprintf(
				/* translators: %d: number of further addresses. */
				__( ' and %d more', 'basic-firewall' ),
				count( $addresses ) - count( $preview )
			);
		}

		return array( $summary );
	}
}
