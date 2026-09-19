<?php
/**
 * The IP address rule type.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\RuleType\Types;

use Kanopi\BasicFirewall\RuleType\Has_Sources;
use Kanopi\BasicFirewall\RuleType\Rule_Type_Base;
use Kanopi\BasicFirewall\Support\Paths;
use Symfony\Component\Yaml\Yaml;
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

	use Has_Sources;

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
		return array(
			'addresses' => array(),
			'sources'   => array(),
		);
	}

	/**
	 * {@inheritDoc}
	 */
	public function settings_help(): array {
		return array(
			'addresses' => array(
				'label'       => __( 'Addresses', 'basic-firewall' ),
				'description' => __( 'One per line. A single address, a CIDR block such as <code>203.0.113.0/24</code>, or a start-end range. IPv4 and IPv6. Leave this empty when the rule takes its addresses from a referenced list below.', 'basic-firewall' ),
			),
		);
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param array<string, mixed>  $settings Described by the interface.
	 * @param array<string, string> $errors Described by the interface.
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

		return array(
			'addresses' => $clean,
			'sources'   => $this->validate_sources( (array) ( $settings['sources'] ?? array() ), $errors ),
		);
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
	 *
	 * `cidr`, because the library's validator of that name accepts an address,
	 * a CIDR block or a start-end range -- exactly what the IpAddress plugin
	 * accepts. A feed that starts emitting hostnames is then rejected at
	 * refresh rather than contributing entries that match nothing.
	 */
	public static function source_validator_default(): string {
		return 'cidr';
	}

	/**
	 * No template: an entry from an address list is already an address.
	 *
	 * The IpAddress plugin is the one that takes bare values, which is why
	 * every other type has to shape its entries into rules and this one does
	 * not.
	 *
	 * @param array<string, mixed> $source The referenced list.
	 *
	 * @return string|null
	 */
	protected function source_template( array $source ) {
		$template = trim( (string) ( $source['template'] ?? '' ) );

		return '' !== $template ? $template : null;
	}

	/**
	 * {@inheritDoc}
	 *
	 * A referenced list can be behind a credential -- a paid threat feed, an
	 * internal allowlist service. Those live in the advanced block as
	 * `upstream.auth`, and are named here so the exporter strips them and says
	 * it did, exactly as it does for a Turnstile secret or a database password.
	 */
	public function secret_settings(): array {
		return array(
			'sources.*.advanced.upstream.auth.token',
			'sources.*.advanced.upstream.auth.password',
			'sources.*.advanced.upstream.auth.value',
			'sources.*.advanced.upstream.headers.*',
		);
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param array<string, mixed> $rule Described by the interface.
	 */
	public function compile( array $rule ): array {
		$entry = $this->base_entry( $rule );

		// array_values() because the library reads this as a list, and a gap in
		// the keys after validation dropped an entry would make it an object in
		// YAML rather than a sequence.
		$entry['config'] = array_values( $rule['settings']['addresses'] ?? array() );

		$sources = $this->compile_sources( $rule );

		if ( array() !== $sources ) {
			$entry['metadata']['sources'] = $sources;
		}

		return $entry;
	}


	/**
	 * {@inheritDoc}
	 *
	 * @param array<string, mixed> $settings Described by the interface.
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
