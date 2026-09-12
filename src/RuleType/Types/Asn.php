<?php
/**
 * The ASN rule type.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\RuleType\Types;

use Kanopi\BasicFirewall\RuleType\Condition_Rule_Type_Base;
use Kanopi\BasicFirewall\RuleType\Geo_Reader_Settings;
use Kanopi\Firewall\Plugins\Asn as LibraryAsn;

/**
 * Matches on the autonomous system the client address belongs to.
 *
 * Effective against hosting and VPN traffic, which is most of what a scanner
 * arrives from: an ASN rule turns away an entire provider without maintaining a
 * list of its addresses.
 */
final class Asn extends Condition_Rule_Type_Base {

	use Geo_Reader_Settings;

	/**
	 * {@inheritDoc}
	 */
	public function id(): string {
		return 'asn';
	}

	/**
	 * {@inheritDoc}
	 */
	public function label(): string {
		return __( 'ASN', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function description(): string {
		return __( 'Matches the autonomous system number or organisation the client address belongs to. Needs a MaxMind ASN database. Effective against hosting and VPN traffic.', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function library_class(): string {
		return LibraryAsn::class;
	}

	/**
	 * {@inheritDoc}
	 */
	public function weight(): int {
		return -40;
	}

	/**
	 * {@inheritDoc}
	 */
	protected function variable_options(): array {
		return array(
			'asn'          => __( 'Autonomous system number, such as 16509', 'basic-firewall' ),
			'organization' => __( 'Autonomous system organisation, such as AMAZON-02', 'basic-firewall' ),
			'network'      => __( 'The network block the address falls in', 'basic-firewall' ),
		);
	}

	/**
	 * {@inheritDoc}
	 */
	public function default_settings(): array {
		return parent::default_settings() + $this->reader_defaults();
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param array<string, mixed>  $settings Described by the interface.
	 * @param array<string, string> $errors Described by the interface.
	 */
	public function validate_settings( array $settings, array &$errors ): array {
		return parent::validate_settings( $settings, $errors ) + $this->validate_reader( $settings, $errors );
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param array<string, mixed> $rule Described by the interface.
	 */
	public function compile( array $rule ): array {
		$entry = parent::compile( $rule );

		return $this->apply_reader( $entry, $rule['settings'] ?? array() );
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param array<string, mixed> $settings Described by the interface.
	 */
	public function check_requirements( array $settings ): array {
		return array_merge( parent::check_requirements( $settings ), $this->reader_requirements( $settings ) );
	}

	/**
	 * {@inheritDoc}
	 */
	public function secret_settings(): array {
		return array( 'reader.license_key' );
	}
}
