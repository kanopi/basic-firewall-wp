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
			'asn'     => __( 'Autonomous system number, such as 16509', 'basic-firewall' ),
			'asn_org' => __( 'Autonomous system organisation, such as AMAZON-02 — registered names vary, so "contains" is usually the comparison to use', 'basic-firewall' ),
		);
	}

	/**
	 * Old variable name to the library's.
	 *
	 * @var array<string, string>
	 */
	public const RENAMED_VARIABLES = array(
		'organization' => 'asn_org',
	);

	/**
	 * {@inheritDoc}
	 *
	 * The library's ASN plugin knows `asn` and `asn_org` and nothing else.
	 */
	protected function renamed_variables(): array {
		return self::RENAMED_VARIABLES;
	}

	/**
	 * {@inheritDoc}
	 *
	 * `network` was offered and has no library equivalent: the plugin resolves
	 * only the number and the organisation.
	 */
	protected function retired_variables(): array {
		return array(
			'network' => __( 'Remove it; to match a network block, use an IP address rule with the range in CIDR form.', 'basic-firewall' ),
		);
	}

	/**
	 * {@inheritDoc}
	 *
	 * An autonomous system number reaches the library as the integer the
	 * MaxMind record holds, and `equals` and `is one of` compare strictly -- so
	 * `16509` as typed, which every form field produces as a string, never
	 * equalled the `16509` in the record. The most obvious ASN rule there is
	 * compiled, loaded, and matched nothing. A number is compiled as a number,
	 * and the `AS` prefix people copy from looking-glass sites is taken off.
	 *
	 * @param array<string, mixed> $condition Stored condition.
	 *
	 * @return array<string, mixed>
	 */
	protected function compile_condition( array $condition ): array {
		$compiled = parent::compile_condition( $condition );

		if ( 'asn' !== $compiled['variable'] || ! in_array( $compiled['operator'], array( 'equals', 'not_equals', 'in' ), true ) ) {
			return $compiled;
		}

		$compiled['value'] = is_array( $compiled['value'] )
			? array_map( array( self::class, 'as_number' ), $compiled['value'] )
			: self::as_number( $compiled['value'] );

		return $compiled;
	}

	/**
	 * An autonomous system number as the integer the record holds.
	 *
	 * Anything that is not one is left as it was, so a placeholder such as a
	 * referenced list's `{value}` still reaches the library to be substituted.
	 *
	 * @param mixed $value Compiled value.
	 *
	 * @return mixed
	 */
	private static function as_number( $value ) {
		if ( is_string( $value ) && 1 === preg_match( '/^\s*(?:AS)?(\d+)\s*$/i', $value, $matches ) ) {
			return (int) $matches[1];
		}

		return $value;
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
	public function settings_help(): array {
		return $this->reader_help();
	}

	/**
	 * {@inheritDoc}
	 *
	 * The library's ASN plugin reads a MaxMind database and nothing else.
	 */
	protected function reader_reads_edge(): bool {
		return false;
	}

	/**
	 * {@inheritDoc}
	 */
	public function secret_settings(): array {
		return array( 'reader.license_key' );
	}
}
