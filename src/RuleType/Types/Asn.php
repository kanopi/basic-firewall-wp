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

	/*
	 * No compile-time handling of autonomous system numbers, on purpose.
	 *
	 * Until kanopi/firewall 2.35.0 the library compared `asn` strictly, the
	 * record's integer against the rule's string, so every equality rule
	 * matched nothing and `not_equals` matched everybody. This type cast typed
	 * values to integers, took off the `AS` prefix, and compiled a list of
	 * numbers into a digits-only `#^16509$#` pattern because list entries are
	 * substituted after compilation, out of its reach (#49).
	 *
	 * The library now reads both sides of `equals`, `not_equals` and `in` as a
	 * number, a leading `AS` allowed, for typed values and list entries alike.
	 * So a condition compiles as typed, a list entry is compared as the number
	 * it is, and an entry written `AS16509` matches instead of being skipped.
	 * Stored rules need no migration: the same settings compile to a plainer
	 * condition that the library reads the same way.
	 */

	/**
	 * {@inheritDoc}
	 */
	public function source_note(): string {
		return __( 'For an autonomous system number with "is equal to", "is not equal to" or "is one of", each entry is compared as a whole number, written as digits or with the AS prefix (16509 or AS16509). Use "contains" on the organisation for names.', 'basic-firewall' );
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
	protected function reader_lookup(): string {
		return 'asn';
	}
}
