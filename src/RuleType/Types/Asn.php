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
	 * Whether a list's entries are matched as whole autonomous system numbers.
	 *
	 * @param array<string, mixed> $source The referenced list.
	 */
	private function source_matches_whole_numbers( array $source ): bool {
		return '' === trim( (string) ( $source['template'] ?? '' ) )
			&& 'asn' === $this->library_variable( trim( (string) ( $source['variable'] ?? '' ) ) )
			&& in_array( (string) ( $source['operator'] ?? '' ), array( 'equals', 'not_equals', 'in' ), true );
	}

	/**
	 * {@inheritDoc}
	 *
	 * A list of numbers compared with "is equal to" or "is one of" matched
	 * nothing. A text list's entries are strings, the record holds an integer,
	 * and the library compares strictly -- and it substitutes the entry into
	 * the template after this plugin has compiled it, so the integer cast
	 * above never reaches it.
	 *
	 * So such a list is compiled as a pattern instead: each entry becomes
	 * `#^16509$#`, which the library runs against the number as text, whole,
	 * and which matches the same numbers "is equal to" says it does. A JSON
	 * list of integers works the same way. "Is not equal to" is the same
	 * pattern, inverted.
	 *
	 * The entry lands inside a regular expression, which is why
	 * source_record_guard() admits only entries that are digits and nothing
	 * else: a published list is somebody else's file, and an entry of `.*`
	 * must not become a pattern that matches every network there is.
	 *
	 * @param array<string, mixed> $source The referenced list.
	 *
	 * @return string|array<string, mixed>|null
	 */
	protected function source_template( array $source ) {
		if ( ! $this->source_matches_whole_numbers( $source ) ) {
			return parent::source_template( $source );
		}

		return array(
			'variable'       => 'asn',
			'operator'       => 'regex',
			'value'          => '#^{value}$#',
			'negate'         => ! empty( $source['negate'] ) !== ( 'not_equals' === $source['operator'] ),
			'case_sensitive' => true,
		);
	}

	/**
	 * {@inheritDoc}
	 *
	 * Digits only, for the pattern source_template() builds. An entry written
	 * `AS16509` is dropped by this rather than matched: the prefix cannot be
	 * taken off an entry the library substitutes after compilation. The rule
	 * screen and the README say so.
	 *
	 * @param array<string, mixed> $source The referenced list, with defaults.
	 */
	protected function source_record_guard( array $source ): array {
		if ( ! $this->source_matches_whole_numbers( $source ) ) {
			return array();
		}

		return array(
			array(
				'variable'       => 'value',
				'operator'       => 'regex',
				'value'          => '#^[0-9]+$#',
				'negate'         => false,
				'case_sensitive' => true,
			),
		);
	}

	/**
	 * {@inheritDoc}
	 */
	public function source_note(): string {
		return __( 'For an autonomous system number with "is equal to", "is not equal to" or "is one of", each entry is matched as a whole number, and has to be written as digits alone: an entry such as AS16509 is skipped. Use "contains" on the organisation for names.', 'basic-firewall' );
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

	/**
	 * {@inheritDoc}
	 *
	 * Along with the referenced lists' credentials, which the parent names.
	 */
	public function secret_settings(): array {
		return array_merge( parent::secret_settings(), array( 'reader.license_key' ) );
	}
}
