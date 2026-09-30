<?php
/**
 * The geolocation rule type.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\RuleType\Types;

use Kanopi\BasicFirewall\RuleType\Condition_Rule_Type_Base;
use Kanopi\BasicFirewall\RuleType\Geo_Reader_Settings;
use Kanopi\Firewall\Plugins\GeoLocation;

/**
 * Matches on where the client address resolves to.
 *
 * The location can come from a MaxMind database or, since library 2.18, from
 * the CDN in front of the site. The second is cheaper -- the edge already
 * resolved the address, so there is no database to license and no lookup per
 * request -- but it means trusting a header, and that has a failure mode worth
 * stating plainly:
 *
 * **Without trusted proxies configured, the library will not believe the header,
 * the rule matches nothing, and geo blocking that silently does not work looks
 * exactly like nobody from those countries visiting.** Site Health raises an
 * error when a rule reads from the edge and the proxy settings are absent,
 * because that is the one failure nobody notices on their own.
 */
final class Geo_Location extends Condition_Rule_Type_Base {

	use Geo_Reader_Settings;

	/**
	 * {@inheritDoc}
	 */
	public function id(): string {
		return 'geolocation';
	}

	/**
	 * {@inheritDoc}
	 */
	public function label(): string {
		return __( 'Geolocation', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function description(): string {
		return __( 'Matches the country, continent, city, postal code, timezone or coordinates the client address resolves to. Reads from a MaxMind database or from your CDN.', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function library_class(): string {
		return GeoLocation::class;
	}

	/**
	 * {@inheritDoc}
	 */
	public function weight(): int {
		return -30;
	}

	/**
	 * {@inheritDoc}
	 */
	protected function variable_options(): array {
		return array(
			'country'            => __( 'Country code, such as US or GB', 'basic-firewall' ),
			'country.name'       => __( 'Country name, such as United Kingdom — from the database, or a CDN that sends it (CloudFront, Fastly)', 'basic-firewall' ),
			'continent'          => __( 'Continent code, such as EU', 'basic-firewall' ),
			'city'               => __( 'City — needs a City database, and most CDNs do not send it', 'basic-firewall' ),
			'postal'             => __( 'Postal code — needs a City database', 'basic-firewall' ),
			'location.timeZone'  => __( 'Timezone, such as Europe/London — needs a City database; no CDN sends it', 'basic-firewall' ),
			'location.latitude'  => __( 'Latitude, in degrees — greater than or less than for an area; equals only matches the exact coordinate', 'basic-firewall' ),
			'location.longitude' => __( 'Longitude, in degrees — greater than or less than for an area; equals only matches the exact coordinate', 'basic-firewall' ),
		);
	}

	/**
	 * {@inheritDoc}
	 *
	 * The names this type used to offer. The library reads a GeoIP2
	 * record by its own property path -- `country.name`, `location.timeZone`
	 * -- and resolves anything else to nothing, so every rule written on these
	 * saved, reported itself healthy, and matched nobody.
	 */
	protected function renamed_variables(): array {
		return self::RENAMED_VARIABLES;
	}

	/**
	 * Old variable name to the library's.
	 *
	 * @var array<string, string>
	 */
	public const RENAMED_VARIABLES = array(
		'country_name' => 'country.name',
		'timezone'     => 'location.timeZone',
		'latitude'     => 'location.latitude',
		'longitude'    => 'location.longitude',
	);

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
		$entry    = parent::compile( $rule );
		$settings = (array) ( $rule['settings'] ?? array() );
		$reader   = (array) ( $settings['reader'] ?? array() );

		if ( 'edge' !== ( $reader['source'] ?? 'database' ) && is_array( $entry['config'] ?? null ) ) {
			$entry['config'] = self::coordinates_as_numbers( $entry['config'] );
		}

		return $this->apply_reader( $entry, $settings );
	}

	/**
	 * Compare a coordinate as a number when it comes from a database (#49).
	 *
	 * A MaxMind record holds latitude and longitude as floats, a compiled
	 * value is text, and the library compares `equals`, `not_equals` and `in`
	 * strictly -- so "latitude equals 51.5142" never matched a visitor at
	 * 51.5142, and "not equals" matched every visitor, that one included.
	 * Library 2.35 coerces the ASN number this way and nothing else.
	 *
	 * Cast here, at compile time, rather than by withholding `equals` from
	 * the screen: the operator means what it says once both sides are
	 * numbers, and rules that already use it start working rather than
	 * having to be rewritten. Only for a database. A CDN sends the
	 * coordinate as a header, which is text, and text against text already
	 * compares correctly -- a float there would break a rule that works.
	 *
	 * The comparison is also made case-sensitive, which for a number changes
	 * nothing but what the library does to the value first: case-insensitive,
	 * it lowercases every entry of an `in` list, turning each float back into
	 * text before the strict comparison. A value that is not a number is left
	 * as typed; it matched nothing before and still matches nothing.
	 *
	 * @param array<int|string, mixed> $rules Compiled conditions, possibly grouped.
	 *
	 * @return array<int|string, mixed>
	 */
	private static function coordinates_as_numbers( array $rules ): array {
		foreach ( $rules as $index => $rule ) {
			if ( ! is_array( $rule ) ) {
				continue;
			}

			if ( is_array( $rule['rules'] ?? null ) ) {
				$rules[ $index ]['rules'] = self::coordinates_as_numbers( $rule['rules'] );

				continue;
			}

			if (
				! in_array( $rule['variable'] ?? '', array( 'location.latitude', 'location.longitude' ), true )
				|| ! in_array( $rule['operator'] ?? '', array( 'equals', 'not_equals', 'in' ), true )
			) {
				continue;
			}

			$value = $rule['value'] ?? '';

			if ( is_array( $value ) ) {
				if ( array() === $value || count( array_filter( $value, 'is_numeric' ) ) !== count( $value ) ) {
					continue;
				}

				$rules[ $index ]['value'] = array_map( 'floatval', $value );
			} elseif ( is_numeric( $value ) ) {
				$rules[ $index ]['value'] = (float) $value;
			} else {
				continue;
			}

			$rules[ $index ]['case_sensitive'] = true;
		}

		return $rules;
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
	 * Along with the referenced lists' credentials, which the parent names.
	 */
	public function secret_settings(): array {
		return array_merge( parent::secret_settings(), array( 'reader.license_key' ) );
	}
}
