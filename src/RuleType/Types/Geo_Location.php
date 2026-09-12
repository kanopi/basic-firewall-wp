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
		return __( 'Matches the country, continent, city, postal code or timezone the client address resolves to. Reads from a MaxMind database or from your CDN.', 'basic-firewall' );
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
			'country'      => __( 'Country code, such as US or GB', 'basic-firewall' ),
			'country_name' => __( 'Country name', 'basic-firewall' ),
			'continent'    => __( 'Continent code, such as EU', 'basic-firewall' ),
			'city'         => __( 'City — needs a City database, and most CDNs do not send it', 'basic-firewall' ),
			'postal'       => __( 'Postal code — needs a City database', 'basic-firewall' ),
			'timezone'     => __( 'Timezone — needs a City database', 'basic-firewall' ),
			'latitude'     => __( 'Latitude', 'basic-firewall' ),
			'longitude'    => __( 'Longitude', 'basic-firewall' ),
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
	 */
	public function validate_settings( array $settings, array &$errors ): array {
		return parent::validate_settings( $settings, $errors ) + $this->validate_reader( $settings, $errors );
	}

	/**
	 * {@inheritDoc}
	 */
	public function compile( array $rule ): array {
		$entry = parent::compile( $rule );

		return $this->apply_reader( $entry, $rule['settings'] ?? array() );
	}

	/**
	 * {@inheritDoc}
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
