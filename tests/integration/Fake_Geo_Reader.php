<?php
/**
 * A MaxMind reader for tests.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use GeoIp2\Database\Reader;
use GeoIp2\Model\Asn as AsnModel;
use GeoIp2\Model\City;
use GeoIp2\Model\Country;

/**
 * A MaxMind reader that needs no database and always answers London, AWS.
 *
 * The Country lookup answers the same country, for the vulnerability score
 * plugin, which asks for a Country record rather than a City one.
 *
 * The real reader's record classes are used, so a variable resolves only if
 * the library reads it off the record the way a real lookup would.
 */
final class Fake_Geo_Reader extends Reader {

	/**
	 * No database to open.
	 */
	public function __construct() {} // phpcs:ignore Generic.CodeAnalysis.UselessOverridingMethod.Found

	/**
	 * A City record.
	 *
	 * @param string $ipAddress Address.
	 */
	public function city( string $ipAddress ): City { // phpcs:ignore WordPress.NamingConventions.ValidVariableName.VariableNotSnakeCase
		return new City(
			array(
				'country'   => array(
					'iso_code' => 'GB',
					'names'    => array( 'en' => 'United Kingdom' ),
				),
				'continent' => array(
					'code'  => 'EU',
					'names' => array( 'en' => 'Europe' ),
				),
				'city'      => array( 'names' => array( 'en' => 'London' ) ),
				'postal'    => array( 'code' => 'EC1A' ),
				'location'  => array(
					'latitude'  => 51.5142,
					'longitude' => -0.0931,
					'time_zone' => 'Europe/London',
				),
				'traits'    => array(
					'ip_address' => $ipAddress, // phpcs:ignore WordPress.NamingConventions.ValidVariableName.VariableNotSnakeCase
					'prefix_len' => 24,
				),
			),
			array( 'en' )
		);
	}

	/**
	 * A Country record, which the vulnerability score plugin looks up.
	 *
	 * @param string $ipAddress Address.
	 */
	public function country( string $ipAddress ): Country { // phpcs:ignore WordPress.NamingConventions.ValidVariableName.VariableNotSnakeCase
		return new Country(
			array(
				'country'   => array(
					'iso_code' => 'GB',
					'names'    => array( 'en' => 'United Kingdom' ),
				),
				'continent' => array(
					'code'  => 'EU',
					'names' => array( 'en' => 'Europe' ),
				),
				'traits'    => array(
					'ip_address' => $ipAddress, // phpcs:ignore WordPress.NamingConventions.ValidVariableName.VariableNotSnakeCase
					'prefix_len' => 24,
				),
			),
			array( 'en' )
		);
	}

	/**
	 * An ASN record.
	 *
	 * @param string $ipAddress Address.
	 */
	public function asn( string $ipAddress ): AsnModel { // phpcs:ignore WordPress.NamingConventions.ValidVariableName.VariableNotSnakeCase
		return new AsnModel(
			array(
				'autonomous_system_number'       => 16509,
				'autonomous_system_organization' => 'AMAZON-02',
				'ip_address'                     => $ipAddress, // phpcs:ignore WordPress.NamingConventions.ValidVariableName.VariableNotSnakeCase
				'prefix_len'                     => 16,
			)
		);
	}
}
