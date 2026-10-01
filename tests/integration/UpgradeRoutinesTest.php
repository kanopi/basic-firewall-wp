<?php
/**
 * Upgrade routines, run over documents as earlier releases stored them.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Install\Upgrader;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\RuleType\Types\Vulnerability_Score;
use Kanopi\BasicFirewall\Support\Schema;

/**
 * What an upgrade leaves in the option, given what an older release wrote.
 *
 * Each test writes the option raw at an older schema version and runs the
 * upgrader from there, so the routines run in the order and combination a real
 * site would meet them -- which is where two routines can undo each other.
 *
 * @covers \Kanopi\BasicFirewall\Install\Upgrader
 * @covers \Kanopi\BasicFirewall\RuleType\Types\Vulnerability_Score
 */
final class UpgradeRoutinesTest extends Settings_Snapshot {

	/**
	 * Schema version as found, put back afterwards.
	 *
	 * @var mixed
	 */
	private $version;

	/**
	 * Remember the schema version.
	 */
	protected function setUp(): void {
		parent::setUp();

		$this->version = get_option( Schema::VERSION_OPTION, null );
	}

	/**
	 * Put the schema version back.
	 */
	protected function tearDown(): void {
		if ( null === $this->version ) {
			delete_option( Schema::VERSION_OPTION );
		} else {
			update_option( Schema::VERSION_OPTION, $this->version, false );
		}

		delete_option( Upgrader::FAILURE_OPTION );

		parent::tearDown();
	}

	/**
	 * Write a document with these rules raw, at a schema version, and upgrade.
	 *
	 * @param list<array<string, mixed>> $rules   Rules as the older release stored them.
	 * @param int                        $version The schema version the site is on.
	 *
	 * @return array<string, array<string, mixed>> The upgraded rules, by id.
	 */
	private function upgrade( array $rules, int $version ): array {
		$this->given_settings( array() );

		$document          = Plugin::instance()->settings()->all();
		$document['rules'] = $rules;

		update_option( Schema::OPTION, $document, false );
		update_option( Schema::VERSION_OPTION, $version, false );
		Plugin::instance()->settings()->flush();

		Upgrader::maybe_upgrade();
		Plugin::instance()->settings()->flush();

		$this->assertNull( Upgrader::failure() );
		$this->assertSame( Schema::VERSION, (int) get_option( Schema::VERSION_OPTION ) );

		$stored = (array) get_option( Schema::OPTION );

		return array_column( (array) $stored['rules'], null, 'id' );
	}

	/**
	 * A stored Request / URL rule.
	 *
	 * @param string                     $id         Rule id.
	 * @param list<array<string, mixed>> $conditions Conditions, as stored.
	 * @param string                     $match_type any or all.
	 *
	 * @return array<string, mixed>
	 */
	private static function url_rule( string $id, array $conditions, string $match_type = 'any' ): array {
		return array(
			'id'       => $id,
			'type'     => 'url',
			'label'    => $id,
			'enabled'  => true,
			'response' => 'block',
			'settings' => array(
				'match_type' => $match_type,
				'conditions' => $conditions,
				'sources'    => array(),
			),
		);
	}

	/**
	 * A stored condition.
	 *
	 * @param string $variable Variable.
	 * @param string $operator Operator.
	 * @param string $value    Value.
	 * @param bool   $negate   Negated.
	 *
	 * @return array<string, mixed>
	 */
	private static function condition( string $variable, string $operator, string $value, bool $negate = false ): array {
		return array(
			'variable' => $variable,
			'operator' => $operator,
			'value'    => $value,
			'negate'   => $negate,
		);
	}

	/**
	 * Routine 9 stores `referer` and `content_type` as the headers they are,
	 * and keeps the variables with no equivalent exactly as they were.
	 */
	public function test_url_variables_are_renamed_and_the_rest_kept(): void {
		$rules = $this->upgrade(
			array(
				self::url_rule(
					'url',
					array(
						self::condition( 'referer', 'not_contains', 'example.com' ),
						self::condition( 'content_type', 'contains', 'json' ),
						self::condition( 'uri', 'contains', 'x', true ),
						self::condition( 'server.SERVER_NAME', 'equals', 'example.com' ),
						self::condition( 'path', 'starts_with', '/wp-admin' ),
					),
					'all'
				),
			),
			8
		);

		$this->assertSame(
			array( 'header.referer', 'header.content-type', 'uri', 'server.SERVER_NAME', 'path' ),
			array_column( $rules['url']['settings']['conditions'], 'variable' )
		);
		$this->assertTrue( $rules['url']['settings']['conditions'][2]['negate'], 'A kept condition lost its negation.' );
	}

	/**
	 * Upgrading from schema 1 keeps each pattern's case, whatever routine 2 does.
	 *
	 * Routine 2 saves the document, and a save re-validates every rule, which
	 * took every pasted pattern's delimiters off and left its case to the
	 * checkbox -- a schema 1 document has no checkbox value. Routine 3 then
	 * found nothing delimited and no flag to read, so `#Bot#` came out of the
	 * upgrade case-insensitive, matching `bot`, `BOT` and `robot` alike.
	 */
	public function test_regex_case_survives_upgrading_from_schema_1(): void {
		$rules = $this->upgrade(
			array(
				self::url_rule(
					'patterns',
					array(
						self::condition( 'header.user-agent', 'regex', '#Bot#' ),
						self::condition( 'header.user-agent', 'regex', '#bot#i' ),
						self::condition( 'path', 'regex', '/wp-admin/' ),
						self::condition( 'path', 'regex', '^/already-a-body' ),
					)
				),
			),
			1
		);

		$conditions = $rules['patterns']['settings']['conditions'];

		$this->assertSame( array( 'Bot', 'bot', 'wp-admin', '^/already-a-body' ), array_column( $conditions, 'value' ) );
		$this->assertSame( array( true, false, true, false ), array_column( $conditions, 'case_sensitive' ), 'An upgrade changed which case a pattern matches.' );
	}

	/**
	 * Routine 12 translates a withdrawn-shape vulnerability score rule where
	 * the mapping is sound, and switches the rest off without changing them.
	 *
	 * A threshold becomes one level that matches at it, with the default
	 * scores. A weight was one number for a whole signal, which the library
	 * has no equivalent for, so a rule with weights is kept as it was --
	 * and the compiler names it; see RuleTypesHonouredTest.
	 */
	public function test_withdrawn_vulnerability_score_rules_are_translated_or_switched_off(): void {
		$legacy = static fn ( string $id, array $settings ): array => array(
			'id'       => $id,
			'type'     => 'vulnerability_score',
			'label'    => $id,
			'enabled'  => true,
			'response' => 'challenge',
			'settings' => $settings,
		);

		$type     = new Vulnerability_Score();
		$weighted = array(
			'threshold' => 30,
			'weights'   => array( 'method' => 20 ),
		);

		$rules = $this->upgrade(
			array(
				$legacy(
					'plain',
					array(
						'threshold' => 45,
						'weights'   => array(),
					)
				),
				$legacy( 'weighted', $weighted ),
			),
			11
		);

		$expected                = $type->default_settings();
		$expected['risk_levels'] = array(
			array(
				'name'            => 'threshold',
				'threshold'       => 45,
				'block'           => true,
				'status_code'     => 0,
				'expiration_time' => 0,
			),
		);

		$this->assertSame( $expected, $rules['plain']['settings'], 'A threshold with no weights was not translated to one matching level.' );
		$this->assertTrue( $rules['plain']['enabled'], 'A translated rule was switched off.' );
		$this->assertSame( 'challenge', $rules['plain']['response'] );
		$this->assertFalse( Vulnerability_Score::is_legacy( $rules['plain']['settings'] ) );

		$errors = array();

		$this->assertSame( $expected, $type->validate_settings( $expected, $errors ), 'A translated rule does not survive its own validator.' );
		$this->assertSame( array(), $errors );

		$this->assertSame( $weighted, $rules['weighted']['settings'], 'An untranslatable rule was changed.' );
		$this->assertFalse( $rules['weighted']['enabled'], 'An untranslatable rule was left switched on.' );

		// Idempotent: run again from 11, and nothing moves.
		$again = $this->upgrade( array_values( $rules ), 11 );

		$this->assertSame( $rules['plain']['settings'], $again['plain']['settings'] );
		$this->assertSame( $weighted, $again['weighted']['settings'] );
	}

	/**
	 * Routine 13 deletes the geolocation and ASN license key, and nothing else (#54).
	 *
	 * Written straight into the option, the way 1.0 stored it, because every
	 * writer that goes through the settings now validates the key away.
	 */
	public function test_the_license_key_is_deleted_on_upgrade(): void {
		$reader = static fn ( string $database ): array => array(
			'source'      => 'database',
			'database'    => $database,
			'license_key' => 'MAXMIND-KEY-1c9e',
			'edge'        => 'cloudflare',
			'headers'     => array(),
		);
		$rule   = static fn ( string $id, string $type, string $variable, string $database ): array => array(
			'id'       => $id,
			'type'     => $type,
			'label'    => $id,
			'enabled'  => true,
			'response' => 'block',
			'settings' => array(
				'match_type' => 'any',
				'conditions' => array(
					array(
						'variable'       => $variable,
						'operator'       => 'equals',
						'value'          => 'ZZ',
						'negate'         => false,
						'case_sensitive' => false,
					),
				),
				'sources'    => array(),
				'reader'     => $reader( $database ),
			),
		);

		$url   = self::url_rule(
			'untouched',
			array(
				array(
					'variable'       => 'path',
					'operator'       => 'contains',
					'value'          => '/license_key',
					'negate'         => false,
					'case_sensitive' => false,
				),
			)
		);
		$rules = $this->upgrade(
			array(
				$rule( 'geo', 'geolocation', 'country', 'geoip/GeoLite2-City.mmdb' ),
				$rule( 'net', 'asn', 'asn_org', 'geoip/GeoLite2-ASN.mmdb' ),
				$url,
			),
			12
		);

		foreach ( array(
			'geo' => 'geoip/GeoLite2-City.mmdb',
			'net' => 'geoip/GeoLite2-ASN.mmdb',
		) as $id => $database ) {
			$this->assertArrayNotHasKey( 'license_key', $rules[ $id ]['settings']['reader'], sprintf( 'Rule %s kept its license key.', $id ) );
			$this->assertSame( $database, $rules[ $id ]['settings']['reader']['database'], 'The database path went with it.' );
			$this->assertSame( 'ZZ', $rules[ $id ]['settings']['conditions'][0]['value'] );
			$this->assertTrue( $rules[ $id ]['enabled'] );
		}

		$this->assertSame( $url['settings']['conditions'], $rules['untouched']['settings']['conditions'], 'A rule of another type was changed.' );
		$this->assertStringNotContainsString( 'MAXMIND-KEY-1c9e', (string) wp_json_encode( get_option( Schema::OPTION ) ) );

		// Idempotent: run again from 12, and the settings are not even written.
		$saves = 0;
		$count = static function () use ( &$saves ): void {
			++$saves;
		};

		add_action( 'basic_firewall_settings_saved', $count );

		try {
			$again = $this->upgrade( array_values( $rules ), 12 );
		} finally {
			remove_action( 'basic_firewall_settings_saved', $count );
		}

		$this->assertSame( $rules, $again );
		$this->assertSame( 1, $saves, 'Routine 13 wrote settings that held no license key.' );
	}
}
