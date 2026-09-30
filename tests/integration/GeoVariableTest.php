<?php
/**
 * Geolocation and ASN variables, against the library that reads them.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use GeoIp2\Database\Reader;
use Kanopi\BasicFirewall\Compiler\Config_Compiler;
use Kanopi\BasicFirewall\Install\Upgrader;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\RuleType\Condition_Rule_Type_Base;
use Kanopi\BasicFirewall\Support\Schema;
use Kanopi\Firewall\Plugins\Asn as LibraryAsn;
use Kanopi\Firewall\Plugins\GeoLocation;
use Kanopi\Firewall\Source\SourceDefinition;
use Kanopi\Firewall\Source\SourceLoader;
use Symfony\Component\HttpFoundation\Request;

/**
 * Every variable a rule screen offers has to be one the library resolves.
 *
 * The geolocation type offered `country_name`, `timezone`, `latitude` and
 * `longitude`; the library reads a GeoIP2 record by its property path, as
 * `country.name`, `location.timeZone`, `location.latitude` and
 * `location.longitude`, and resolves anything else to nothing. The ASN type
 * offered `organization` for the library's `asn_org`, and `network`, which the
 * library does not read at all. Every one of those rules saved, loaded,
 * reported itself healthy, and matched nobody.
 *
 * So these tests do not compare names against a list. They compile a rule
 * through the rule type, hand the result to the library's own plugin with a
 * reader that returns a known record, and assert the rule matches.
 *
 * @covers \Kanopi\BasicFirewall\RuleType\Types\Geo_Location
 * @covers \Kanopi\BasicFirewall\RuleType\Types\Asn
 * @covers \Kanopi\BasicFirewall\RuleType\Condition_Rule_Type_Base
 * @covers \Kanopi\BasicFirewall\Install\Upgrader
 * @covers \Kanopi\BasicFirewall\Compiler\Config_Compiler
 */
final class GeoVariableTest extends Settings_Snapshot {

	/**
	 * What each offered geolocation variable is compared against.
	 *
	 * Operator and value, chosen to match the record the fake reader returns.
	 * Coordinates are compared numerically: the record holds a float, and an
	 * equality test on one is meaningless anyway.
	 *
	 * @var array<string, array{0: string, 1: string}>
	 */
	private const GEO_MATCHES = array(
		'country'            => array( 'equals', 'GB' ),
		'country.name'       => array( 'equals', 'United Kingdom' ),
		'continent'          => array( 'equals', 'EU' ),
		'city'               => array( 'equals', 'London' ),
		'postal'             => array( 'equals', 'EC1A' ),
		'location.timeZone'  => array( 'equals', 'Europe/London' ),
		'location.latitude'  => array( 'gt', '51' ),
		'location.longitude' => array( 'lt', '0' ),
	);

	/**
	 * What each offered ASN variable is compared against.
	 *
	 * @var array<string, array{0: string, 1: string}>
	 */
	private const ASN_MATCHES = array(
		'asn'     => array( 'equals', '16509' ),
		'asn_org' => array( 'contains', 'amazon' ),
	);

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
	 * Every offered geolocation variable matches a record read from a database.
	 */
	public function test_every_offered_geolocation_variable_resolves(): void {
		$offered = $this->offered( 'geolocation' );

		$this->assertSame( array_keys( self::GEO_MATCHES ), array_keys( $offered ), 'An offered variable has no test proving the library reads it.' );

		foreach ( self::GEO_MATCHES as $variable => list( $operator, $value ) ) {
			$this->assertTrue(
				$this->geo_plugin( $this->compile( 'geolocation', $variable, $operator, $value ) )->evaluate( $this->request() ),
				"$variable $operator $value did not match the record."
			);
			$this->assertFalse(
				$this->geo_plugin( $this->compile( 'geolocation', $variable, $operator, 'gt' === $operator ? '89' : ( 'lt' === $operator ? '-179' : 'nowhere' ) ) )->evaluate( $this->request() ),
				"$variable matched a value the record does not hold."
			);
		}
	}

	/**
	 * Every offered ASN variable matches a record read from a database.
	 */
	public function test_every_offered_asn_variable_resolves(): void {
		$offered = $this->offered( 'asn' );

		$this->assertSame( array_keys( self::ASN_MATCHES ), array_keys( $offered ), 'An offered variable has no test proving the library reads it.' );

		foreach ( self::ASN_MATCHES as $variable => list( $operator, $value ) ) {
			$this->assertTrue(
				$this->asn_plugin( $this->compile( 'asn', $variable, $operator, $value ) )->evaluate( $this->request() ),
				"$variable $operator $value did not match the record."
			);
			$this->assertFalse(
				$this->asn_plugin( $this->compile( 'asn', $variable, $operator, '99999' ) )->evaluate( $this->request() ),
				"$variable matched a value the record does not hold."
			);
		}
	}

	/**
	 * An autonomous system number matches however it is written.
	 *
	 * The record holds an integer and every form field produces a string. The
	 * plugin used to cast the value and strip the prefix itself; since
	 * kanopi/firewall 2.35.0 the library reads both sides as a number, so the
	 * condition compiles as typed and this proves the library does the rest.
	 *
	 * @dataProvider asn_spellings
	 *
	 * @param string $operator The comparison.
	 * @param string $value    As typed.
	 */
	public function test_an_asn_matches_as_typed( string $operator, string $value ): void {
		$entry = $this->compile( 'asn', 'asn', $operator, $value );

		$this->assertTrue( $this->asn_plugin( $entry )->evaluate( $this->request() ) );
	}

	/**
	 * The ways somebody writes an autonomous system number.
	 *
	 * @return array<string, array{0: string, 1: string}>
	 */
	public static function asn_spellings(): array {
		return array(
			'digits'                => array( 'equals', '16509' ),
			'with the prefix'       => array( 'equals', 'AS16509' ),
			'lower-case prefix'     => array( 'equals', 'as16509' ),
			'in a list'             => array( 'in', '13335, 16509' ),
			'in a list, prefixed'   => array( 'in', 'AS13335, AS16509' ),
			'not another'           => array( 'not_equals', '13335' ),
			'not another, prefixed' => array( 'not_equals', 'AS13335' ),
			'numeric compared'      => array( 'gte', '16509' ),
			'contains is text'      => array( 'contains', '650' ),
		);
	}

	/**
	 * An autonomous system number is not matched by a condition that excludes it.
	 *
	 * Before 2.35.0 `not_equals` compared the record's integer with a string,
	 * never found them equal, and so matched every visitor, the named network
	 * included.
	 *
	 * @dataProvider asn_non_matches
	 *
	 * @param string $operator The comparison.
	 * @param string $value    As typed.
	 */
	public function test_an_asn_does_not_match_a_condition_excluding_it( string $operator, string $value ): void {
		$entry = $this->compile( 'asn', 'asn', $operator, $value );

		$this->assertFalse( $this->asn_plugin( $entry )->evaluate( $this->request() ) );
	}

	/**
	 * Conditions that AS16509 must not meet.
	 *
	 * @return array<string, array{0: string, 1: string}>
	 */
	public static function asn_non_matches(): array {
		return array(
			'not equal, digits'   => array( 'not_equals', '16509' ),
			'not equal, prefixed' => array( 'not_equals', 'AS16509' ),
			'a prefix of it'      => array( 'equals', '1650' ),
			'a longer number'     => array( 'equals', '165090' ),
			'another network'     => array( 'in', '13335, AS15169' ),
		);
	}

	/**
	 * A rule stored under an old name compiles to the library's, and matches.
	 *
	 * @dataProvider renamed
	 *
	 * @param string $type     Rule type.
	 * @param string $old      The old name.
	 * @param string $library  The library's name.
	 */
	public function test_an_old_name_compiles_to_the_library_name( string $type, string $old, string $library ): void {
		$matches = 'asn' === $type ? self::ASN_MATCHES : self::GEO_MATCHES;
		$entry   = $this->compile( $type, $old, $matches[ $library ][0], $matches[ $library ][1] );

		$this->assertSame( $library, $entry['config'][0]['variable'] );

		$plugin = 'asn' === $type ? $this->asn_plugin( $entry ) : $this->geo_plugin( $entry );

		$this->assertTrue( $plugin->evaluate( $this->request() ), "A rule saved on $old still matches nothing." );
	}

	/**
	 * Every rename.
	 *
	 * @return array<string, array{0: string, 1: string, 2: string}>
	 */
	public static function renamed(): array {
		return array(
			'country_name' => array( 'geolocation', 'country_name', 'country.name' ),
			'timezone'     => array( 'geolocation', 'timezone', 'location.timeZone' ),
			'latitude'     => array( 'geolocation', 'latitude', 'location.latitude' ),
			'longitude'    => array( 'geolocation', 'longitude', 'location.longitude' ),
			'organization' => array( 'asn', 'organization', 'asn_org' ),
		);
	}

	/**
	 * Validating an old name stores the library's, rather than refusing it.
	 *
	 * Every settings write re-validates every rule, so refusing would drop the
	 * condition -- and out of an "all" rule that widens what it matches.
	 */
	public function test_validation_stores_the_library_name(): void {
		$errors = array();
		$clean  = $this->type( 'geolocation' )->validate_settings(
			array(
				'match_type' => 'all',
				'conditions' => array(
					array(
						'variable' => 'country_name',
						'operator' => 'equals',
						'value'    => 'France',
					),
				),
				'sources'    => array(),
			),
			$errors
		);

		$this->assertArrayNotHasKey( 'conditions.0.variable', $errors );
		$this->assertSame( 'country.name', $clean['conditions'][0]['variable'] );
	}

	/**
	 * The edge supplies the same vocabulary, so a rule works on either source.
	 */
	public function test_the_library_names_resolve_from_the_edge(): void {
		$proxies = Request::getTrustedProxies();
		$headers = Request::getTrustedHeaderSet();

		try {
			Request::setTrustedProxies( array( '10.0.0.1' ), Request::HEADER_X_FORWARDED_FOR );

			$request = Request::create(
				'/',
				'GET',
				array(),
				array(),
				array(),
				array(
					'REMOTE_ADDR'                         => '10.0.0.1',
					'HTTP_X_FORWARDED_FOR'                => '203.0.113.10',
					'HTTP_CLOUDFRONT_VIEWER_COUNTRY'      => 'GB',
					'HTTP_CLOUDFRONT_VIEWER_COUNTRY_NAME' => 'United Kingdom',
					'HTTP_CLOUDFRONT_VIEWER_LATITUDE'     => '51.5142',
					'HTTP_CLOUDFRONT_VIEWER_LONGITUDE'    => '-0.0931',
				)
			);

			foreach ( array( 'country', 'country.name', 'location.latitude', 'location.longitude' ) as $variable ) {
				$entry = $this->compile( 'geolocation', $variable, self::GEO_MATCHES[ $variable ][0], self::GEO_MATCHES[ $variable ][1], $this->edge_reader() );

				$this->assertSame( 'header', $entry['metadata']['source'] );
				$this->assertTrue(
					( new GeoLocation( $entry['metadata'], $entry['config'] ) )->evaluate( $request ),
					"$variable did not resolve from CloudFront's headers."
				);
			}
		} finally {
			Request::setTrustedProxies( $proxies, $headers );
		}
	}

	/**
	 * The upgrade rewrites stored names to the library's.
	 */
	public function test_the_upgrade_rewrites_stored_names(): void {
		$this->given_settings( array() );

		$document          = Plugin::instance()->settings()->all();
		$document['rules'] = array(
			$this->rule( 'geo', 'geolocation', array( 'country_name', 'timezone', 'latitude', 'longitude', 'country' ), 'longitude' ),
			$this->rule( 'net', 'asn', array( 'organization', 'asn' ), 'organization' ),
		);

		// Written raw, as a site on the previous release has it.
		update_option( Schema::OPTION, $document, false );
		update_option( Schema::VERSION_OPTION, 6, false );
		Plugin::instance()->settings()->flush();

		Upgrader::maybe_upgrade();
		Plugin::instance()->settings()->flush();

		$this->assertNull( Upgrader::failure() );
		$this->assertSame( Schema::VERSION, (int) get_option( Schema::VERSION_OPTION ) );

		$rules = array_column( (array) Plugin::instance()->settings()->get( 'rules', array() ), null, 'id' );

		$this->assertSame(
			array( 'country.name', 'location.timeZone', 'location.latitude', 'location.longitude', 'country' ),
			array_column( $rules['geo']['settings']['conditions'], 'variable' )
		);
		$this->assertSame( 'location.longitude', $rules['geo']['settings']['sources'][0]['variable'] );
		$this->assertSame( array( 'asn_org', 'asn' ), array_column( $rules['net']['settings']['conditions'], 'variable' ) );
		$this->assertSame( 'asn_org', $rules['net']['settings']['sources'][0]['variable'] );
	}

	/**
	 * A condition on a variable the library cannot read is kept, and reported.
	 *
	 * Kept, because dropping it out of an "all" rule would widen the rule. Not
	 * offered, and reported on the rule and by the compiler, because the
	 * problem was that it reported itself healthy.
	 */
	public function test_a_network_condition_is_kept_and_reported(): void {
		$this->given_settings(
			array(
				'rules' => array(
					$this->rule( 'net', 'asn', array( 'asn', 'network' ), '' ),
				),
			)
		);

		$rule = ( (array) Plugin::instance()->settings()->get( 'rules', array() ) )[0];

		$this->assertSame( array( 'asn', 'network' ), array_column( $rule['settings']['conditions'], 'variable' ), 'A settings write dropped the condition.' );
		$this->assertArrayNotHasKey( 'network', $this->offered( 'asn' ) );
		$this->assertNotEmpty( preg_grep( '/network/', $this->type( 'asn' )->check_requirements( $rule['settings'] ) ) );

		$compiler = new Config_Compiler();
		$compiler->compile();

		$this->assertNotEmpty( preg_grep( '/"net".*network/', $compiler->problems() ) );
	}

	/**
	 * A list of autonomous system numbers matches with equals, one of, and not equal to.
	 *
	 * A text list's entries are strings and the record holds an integer. The
	 * plugin used to compile such a list into a digits-only pattern, skipping
	 * an entry written `AS16509`; since kanopi/firewall 2.35.0 the library
	 * compares the substituted entry as a number, so the list compiles to a
	 * plain equality and a prefixed entry matches. The list is run through the
	 * library's own source pipeline here, the way a refresh does, and the
	 * entries it produces are handed to the library's ASN plugin.
	 *
	 * @dataProvider asn_lists
	 *
	 * @param string $operator The comparison.
	 * @param string $format   The list's format.
	 * @param string $body     The list.
	 * @param bool   $matches  Whether AS16509 matches.
	 */
	public function test_an_asn_list_matches_whole_numbers( string $operator, string $format, string $body, bool $matches ): void {
		$rule                                   = $this->rule( 'net', 'asn', array(), '' );
		$rule['settings']['sources'][0]         = array_merge(
			$this->type( 'asn' )::source_defaults(),
			array(
				'url'      => 'https://example.test/networks.' . $format,
				'format'   => $format,
				'variable' => 'asn',
				'operator' => $operator,
			)
		);
		$rule['settings']['reader']['database'] = 'unused.mmdb';

		$entry       = $this->type( 'asn' )->compile( $rule );
		$declaration = $entry['metadata']['sources'][0];

		$this->assertStringNotContainsString( 'regex', (string) wp_json_encode( $declaration ), 'A list of numbers is still compiled as a pattern.' );
		$this->assertArrayNotHasKey( 'where', $declaration, 'A list of numbers still carries the digits-only guard.' );
		$entries = ( new SourceLoader( null, null, null, null, null, array(), true ) )->pipeline( SourceDefinition::fromArray( $declaration ), $body );

		$entry['config'] = array_merge( (array) ( $entry['config'] ?? array() ), $entries );
		unset( $entry['metadata']['sources'] );

		$this->assertSame( $matches, (bool) $this->asn_plugin( $entry )->evaluate( $this->request() ) );
	}

	/**
	 * Lists, and whether AS16509 is matched by each.
	 *
	 * @return array<string, array{0: string, 1: string, 2: string, 3: bool}>
	 */
	public static function asn_lists(): array {
		return array(
			'listed, equals'             => array( 'equals', 'txt', "13335\n16509\n", true ),
			'listed, one of'             => array( 'in', 'txt', "16509\n", true ),
			'not listed'                 => array( 'equals', 'txt', "13335\n1650\n165090\n", false ),
			'a JSON list of integers'    => array( 'equals', 'json', '[13335, 16509]', true ),
			'not equal, not listed'      => array( 'not_equals', 'txt', "13335\n", true ),
			'not equal, listed'          => array( 'not_equals', 'txt', "16509\n", false ),
			'a pattern is not a number'  => array( 'equals', 'txt', ".*\n1.*\n", false ),
			'listed with the prefix'     => array( 'equals', 'txt', "AS13335\nAS16509\n", true ),
			'prefixed, one of'           => array( 'in', 'txt', "AS16509\n", true ),
			'not equal, listed prefixed' => array( 'not_equals', 'txt', "AS16509\n", false ),
			'not equal, other prefixed'  => array( 'not_equals', 'txt', "AS13335\n", true ),
			'padded entry'               => array( 'equals', 'txt', "  16509  \n", true ),
		);
	}

	/**
	 * The variables a type offers on its screen.
	 *
	 * @param string $id Rule type.
	 *
	 * @return array<string, string>
	 */
	private function offered( string $id ): array {
		$reflector = new \ReflectionMethod( $this->type( $id ), 'variable_options' );
		$reflector->setAccessible( true );

		return (array) $reflector->invoke( $this->type( $id ) );
	}

	/**
	 * A registered condition rule type.
	 *
	 * @param string $id Rule type.
	 */
	private function type( string $id ): Condition_Rule_Type_Base {
		$type = Plugin::instance()->rule_types()->get( $id );

		$this->assertInstanceOf( Condition_Rule_Type_Base::class, $type );

		return $type;
	}

	/**
	 * Compile a one-condition rule through its type.
	 *
	 * @param string               $id       Rule type.
	 * @param string               $variable Variable.
	 * @param string               $operator Screen operator.
	 * @param string               $value    Value.
	 * @param array<string, mixed> $reader   Reader settings.
	 *
	 * @return array<string, mixed>
	 */
	private function compile( string $id, string $variable, string $operator, string $value, array $reader = array() ): array {
		$rule = $this->rule( 'r', $id, array( $variable ), '' );

		$rule['settings']['conditions'][0]['operator'] = $operator;
		$rule['settings']['conditions'][0]['value']    = $value;
		$rule['settings']['reader']                    = $reader;

		return $this->type( $id )->compile( $rule );
	}

	/**
	 * A rule with one condition per variable, and optionally a list.
	 *
	 * @param string       $id        Rule id.
	 * @param string       $type      Rule type.
	 * @param list<string> $variables Condition variables.
	 * @param string       $source    List variable, or none.
	 *
	 * @return array<string, mixed>
	 */
	private function rule( string $id, string $type, array $variables, string $source ): array {
		return array(
			'id'              => $id,
			'type'            => $type,
			'label'           => $id,
			'enabled'         => true,
			'observe'         => false,
			'response'        => 'block',
			'weight'          => 0,
			'status_code'     => 0,
			'record'          => 'default',
			'redirect_to'     => '',
			'redirect_status' => 302,
			'mark_as'         => '',
			'mark_header'     => '',
			'expiration'      => 600,
			'settings'        => array(
				'match_type' => 'any',
				'conditions' => array_map(
					static fn ( string $variable ): array => array(
						'variable'       => $variable,
						'operator'       => 'equals',
						'value'          => 'x',
						'negate'         => false,
						'case_sensitive' => false,
					),
					$variables
				),
				'sources'    => '' === $source ? array() : array(
					array(
						'url'      => 'example.txt',
						'variable' => $source,
						'operator' => 'contains',
						'template' => '',
						'negate'   => false,
					),
				),
			),
		);
	}

	/**
	 * Reader settings for CloudFront's headers.
	 *
	 * @return array<string, mixed>
	 */
	private function edge_reader(): array {
		return array(
			'source'      => 'edge',
			'database'    => '',
			'license_key' => '',
			'edge'        => 'cloudfront',
			'headers'     => array(),
		);
	}

	/**
	 * A request from the address the fake reader knows.
	 */
	private function request(): Request {
		return Request::create( '/', 'GET', array(), array(), array(), array( 'REMOTE_ADDR' => '203.0.113.10' ) );
	}

	/**
	 * The library's geolocation plugin, reading the fake database.
	 *
	 * @param array<string, mixed> $entry Compiled entry.
	 */
	private function geo_plugin( array $entry ): GeoLocation {
		$plugin = new class( $entry['metadata'] ?? array(), $entry['config'] ?? array() ) extends GeoLocation {
			/**
			 * Swap in a reader.
			 *
			 * @param Reader $reader The reader.
			 */
			public function use_reader( Reader $reader ): void {
				$this->reader = $reader;
			}
		};

		$plugin->use_reader( new Fake_Geo_Reader() );

		return $plugin;
	}

	/**
	 * The library's ASN plugin, reading the fake database.
	 *
	 * @param array<string, mixed> $entry Compiled entry.
	 */
	private function asn_plugin( array $entry ): LibraryAsn {
		$plugin = new class( $entry['metadata'] ?? array(), $entry['config'] ?? array() ) extends LibraryAsn {
			/**
			 * Swap in a reader.
			 *
			 * @param Reader $reader The reader.
			 */
			public function use_reader( Reader $reader ): void {
				$this->reader = $reader;
			}
		};

		$plugin->use_reader( new Fake_Geo_Reader() );

		return $plugin;
	}
}
