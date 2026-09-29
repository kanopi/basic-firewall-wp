<?php
/**
 * Where a geolocation or ASN rule gets its answer from, through the rule screen.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Plugin;
use Kanopi\Firewall\Firewall;
use Symfony\Component\Yaml\Yaml;

/**
 * The reader settings survive a save through the screen, and compile to what the library reads.
 *
 * The round trip is done the way a browser does it: the edit screen is
 * rendered, every control on its form is read back out of the markup with the
 * value it was rendered with, and that is what is posted to the handler. So a
 * field the screen forgets to render is a field this test forgets to post --
 * which is exactly how the reader used to be lost.
 *
 * @covers \Kanopi\BasicFirewall\Admin\Screen\Rule_Edit_Screen
 * @covers \Kanopi\BasicFirewall\RuleType\Geo_Reader_Settings
 * @covers \Kanopi\BasicFirewall\RuleType\Types\Geo_Location
 * @covers \Kanopi\BasicFirewall\RuleType\Types\Asn
 */
final class GeoReaderSettingsTest extends Settings_Snapshot {

	use Rendered_Rule_Form;

	/**
	 * Request globals, put back after each test.
	 *
	 * @var array{get: array<mixed>, post: array<mixed>, user: int}
	 */
	private array $globals;

	/**
	 * Remember the request globals.
	 */
	protected function setUp(): void {
		parent::setUp();

		// The edit screen closes its form with submit_button(), which only
		// admin requests load.
		require_once ABSPATH . 'wp-admin/includes/template.php';

		$this->globals = array(
			'get'  => $_GET, // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			'post' => $_POST, // phpcs:ignore WordPress.Security.NonceVerification.Missing
			'user' => get_current_user_id(),
		);
	}

	/**
	 * Put them back, and drop any notices a screen queued.
	 */
	protected function tearDown(): void {
		delete_transient( 'basic_firewall_notices_' . get_current_user_id() );
		remove_all_filters( 'wp_redirect' );

		$_GET  = $this->globals['get'];
		$_POST = $this->globals['post'];
		wp_set_current_user( $this->globals['user'] );

		parent::tearDown();
	}

	/**
	 * A database reader is on the edit screen, with what is stored.
	 */
	public function test_the_edit_screen_renders_the_reader(): void {
		$this->given_rule( $this->rule( 'geolocation', $this->database_reader() ) );

		$fields = $this->rendered_fields( 'geo' );

		$this->assertSame( 'database', $fields['settings[reader][source]'] ?? null );
		$this->assertSame( 'geoip/GeoLite2-City.mmdb', $fields['settings[reader][database]'] ?? null );
		$this->assertSame( 'LICENSE-KEY', $fields['settings[reader][license_key]'] ?? null );
	}

	/**
	 * Saving a database-backed rule through the screen keeps its reader.
	 *
	 * Before the reader was rendered, nothing of it was posted, and the rule
	 * was refused for having no database path -- so a geolocation rule could
	 * not be saved through its own screen at all.
	 */
	public function test_saving_through_the_screen_keeps_a_database_reader(): void {
		$this->given_rule( $this->rule( 'geolocation', $this->database_reader() ) );

		$this->assertTrue( $this->save_as_rendered( 'geo' ), 'The screen refused its own rendering of the rule.' );
		$this->assertSame( $this->database_reader(), $this->stored_reader() );
	}

	/**
	 * Saving an edge-backed rule through the screen keeps it on the edge.
	 *
	 * The quiet failure: with nothing posted, the validator put the rule back
	 * on a database it did not have.
	 */
	public function test_saving_through_the_screen_keeps_an_edge_reader(): void {
		$reader = array(
			'source'      => 'edge',
			'database'    => 'geoip/kept-for-later.mmdb',
			'license_key' => '',
			'edge'        => 'custom',
			'headers'     => array(
				'country'           => 'X-Geo-Country',
				'location.latitude' => 'X-Geo-Lat',
			),
		);

		$this->given_rule( $this->rule( 'geolocation', $reader ) );

		$this->assertTrue( $this->save_as_rendered( 'geo' ) );
		$this->assertSame( $reader, $this->stored_reader(), 'The database path is kept for switching back, and the mapping survives as a map.' );
	}

	/**
	 * An ASN rule keeps its database through the screen too.
	 */
	public function test_saving_an_asn_rule_keeps_its_reader(): void {
		$reader = array( 'database' => 'geoip/GeoLite2-ASN.mmdb' ) + $this->database_reader();

		$this->given_rule( $this->rule( 'asn', $reader ) );

		$fields = $this->rendered_fields( 'geo' );

		$this->assertArrayNotHasKey( 'settings[reader][source]', $fields, 'The ASN plugin reads no header, so the choice is not offered.' );

		$this->assertTrue( $this->save_as_rendered( 'geo' ) );
		$this->assertSame( 'geoip/GeoLite2-ASN.mmdb', $this->stored_reader()['database'] ?? null );
	}

	/**
	 * A mapping to a field the library does not know is refused.
	 *
	 * The library throws on it when the rule is built, and the firewall fails
	 * open on every rule when that happens.
	 */
	public function test_an_unknown_header_field_is_refused(): void {
		$errors = array();

		Plugin::instance()->rule_types()->get( 'geolocation' )->validate_settings(
			array(
				'reader' => array(
					'source'  => 'edge',
					'edge'    => 'custom',
					'headers' => "country_name: X-Geo-Name\ncountry: X-Geo-Country",
				),
			),
			$errors
		);

		$this->assertArrayHasKey( 'reader.headers', $errors );
	}

	/**
	 * A database reader compiles to the reader the library builds.
	 *
	 * It used to compile to a top-level `database` key the library never
	 * read, so every such rule loaded, reported healthy, and matched nothing.
	 */
	public function test_a_database_reader_compiles_to_the_library_shape(): void {
		$this->given_rule( $this->rule( 'geolocation', $this->database_reader() ) );

		$metadata = $this->compiled_metadata();

		$this->assertSame(
			array(
				'type' => 'reader',
				'db'   => Plugin::instance()->paths()->resolve( 'geoip/GeoLite2-City.mmdb' ),
			),
			$metadata['reader'] ?? null
		);
		$this->assertArrayNotHasKey( 'database', $metadata );
		$this->assertArrayNotHasKey( 'license_key', $metadata, 'Nothing reads it, so the credential stays out of the file.' );
	}

	/**
	 * An edge reader compiles to the header source, named as the library names it.
	 */
	public function test_an_edge_reader_compiles_to_the_header_source(): void {
		$this->given_rule(
			$this->rule(
				'geolocation',
				array(
					'source' => 'edge',
					'edge'   => 'google_cloud',
				) + $this->database_reader()
			)
		);

		$metadata = $this->compiled_metadata();

		$this->assertSame( 'header', $metadata['source'] ?? null );
		$this->assertSame( 'gcp', $metadata['provider'] ?? null );
		$this->assertArrayNotHasKey( 'reader', $metadata );
	}

	/**
	 * The library starts on a custom mapping the screen accepted.
	 */
	public function test_the_library_starts_on_a_custom_mapping(): void {
		$this->given_rule(
			$this->rule(
				'geolocation',
				array(
					'source'  => 'edge',
					'edge'    => 'custom',
					'headers' => array( 'country.name' => 'X-Geo-Name' ),
				) + $this->database_reader()
			)
		);

		$this->assertSame( array( 'country.name' => 'X-Geo-Name' ), $this->compiled_metadata()['headers'] ?? null );

		Firewall::create( array( Plugin::instance()->paths()->compiled_file() ) );

		$this->addToAssertionCount( 1 );
	}

	/**
	 * A reader on a local database, as stored.
	 *
	 * @return array<string, mixed>
	 */
	private function database_reader(): array {
		return array(
			'source'      => 'database',
			'database'    => 'geoip/GeoLite2-City.mmdb',
			'license_key' => 'LICENSE-KEY',
			'edge'        => 'cloudflare',
			'headers'     => array(),
		);
	}

	/**
	 * A rule of a reader-backed type.
	 *
	 * @param string               $type   The rule type.
	 * @param array<string, mixed> $reader Its reader.
	 *
	 * @return array<string, mixed>
	 */
	private function rule( string $type, array $reader ): array {
		return array(
			'id'              => 'geo',
			'type'            => $type,
			'label'           => 'Reader-backed',
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
			'expiration'      => 3600,
			'settings'        => array(
				'match_type' => 'any',
				'sources'    => array(),
				'conditions' => array(
					array(
						'variable' => 'geolocation' === $type ? 'country' : 'asn',
						'operator' => 'equals',
						'value'    => 'geolocation' === $type ? 'XX' : '64496',
					),
				),
				'reader'     => $reader,
			),
		);
	}

	/**
	 * Store one rule, and compile.
	 *
	 * @param array<string, mixed> $rule The rule.
	 */
	private function given_rule( array $rule ): void {
		$this->given_settings( array( 'enabled' => true ) );
		Plugin::instance()->settings()->set( 'rules', array( $rule ) );
		Plugin::instance()->compiled()->rebuild();
	}

	/**
	 * The stored rule's reader.
	 *
	 * @return array<string, mixed>
	 */
	private function stored_reader(): array {
		Plugin::instance()->settings()->flush();

		$rules = (array) Plugin::instance()->settings()->get( 'rules', array() );

		return (array) ( $rules[0]['settings']['reader'] ?? array() );
	}

	/**
	 * The compiled rule's metadata.
	 *
	 * @return array<string, mixed>
	 */
	private function compiled_metadata(): array {
		$compiled = Yaml::parseFile( Plugin::instance()->paths()->compiled_file() );

		return is_array( $compiled ) ? (array) ( $compiled['plugins'][0]['metadata'] ?? array() ) : array();
	}
}
