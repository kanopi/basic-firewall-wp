<?php
/**
 * Rule credentials through the rule screen: typed, never shown.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\RuleType\Rule_Type_Base;
use Kanopi\Firewall\Plugins\Url as LibraryUrl;

/**
 * Render, post exactly what was rendered, and the stored key is unchanged and never in the page.
 *
 * The geolocation and ASN license key and the AbuseIPDB API key were rendered
 * into their fields with their values, so they sat in the page source, the
 * browser's form cache and every screenshot. They are now `secret` fields: an
 * empty password input, blank keeps what is stored, a box removes it.
 *
 * @covers \Kanopi\BasicFirewall\Admin\Screen\Rule_Edit_Screen
 * @covers \Kanopi\BasicFirewall\RuleType\Geo_Reader_Settings
 * @covers \Kanopi\BasicFirewall\RuleType\Types\Abuse_Ipdb
 */
final class RuleCredentialFieldsTest extends Settings_Snapshot {

	use Rendered_Rule_Form;

	/**
	 * Recognisable, and with the characters the textarea sanitiser would change.
	 *
	 * No surrounding whitespace: both validators trim a key, deliberately, so
	 * a pasted trailing space does not fail every lookup.
	 */
	private const KEY = 'KEY-7f3a %41<b>x</b>';

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
	 * Each rule type with a credential field, the field's control name and its stored path.
	 *
	 * @return array<string, array{0: string, 1: string, 2: list<string>}>
	 */
	public static function credentials(): array {
		return array(
			'geolocation license key' => array( 'geolocation', 'settings[reader][license_key]', array( 'reader', 'license_key' ) ),
			'ASN license key'         => array( 'asn', 'settings[reader][license_key]', array( 'reader', 'license_key' ) ),
			'AbuseIPDB API key'       => array( 'abuse_ipdb', 'settings[api_key]', array( 'api_key' ) ),
		);
	}

	/**
	 * The field is an empty password input with a box to remove the key, and the key is not in the page.
	 *
	 * @dataProvider credentials
	 *
	 * @param string       $type    Rule type.
	 * @param string       $control Control name.
	 * @param list<string> $path    Where the key is stored in the settings.
	 */
	public function test_the_key_is_not_rendered( string $type, string $control, array $path ): void {
		$this->given_rule( $type );

		$fields = $this->rendered_fields( 'credential' );

		$this->assertSame( '', $fields[ $control ] ?? null, 'The credential field was filled in.' );
		$this->assertStringNotContainsString( 'KEY-7f3a', $this->rendered_html, 'The key is in the page.' );
		$this->assertMatchesRegularExpression( '/<input[^>]+type="password"[^>]+name="' . preg_quote( $control, '/' ) . '"|<input[^>]+name="' . preg_quote( $control, '/' ) . '"[^>]+type="password"/', $this->rendered_html );
		$this->assertStringContainsString( 'name="clear_secret' . substr( $control, strlen( 'settings' ) ) . '"', $this->rendered_html );
		$this->assertSame( self::KEY, $this->stored_key( $path ) );
	}

	/**
	 * Posting back exactly what was rendered leaves the settings as they were.
	 *
	 * @dataProvider credentials
	 *
	 * @param string       $type    Rule type.
	 * @param string       $control Control name.
	 * @param list<string> $path    Where the key is stored in the settings.
	 */
	public function test_saving_as_rendered_keeps_the_key( string $type, string $control, array $path ): void {
		$this->given_rule( $type );

		$before = $this->stored_settings();

		$this->assertTrue( $this->save_as_rendered( 'credential' ), 'The screen refused its own rendering of the rule.' );
		$this->assertSame( $before, $this->stored_settings() );
		$this->assertSame( self::KEY, $this->stored_key( $path ) );

		// And again, from what that save stored.
		$this->assertTrue( $this->save_as_rendered( 'credential' ) );
		$this->assertSame( $before, $this->stored_settings() );
		$this->assertStringNotContainsString( 'KEY-7f3a', $this->rendered_html );
	}

	/**
	 * A key typed into the field replaces the stored one, byte for byte.
	 *
	 * @dataProvider credentials
	 *
	 * @param string       $type    Rule type.
	 * @param string       $control Control name.
	 * @param list<string> $path    Where the key is stored in the settings.
	 */
	public function test_a_typed_key_is_stored_as_typed( string $type, string $control, array $path ): void {
		$this->given_rule( $type );

		$this->assertTrue( $this->save_as_rendered( 'credential', array( $control => '%env(ROTATED_KEY)%' ) ) );
		$this->assertSame( '%env(ROTATED_KEY)%', $this->stored_key( $path ) );
	}

	/**
	 * The box removes a license key, which nothing requires.
	 */
	public function test_the_box_removes_a_license_key(): void {
		$this->given_rule( 'geolocation' );

		$this->assertTrue( $this->save_as_rendered( 'credential', array( 'clear_secret[reader][license_key]' => '1' ) ) );
		$this->assertSame( '', $this->stored_key( array( 'reader', 'license_key' ) ) );
	}

	/**
	 * A contributed type's declared credential is kept off the page even when its presentation forgets to say so.
	 *
	 * The exporter strips what secret_settings() names. A type that declares a
	 * key there and leaves `secret` out of settings_help() had the key
	 * rendered with its value, under a warning that it was a credential.
	 */
	public function test_a_declared_credential_is_secret_without_the_flag(): void {
		$filter = static function ( array $types ): array {
			$types['contributed_keyed'] = new class() extends Rule_Type_Base {

				/**
				 * {@inheritDoc}
				 */
				public function id(): string {
					return 'contributed_keyed';
				}

				/**
				 * {@inheritDoc}
				 */
				public function label(): string {
					return 'Contributed, keyed';
				}

				/**
				 * {@inheritDoc}
				 */
				public function description(): string {
					return 'A contributed type holding a key.';
				}

				/**
				 * {@inheritDoc}
				 */
				public function library_class(): string {
					return LibraryUrl::class;
				}

				/**
				 * {@inheritDoc}
				 */
				public function weight(): int {
					return 500;
				}

				/**
				 * {@inheritDoc}
				 */
				public function default_settings(): array {
					return array( 'service_key' => '' );
				}

				/**
				 * {@inheritDoc}
				 */
				public function secret_settings(): array {
					return array( 'service_key' );
				}

				/**
				 * {@inheritDoc}
				 *
				 * @param array<string, mixed>  $settings Raw settings.
				 * @param array<string, string> $errors   Problems, by reference.
				 */
				public function validate_settings( array $settings, array &$errors ): array {
					return array( 'service_key' => (string) ( $settings['service_key'] ?? '' ) );
				}

				/**
				 * {@inheritDoc}
				 *
				 * @param array<string, mixed> $rule The whole rule.
				 */
				public function compile( array $rule ): array {
					$entry = $this->base_entry( $rule );

					$entry['config'] = array(
						array(
							'variable' => 'path',
							'operator' => 'equals',
							'value'    => '/contributed',
						),
					);

					return $entry;
				}
			};

			return $types;
		};

		add_filter( 'basic_firewall_rule_types', $filter );
		Plugin::instance()->rule_types()->reset();

		try {
			$this->store_rule( 'contributed_keyed', array( 'service_key' => self::KEY ) );

			$fields = $this->rendered_fields( 'credential' );

			$this->assertSame( '', $fields['settings[service_key]'] ?? null, 'The declared credential was filled in.' );
			$this->assertStringNotContainsString( 'KEY-7f3a', $this->rendered_html );

			$this->assertTrue( $this->save_as_rendered( 'credential' ) );
			$this->assertSame( self::KEY, $this->stored_key( array( 'service_key' ) ), 'A blank field cleared the declared credential.' );
		} finally {
			remove_filter( 'basic_firewall_rule_types', $filter );
			Plugin::instance()->rule_types()->reset();
		}
	}

	/**
	 * Store one rule of the type, holding the key.
	 *
	 * @param string $type Rule type.
	 */
	private function given_rule( string $type ): void {
		$settings = Plugin::instance()->rule_types()->get( $type )?->default_settings() ?? array();

		if ( 'abuse_ipdb' === $type ) {
			$settings['api_key'] = self::KEY;
		} else {
			$settings['reader']['database']    = 'geoip/' . ( 'asn' === $type ? 'GeoLite2-ASN' : 'GeoLite2-City' ) . '.mmdb';
			$settings['reader']['license_key'] = self::KEY;
		}

		if ( 'abuse_ipdb' !== $type ) {
			$settings['conditions'] = array(
				array(
					'variable' => 'asn' === $type ? 'asn' : 'country.iso_code',
					'operator' => 'equals',
					'value'    => 'asn' === $type ? '64500' : 'ZZ',
					'negate'   => false,
				),
			);
		}

		$this->store_rule( $type, $settings );

		$this->assertSame( self::KEY, $this->stored_key( 'abuse_ipdb' === $type ? array( 'api_key' ) : array( 'reader', 'license_key' ) ), 'The fixture did not store the key as given.' );
	}

	/**
	 * Store the one rule under test and compile it.
	 *
	 * @param string               $type     Rule type.
	 * @param array<string, mixed> $settings Its settings.
	 */
	private function store_rule( string $type, array $settings ): void {
		Plugin::instance()->settings()->set(
			'rules',
			array(
				array(
					'id'              => 'credential',
					'type'            => $type,
					'label'           => 'Credential',
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
					'description'     => '',
					'settings'        => $settings,
				),
			)
		);
		Plugin::instance()->compiled()->rebuild();
	}

	/**
	 * The stored rule's settings.
	 *
	 * @return array<string, mixed>
	 */
	private function stored_settings(): array {
		Plugin::instance()->settings()->flush();

		$rules = (array) Plugin::instance()->settings()->get( 'rules', array() );

		return (array) ( $rules[0]['settings'] ?? array() );
	}

	/**
	 * The stored key.
	 *
	 * @param list<string> $path Where it is in the settings.
	 */
	private function stored_key( array $path ): ?string {
		$node = $this->stored_settings();

		foreach ( $path as $segment ) {
			if ( ! is_array( $node ) || ! array_key_exists( $segment, $node ) ) {
				return null;
			}

			$node = $node[ $segment ];
		}

		return is_string( $node ) ? $node : null;
	}
}
