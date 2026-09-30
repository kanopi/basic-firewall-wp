<?php
/**
 * Saving a screen unchanged stores what was there.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Admin\Screen\Logging_Screen;
use Kanopi\BasicFirewall\Admin\Screen\Storage_Screen;
use Kanopi\BasicFirewall\Plugin;

/**
 * Render a screen, post exactly what it rendered, and compare what is stored.
 *
 * The failure each of these guards against is the same one: a screen that
 * saves a whole section of the settings from its own fields, and does not
 * render one of them. Its next save -- of anything on that screen, by somebody
 * who changed nothing -- replaces the stored value with the handler's default.
 *
 * @covers \Kanopi\BasicFirewall\Admin\Screen\Rule_Edit_Screen
 * @covers \Kanopi\BasicFirewall\Admin\Screen\Logging_Screen
 * @covers \Kanopi\BasicFirewall\Admin\Screen\Storage_Screen
 */
final class ScreenRoundTripTest extends Settings_Snapshot {

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

		// Screens close their forms with submit_button(), which only admin
		// requests load.
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
	 * A regular expression on a path keeps its slashes through the rule screen.
	 *
	 * `/wp-admin/` was stored as `wp-admin` on save, widening the rule to
	 * every path containing those letters.
	 */
	public function test_a_regex_rule_saves_unchanged(): void {
		$conditions = array(
			array(
				'variable'       => 'path',
				'operator'       => 'regex',
				'value'          => '/wp-admin/',
				'negate'         => false,
				'case_sensitive' => false,
			),
			array(
				'variable'       => 'header.user-agent',
				'operator'       => 'regex',
				'value'          => '(sqlmap|nikto)',
				'negate'         => true,
				'case_sensitive' => true,
			),
		);

		$this->given_settings( array( 'enabled' => true ) );
		Plugin::instance()->settings()->set(
			'rules',
			array(
				array(
					'id'       => 'paths',
					'type'     => 'url',
					'label'    => 'Paths',
					'enabled'  => true,
					'response' => 'block',
					'settings' => array(
						'match_type' => 'all',
						'conditions' => $conditions,
						'sources'    => array(),
					),
				),
			)
		);

		for ( $save = 0; $save < 2; $save++ ) {
			$this->assertTrue( $this->save_as_rendered( 'paths' ), 'The screen refused its own rendering of the rule.' );

			Plugin::instance()->settings()->flush();

			$rules = (array) Plugin::instance()->settings()->get( 'rules', array() );

			$this->assertSame( $conditions, $rules[0]['settings']['conditions'] );
		}
	}

	/**
	 * A vulnerability score rule saves through its screen unchanged.
	 *
	 * Every field is a textarea or a text box over a structure -- levels and
	 * patterns as lists of maps, scores as maps, a network number as an
	 * integer key -- so each is rendered as the lines its validator reads,
	 * and an untouched save has to store exactly what was there.
	 */
	public function test_a_vulnerability_score_rule_saves_unchanged(): void {
		$type     = Plugin::instance()->rule_types()->get( 'vulnerability_score' );
		$settings = $type->default_settings();

		$settings['risk_levels'][]           = array(
			'name'            => 'fractional',
			'threshold'       => 97.5,
			'block'           => true,
			'status_code'     => 429,
			'expiration_time' => 0,
		);
		$settings['scoring']['countries']    = array(
			'CN' => 30,
			'US' => -5,
		);
		$settings['scoring']['asn']          = array(
			4134  => 30,
			13335 => -40,
		);
		$settings['scoring']['asn_patterns'] = array(
			'hosting' => 15,
			'vpn'     => 2.5,
		);
		$settings['databases']               = array(
			'country' => 'geoip/GeoLite2-Country.mmdb',
			'asn'     => '/srv/geoip/GeoLite2-ASN.mmdb',
		);

		$errors = array();

		$this->assertSame( $settings, $type->validate_settings( $settings, $errors ), 'The settings under test do not validate to themselves.' );

		$this->given_settings( array( 'enabled' => true ) );
		Plugin::instance()->settings()->set(
			'rules',
			array(
				array(
					'id'       => 'score',
					'type'     => 'vulnerability_score',
					'label'    => 'Score',
					'enabled'  => true,
					'response' => 'block',
					'settings' => $settings,
				),
			)
		);

		for ( $save = 0; $save < 2; $save++ ) {
			$this->assertTrue( $this->save_as_rendered( 'score' ), 'The screen refused its own rendering of the rule.' );

			Plugin::instance()->settings()->flush();

			$rules = (array) Plugin::instance()->settings()->get( 'rules', array() );

			$this->assertSame( $settings, $rules[0]['settings'] );
		}
	}

	/**
	 * Database log handlers keep where they connect through the Logging screen.
	 *
	 * The screen rebuilt every handler from the fields it rendered, and it
	 * rendered no connection: an imported handler writing to another database
	 * came back from an unchanged save pointed at WordPress's, its DSN or
	 * parameters gone.
	 */
	public function test_the_logging_screen_saves_unchanged(): void {
		$handlers = array(
			array(
				'type'      => 'rotating_file',
				'enabled'   => true,
				'level'     => 'warning',
				'path'      => 'logs/firewall.log',
				'max_files' => 7,
			),
			array(
				'type'              => 'database',
				'enabled'           => true,
				'level'             => 'notice',
				'table'             => 'remote_firewall_log',
				'connection_source' => 'dsn',
				'dsn'               => '%env(FIREWALL_LOG_DSN)%',
				'retain_days'       => 14,
				'buffered'          => true,
				'deferred'          => true,
			),
			array(
				'type'              => 'database',
				'enabled'           => false,
				'level'             => 'info',
				'table'             => 'other_log',
				'connection_source' => 'parameters',
				'parameters'        => array(
					'driver'   => 'mysqli',
					'host'     => 'logs.internal',
					'port'     => 3307,
					'dbname'   => 'logs',
					'user'     => 'firewall',
					'password' => '%env(LOG_DB_PASSWORD)%',
				),
			),
		);

		$this->given_settings( array( 'logger' => $handlers ) );

		$before = Plugin::instance()->settings()->get( 'logger' );

		$this->assertTrue( $this->save_screen_as_rendered( new Logging_Screen() ), 'The Logging screen did not save.' );
		$this->assertStringNotContainsString( 'FIREWALL_LOG_DSN', $this->rendered_html, 'A stored DSN was printed into the page.' );
		$this->assertStringNotContainsString( 'LOG_DB_PASSWORD', $this->rendered_html, 'A stored password was printed into the page.' );

		Plugin::instance()->settings()->flush();

		$this->assertSame( $before, Plugin::instance()->settings()->get( 'logger' ) );
	}

	/**
	 * A stored log credential goes when what it belongs with changes, or on request.
	 */
	public function test_a_log_credential_is_kept_only_where_it_belongs(): void {
		$this->given_settings(
			array(
				'logger' => array(
					array(
						'type'              => 'database',
						'table'             => 'remote_firewall_log',
						'connection_source' => 'dsn',
						'dsn'               => '%env(FIREWALL_LOG_DSN)%',
					),
					array(
						'type'              => 'database',
						'table'             => 'other_log',
						'connection_source' => 'parameters',
						'parameters'        => array(
							'driver'   => 'mysqli',
							'host'     => 'logs.internal',
							'dbname'   => 'logs',
							'user'     => 'firewall',
							'password' => '%env(LOG_DB_PASSWORD)%',
						),
					),
				),
			)
		);

		$this->assertTrue(
			$this->save_screen_as_rendered(
				new Logging_Screen(),
				array(),
				array(
					'handlers[0][table]'            => 'renamed_log',
					'handlers[1][parameters][host]' => 'elsewhere.internal',
				)
			)
		);

		Plugin::instance()->settings()->flush();

		$logger = (array) Plugin::instance()->settings()->get( 'logger' );

		$this->assertSame( '', $logger[0]['dsn'], 'A DSN followed its handler to a different table.' );
		$this->assertSame( '', $logger[1]['parameters']['password'], 'A password followed its connection to a different host.' );
	}

	/**
	 * Database block list storage keeps its connection through the Storage screen.
	 *
	 * `parameters` was not among the choices, so a document imported with it
	 * rendered the select on its first option, and the next save moved the
	 * block list to the WordPress database.
	 *
	 * @dataProvider storage_connections
	 *
	 * @param array<string, mixed> $database The stored database storage settings.
	 */
	public function test_the_storage_screen_saves_unchanged( array $database ): void {
		$this->given_settings(
			array(
				'storage' => array(
					'backend'  => 'database',
					'database' => $database,
				),
			)
		);

		$before = Plugin::instance()->settings()->get( 'storage' );

		$this->assertTrue( $this->save_screen_as_rendered( new Storage_Screen() ), 'The Storage screen did not save.' );
		$this->assertStringNotContainsString( 'STORAGE_DB_PASSWORD', $this->rendered_html, 'A stored password was printed into the page.' );
		$this->assertStringNotContainsString( 'STORAGE_DSN', $this->rendered_html, 'A stored DSN was printed into the page.' );

		Plugin::instance()->settings()->flush();

		$this->assertSame( $before, Plugin::instance()->settings()->get( 'storage' ) );
	}

	/**
	 * Each way database storage connects.
	 *
	 * @return array<string, array{0: array<string, mixed>}>
	 */
	public static function storage_connections(): array {
		return array(
			'individual parameters' => array(
				array(
					'storage_table'     => 'remote_blocked',
					'offenses_table'    => 'remote_offenses',
					'connection_source' => 'parameters',
					'parameters'        => array(
						'driver'   => 'pdo_pgsql',
						'host'     => 'db.internal',
						'port'     => 5432,
						'dbname'   => 'firewall',
						'user'     => 'firewall',
						'password' => '%env(STORAGE_DB_PASSWORD)%',
					),
				),
			),
			'a DSN'                 => array(
				array(
					'connection_source' => 'dsn',
					'dsn'               => '%env(STORAGE_DSN)%',
				),
			),
			'a preset'              => array(
				array( 'connection_source' => 'preset' ),
			),
		);
	}
}
