<?php
/**
 * A rate limit's limits and storage, through the rule screen.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Plugin;

/**
 * Render, post what was rendered, store, render again: nothing changes, and the password never shows.
 *
 * The generic settings renderer had no control for either of a rate limit's
 * structured settings. Each limit is stored as a map, so the limits textarea
 * printed "Array" once per limit, with a PHP warning each, and saving the rule
 * untouched was refused for having no limits. The storage map was a textarea
 * of `key: value` lines with the Redis password among them in clear; it posted
 * back as a string, the validator reset the storage to a file, and the
 * password was gone.
 *
 * @covers \Kanopi\BasicFirewall\Admin\Screen\Rule_Edit_Screen
 * @covers \Kanopi\BasicFirewall\RuleType\Types\Rate_Limit
 */
final class RateLimitSettingsTest extends Settings_Snapshot {

	use Rendered_Rule_Form;

	/**
	 * Recognisable, and with the characters the textarea sanitiser would change.
	 */
	private const PASSWORD = 'SECRET-redis %41<b>pass</b> ';

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
	 * The limits are lines, the storage is fields, and the password is not on the page.
	 */
	public function test_the_screen_renders_limits_and_storage_without_the_password(): void {
		$this->given_rule( $this->settings() );

		$fields = $this->rendered_fields( 'login-limit' );

		$this->assertSame( "/wp-login.php 5 300\n/xmlrpc.php 10 60 client_ip,header.x-api-key\n/search 30 60 client_ip,query_count.Facet", $fields['settings[paths]'] ?? null );
		$this->assertSame( 'redis', $fields['settings[storage][backend]'] ?? null );
		$this->assertSame( '10.0.0.5', $fields['settings[storage][redis_host]'] ?? null );
		$this->assertSame( '6380', $fields['settings[storage][redis_port]'] ?? null );
		$this->assertSame( '', $fields['settings[storage][redis_password]'] ?? null, 'The password field was filled in.' );
		$this->assertArrayNotHasKey( 'settings[storage]', $fields, 'The storage map is still one textarea.' );

		$this->assertStringNotContainsString( 'SECRET-redis', $this->rendered_html, 'The Redis password is in the page.' );
		$this->assertStringNotContainsString( 'Array', $this->rendered_html );
		$this->assertStringContainsString( 'name="clear_secret[storage][redis_password]"', $this->rendered_html );
	}

	/**
	 * Posting back exactly what was rendered stores exactly what was there.
	 */
	public function test_saving_as_rendered_changes_nothing(): void {
		$this->given_rule( $this->settings() );

		$before = $this->stored_settings();

		$this->assertTrue( $this->save_as_rendered( 'login-limit' ), 'The screen refused its own rendering of the rule.' );
		$this->assertSame( $before, $this->stored_settings() );
		$this->assertSame( self::PASSWORD, $this->stored_settings()['storage']['redis_password'] );

		// And again, from what that save stored.
		$this->assertTrue( $this->save_as_rendered( 'login-limit' ) );
		$this->assertSame( $before, $this->stored_settings() );
	}

	/**
	 * A password typed into the field replaces the stored one, exactly as typed.
	 */
	public function test_a_typed_password_is_stored_as_typed(): void {
		$this->given_rule( $this->settings() );

		$this->assertTrue( $this->save_as_rendered( 'login-limit', array( 'settings[storage][redis_password]' => ' NEW %20 <pass> ' ) ) );
		$this->assertSame( ' NEW %20 <pass> ', $this->stored_settings()['storage']['redis_password'] );
	}

	/**
	 * The box removes the stored password.
	 */
	public function test_the_box_removes_the_stored_password(): void {
		$this->given_rule( $this->settings() );

		$this->assertTrue( $this->save_as_rendered( 'login-limit', array( 'clear_secret[storage][redis_password]' => '1' ) ) );
		$this->assertSame( '', $this->stored_settings()['storage']['redis_password'] );
	}

	/**
	 * A DSN carries its password, so it is handled the same way.
	 */
	public function test_a_dsn_is_not_shown_and_survives_a_save(): void {
		$settings            = $this->settings();
		$settings['storage'] = array(
			'backend'           => 'database',
			'connection_source' => 'dsn',
			'dsn'               => 'mysql://firewall:SECRET-dsn-password@db.internal/counters',
			'table'             => 'counters',
		) + $settings['storage'];

		$this->given_rule( $settings );

		$before = $this->stored_settings();

		$this->assertSame( '', $this->rendered_fields( 'login-limit' )['settings[storage][dsn]'] ?? null );
		$this->assertStringNotContainsString( 'SECRET-dsn-password', $this->rendered_html );

		$this->assertTrue( $this->save_as_rendered( 'login-limit' ) );
		$this->assertSame( $before, $this->stored_settings() );
	}

	/**
	 * A new rate limit rule renders and saves with its defaults.
	 */
	public function test_a_new_rule_saves_with_its_defaults(): void {
		$this->given_settings( array( 'enabled' => true ) );

		$this->as_administrator();

		$_GET = array( 'type' => 'rate_limit' );

		ob_start();
		( new \Kanopi\BasicFirewall\Admin\Screen\Rule_Edit_Screen() )->render();
		$html = (string) ob_get_clean();

		$this->assertStringContainsString( 'name="settings[storage][backend]"', $html );
		$this->assertStringNotContainsString( 'clear_secret', $html, 'There is nothing stored to remove.' );
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
	 * Store one rate limit rule, through its own validator, and compile.
	 *
	 * @param array<string, mixed> $settings Its settings.
	 */
	private function given_rule( array $settings ): void {
		$type   = Plugin::instance()->rule_types()->get( 'rate_limit' );
		$errors = array();

		$this->assertNotNull( $type );

		$settings = $type->validate_settings( $settings, $errors );

		$this->assertSame( array(), $errors );

		$this->given_settings( array( 'enabled' => true ) );
		Plugin::instance()->settings()->set(
			'rules',
			array(
				array(
					'id'              => 'login-limit',
					'type'            => 'rate_limit',
					'label'           => 'Login',
					'enabled'         => true,
					'observe'         => false,
					'response'        => 'block',
					'weight'          => -20,
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
	 * Two limits, one keyed, counted in Redis behind a password.
	 *
	 * @return array<string, mixed>
	 */
	private function settings(): array {
		return array(
			'paths'                => "/wp-login.php 5 300\n/xmlrpc.php 10 60 client_ip,header.x-api-key\n/search 30 60 client_ip,query_count.Facet",
			'default_limit'        => 120,
			'default_window'       => 30,
			'limit_unlisted_paths' => false,
			'storage'              => array(
				'backend'        => 'redis',
				'file'           => 'ratelimit.data',
				'redis_host'     => '10.0.0.5',
				'redis_port'     => 6380,
				'redis_password' => self::PASSWORD,
				'key_prefix'     => 'site-a:',
			),
		);
	}
}
