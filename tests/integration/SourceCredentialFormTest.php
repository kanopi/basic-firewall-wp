<?php
/**
 * A referenced list's credentials, through the rule screen.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\RuleType\Types\Ip_Address;
use Kanopi\BasicFirewall\Transfer\Secret_Paths;

/**
 * The advanced block shows `[redacted]` for a stored credential, and a save keeps it.
 *
 * The block is YAML in a textarea, and it rendered a list's bearer token and
 * every request header value as stored -- into the page source, the form
 * cache and any screenshot -- although the exporter strips exactly those.
 *
 * @covers \Kanopi\BasicFirewall\Admin\Screen\Rule_Edit_Screen
 */
final class SourceCredentialFormTest extends Settings_Snapshot {

	use Rendered_Rule_Form;

	private const TOKEN  = 'FEED-TOKEN-91c2';
	private const HEADER = 'FEED-HEADER-5e07';

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
	 * The literal credentials are masked; a token and the header names are shown.
	 */
	public function test_the_advanced_block_masks_literal_credentials(): void {
		$this->given_feed();

		$fields   = $this->rendered_fields( 'feed' );
		$advanced = (string) ( $fields['settings[sources][0][advanced]'] ?? '' );

		$this->assertStringNotContainsString( self::TOKEN, $this->rendered_html, 'The feed token is in the page.' );
		$this->assertStringNotContainsString( self::HEADER, $this->rendered_html, 'The header value is in the page.' );
		$this->assertStringContainsString( Secret_Paths::REDACTED, $advanced );
		$this->assertStringContainsString( 'X-Api-Key', $advanced, 'The header name should stay readable.' );
		$this->assertStringContainsString( '%env(FEED_TRACE)%', $advanced, 'A token is a reference, and is shown.' );
		$this->assertStringContainsString( 'bearer', $advanced );
	}

	/**
	 * Posting back exactly what was rendered stores exactly what was there.
	 */
	public function test_saving_as_rendered_keeps_the_credentials(): void {
		$this->given_feed();

		$before = $this->stored_source();

		$this->assertTrue( $this->save_as_rendered( 'feed' ), 'The screen refused its own rendering of the rule.' );
		$this->assertSame( $before['advanced'], $this->stored_source()['advanced'] );
		$this->assertSame( self::TOKEN, $this->stored_source()['advanced']['upstream']['auth']['token'] ?? null );

		$this->assertTrue( $this->save_as_rendered( 'feed' ) );
		$this->assertSame( $before['advanced'], $this->stored_source()['advanced'] );
	}

	/**
	 * A placeholder does not carry a credential to a list at another URL.
	 */
	public function test_a_changed_url_does_not_keep_the_credential(): void {
		$this->given_feed();

		$this->assertFalse(
			$this->save_as_rendered( 'feed', array( 'settings[sources][0][url]' => 'https://elsewhere.example.test/list.txt' ) ),
			'The save went through with a placeholder and no credential for it.'
		);
		$this->assertSame( self::TOKEN, $this->stored_source()['advanced']['upstream']['auth']['token'] ?? null, 'The stored rule changed.' );
		$this->assertSame( 'https://feeds.example.test/list.txt', $this->stored_source()['url'] ?? null );
	}

	/**
	 * A credential typed over the placeholder is stored.
	 */
	public function test_a_typed_credential_replaces_the_placeholder(): void {
		$this->given_feed();

		$fields   = $this->rendered_fields( 'feed' );
		$advanced = str_replace(
			Secret_Paths::REDACTED,
			'%env(ROTATED)%',
			(string) $fields['settings[sources][0][advanced]']
		);

		$this->assertTrue( $this->save_as_rendered( 'feed', array( 'settings[sources][0][advanced]' => $advanced ) ) );
		$this->assertSame( '%env(ROTATED)%', $this->stored_source()['advanced']['upstream']['auth']['token'] ?? null );
		$this->assertSame( '%env(ROTATED)%', $this->stored_source()['advanced']['upstream']['headers']['X-Api-Key'] ?? null );
	}

	/**
	 * Store an IP address rule referencing a list behind a credential.
	 */
	private function given_feed(): void {
		$type   = Plugin::instance()->rule_types()->get( 'ip_address' );
		$errors = array();

		$this->assertNotNull( $type );

		$settings = $type->validate_settings(
			array(
				'addresses' => array(),
				'sources'   => array(
					array_merge(
						Ip_Address::source_defaults(),
						array(
							'name'     => 'feed',
							'url'      => 'https://feeds.example.test/list.txt',
							'format'   => 'txt',
							'advanced' => array(
								'upstream' => array(
									'auth'    => array(
										'type'  => 'bearer',
										'token' => self::TOKEN,
									),
									'headers' => array(
										'X-Api-Key' => self::HEADER,
										'X-Trace'   => '%env(FEED_TRACE)%',
									),
								),
							),
						)
					),
				),
			),
			$errors
		);

		$this->assertSame( array(), $errors );

		Plugin::instance()->settings()->set(
			'rules',
			array(
				array(
					'id'              => 'feed',
					'type'            => 'ip_address',
					'label'           => 'Feed',
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
	 * The stored rule's only list.
	 *
	 * @return array<string, mixed>
	 */
	private function stored_source(): array {
		Plugin::instance()->settings()->flush();

		$rules = (array) Plugin::instance()->settings()->get( 'rules', array() );

		return (array) ( $rules[0]['settings']['sources'][0] ?? array() );
	}
}
