<?php
/**
 * The challenge pass cookie's name, as set on the Challenge screen (#35).
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Admin\Screen\Challenge_Screen;
use Kanopi\BasicFirewall\Plugin;
use Symfony\Component\Yaml\Yaml;

/**
 * The compiled file names the cookie set on the Challenge screen.
 *
 * Some hosts and edge caches only forward cookies whose names match their own
 * rules, so an admin may need a name other than the default. Whatever the
 * field holds is what the compiled file names and the runner issues.
 *
 * @covers \Kanopi\BasicFirewall\Challenge\Pass_Cookie
 * @covers \Kanopi\BasicFirewall\Compiler\Config_Compiler
 * @covers \Kanopi\BasicFirewall\Compiler\Compiled_Config_Cache
 * @covers \Kanopi\BasicFirewall\Admin\Screen\Challenge_Screen
 */
final class PassCookieNameTest extends Settings_Snapshot {

	/**
	 * A name other than the default.
	 */
	private const CUSTOM = 'STYXKEY_bfw_pass';

	/**
	 * The redirect filter a submission adds, removed afterwards.
	 *
	 * @var callable|null
	 */
	private $redirect_filter = null;

	/**
	 * Remove the redirect filter, and the request globals a submission set.
	 */
	protected function tearDown(): void {
		if ( null !== $this->redirect_filter ) {
			remove_filter( 'wp_redirect', $this->redirect_filter );
		}

		$_POST = array();

		parent::tearDown();
	}

	/**
	 * The compiled name for each stored name.
	 */
	public function test_the_compiled_cookie_name_is_the_stored_one(): void {
		$cases = array(
			'bfw_pass'   => 'bfw_pass',
			self::CUSTOM => self::CUSTOM,
			' my_pass '  => 'my_pass',
			''           => 'bfw_pass',
			'not a name' => 'bfw_pass',
		);

		foreach ( $cases as $stored => $expected ) {
			$this->given_challenge( (string) $stored );

			$label = 'stored "' . $stored . '"';

			$this->assertSame( $expected, $this->compiled()['challenge']['cookie_name'] ?? null, $label . ': the compiled file names the wrong cookie.' );
			$this->assertSame( $expected, Plugin::instance()->compiled()->pass_cookie(), $label . ': the runner would set a different cookie.' );
		}
	}

	/**
	 * The default, with no name stored at all, is still written out explicitly.
	 */
	public function test_the_default_is_written_out(): void {
		$this->given_challenge( null );

		$this->assertStringContainsString( 'cookie_name: bfw_pass', (string) Plugin::instance()->compiled()->contents() );
	}

	/**
	 * The Challenge screen round-trips the field.
	 */
	public function test_the_challenge_screen_round_trips_the_field(): void {
		require_once ABSPATH . 'wp-admin/includes/template.php';

		$this->given_challenge( 'bfw_pass' );
		$this->assertStringContainsString( 'id="cookie_name" value="bfw_pass"', $this->render_screen() );

		$this->submit( self::CUSTOM );

		$this->assertSame( self::CUSTOM, Plugin::instance()->settings()->get( 'challenge.cookie_name' ) );
		$this->assertSame( self::CUSTOM, Plugin::instance()->compiled()->pass_cookie(), 'Saving did not recompile with the new name.' );
		$this->assertStringContainsString( 'id="cookie_name" value="' . self::CUSTOM . '"', $this->render_screen() );
	}

	/**
	 * An empty or malformed name is refused, and nothing is saved.
	 */
	public function test_the_challenge_screen_refuses_an_unusable_name(): void {
		$this->given_challenge( self::CUSTOM );

		foreach ( array( '', '   ', 'has space', 'a;b' ) as $posted ) {
			$this->submit( $posted );

			$this->assertSame( self::CUSTOM, Plugin::instance()->settings()->get( 'challenge.cookie_name' ), '"' . $posted . '" was saved.' );

			$queue = (array) get_transient( 'basic_firewall_notices_' . get_current_user_id() );
			$last  = end( $queue );

			$this->assertIsArray( $last, '"' . $posted . '" was refused without a notice.' );
			$this->assertSame( 'error', $last['type'] );
			$this->assertStringContainsString( 'Nothing was saved', $last['message'] );
		}
	}

	/**
	 * Store a challenge configuration with a secret and a rule, and compile it.
	 *
	 * @param string|null $cookie_name Stored `challenge.cookie_name`; null stores none.
	 */
	private function given_challenge( ?string $cookie_name ): void {
		$challenge = array(
			'provider' => 'math',
			'secret'   => str_repeat( 'pass-cookie-secret-', 2 ),
		);

		if ( null !== $cookie_name ) {
			$challenge['cookie_name'] = $cookie_name;
		}

		$this->given_settings(
			array(
				'challenge' => $challenge,
				'presets'   => array(),
				'rules'     => array(
					array(
						'id'       => 'pass_cookie_challenge',
						'type'     => 'url',
						'label'    => 'Pass cookie challenge',
						'enabled'  => true,
						'response' => 'challenge',
						'settings' => array(
							'match_type' => 'any',
							'conditions' => array(
								array(
									'variable' => 'path',
									'operator' => 'equals',
									'value'    => '/bfw-pass-cookie',
								),
							),
						),
					),
				),
			)
		);

		$result = Plugin::instance()->compiled()->rebuild();

		$this->assertTrue( $result['written'], 'The fixture did not compile.' );
	}

	/**
	 * Post the Challenge screen with the given cookie name.
	 *
	 * @param string $cookie_name Posted `cookie_name`.
	 */
	private function submit( string $cookie_name ): void {
		$admins = get_users(
			array(
				'role'   => 'administrator',
				'number' => 1,
				'fields' => 'ID',
			)
		);

		if ( array() === $admins ) {
			$this->markTestSkipped( 'The site has no administrator to act as.' );
		}

		wp_set_current_user( (int) $admins[0] );
		delete_transient( 'basic_firewall_notices_' . get_current_user_id() );

		$settings = Plugin::instance()->settings();

		$_POST = array(
			'basic_firewall_nonce' => wp_create_nonce( 'basic_firewall_basic-firewall-challenge' ),
			'provider'             => 'math',
			'path'                 => (string) $settings->get( 'challenge.path' ),
			'cookie_name'          => $cookie_name,
			'header_name'          => (string) $settings->get( 'challenge.header_name' ),
			'audience'             => (string) $settings->get( 'challenge.audience' ),
			'ttl'                  => (string) $settings->get( 'challenge.ttl' ),
		);

		if ( null === $this->redirect_filter ) {
			$this->redirect_filter = static function (): void {
				throw new \RuntimeException( 'redirected' );
			};

			add_filter( 'wp_redirect', $this->redirect_filter );
		}

		try {
			( new Challenge_Screen() )->handle();
			$this->fail( 'The screen did not redirect.' );
		} catch ( \RuntimeException $e ) {
			$this->assertSame( 'redirected', $e->getMessage() );
		}
	}

	/**
	 * The compiled file, parsed.
	 *
	 * @return array<string, mixed>
	 */
	private function compiled(): array {
		return (array) Yaml::parse( (string) Plugin::instance()->compiled()->contents() );
	}

	/**
	 * The Challenge screen's markup.
	 */
	private function render_screen(): string {
		ob_start();
		( new Challenge_Screen() )->render();

		return (string) ob_get_clean();
	}
}
