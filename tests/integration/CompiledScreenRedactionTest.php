<?php
/**
 * The Compiled screen shows the compiled file without its credentials.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Admin\Screen\Compiled_Screen;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Transfer\Secret_Paths;

/**
 * The file holds every credential the library needs; the screen shows none.
 *
 * The Compiled screen printed the file as it was, so the challenge signing
 * secret, a CAPTCHA secret key, a Redis password, an AbuseIPDB key and a paid
 * list's token were one screenshot away from a ticket.
 *
 * @covers \Kanopi\BasicFirewall\Admin\Screen\Compiled_Screen
 * @covers \Kanopi\BasicFirewall\Compiler\Compiled_Config_Cache
 * @covers \Kanopi\BasicFirewall\Transfer\Secret_Paths
 */
final class CompiledScreenRedactionTest extends Settings_Snapshot {

	private const SECRETS = array(
		'challenge'  => 'SECRET-challenge-signing-must-not-show',
		'turnstile'  => 'SECRET-turnstile-key-must-not-show',
		'abuseipdb'  => 'SECRET-abuseipdb-key-must-not-show',
		'rate_redis' => 'SECRET-rate-limit-redis-must-not-show',
		'feed'       => 'SECRET-feed-token-must-not-show',
		'header'     => 'SECRET-feed-header-must-not-show',
		'url'        => 'SECRET-url-password-must-not-show',
	);

	/**
	 * The current user, put back afterwards.
	 *
	 * @var int
	 */
	private int $user = 0;

	/**
	 * Remember the user.
	 */
	protected function setUp(): void {
		parent::setUp();

		$this->user = get_current_user_id();
	}

	/**
	 * Put the user back.
	 */
	protected function tearDown(): void {
		wp_set_current_user( $this->user );

		parent::tearDown();
	}

	/**
	 * No credential reaches the screen, and the file still has what the library reads.
	 */
	public function test_the_screen_shows_no_credential(): void {
		$this->given_settings( $this->settings() );

		$rebuild = Plugin::instance()->compiled()->rebuild();

		$this->assertTrue( $rebuild['written'], implode( ' ', $rebuild['problems'] ) );

		$file = (string) Plugin::instance()->compiled()->contents();

		// The control: without it, a compiler that dropped them would pass.
		$this->assertStringContainsString( self::SECRETS['challenge'], $file );
		$this->assertStringContainsString( self::SECRETS['turnstile'], $file );
		$this->assertStringContainsString( self::SECRETS['abuseipdb'], $file );
		$this->assertStringContainsString( self::SECRETS['feed'], $file );

		$html = $this->render();

		foreach ( self::SECRETS as $name => $secret ) {
			$this->assertStringNotContainsString( $secret, $html, sprintf( 'The %s credential is shown on the Compiled screen.', $name ) );
		}

		$this->assertStringContainsString( Secret_Paths::REDACTED, $html );

		// And what is not a credential is still there to read.
		$this->assertStringContainsString( 'PUBLIC-site-key', $html );
		$this->assertStringContainsString( 'feeds.example.com', $html );
		$this->assertStringContainsString( 'reputation', $html );
	}

	/**
	 * An environment token names a variable; it is shown as it is.
	 */
	public function test_a_token_is_shown(): void {
		$settings                        = $this->settings();
		$settings['challenge']['secret'] = '%env(FIREWALL_CHALLENGE_SECRET)%';
		$settings['rules']               = array( $settings['rules'][0] );

		$this->given_settings( $settings );

		Plugin::instance()->compiled()->rebuild();

		$this->assertStringContainsString( '%env(FIREWALL_CHALLENGE_SECRET)%', $this->render() );
	}

	/**
	 * Render the screen as an administrator.
	 */
	private function render(): string {
		$admins = get_users(
			array(
				'role'   => 'administrator',
				'number' => 1,
				'fields' => 'ID',
			)
		);

		if ( array() === $admins ) {
			$this->markTestSkipped( 'This site has no administrator to act as.' );
		}

		wp_set_current_user( (int) $admins[0] );

		require_once ABSPATH . 'wp-admin/includes/template.php';

		ob_start();
		( new Compiled_Screen() )->render();

		return (string) ob_get_clean();
	}

	/**
	 * Settings holding one of each credential the compiled file can carry.
	 *
	 * @return array<string, mixed>
	 */
	private function settings(): array {
		return array(
			'enabled'   => true,
			'challenge' => array(
				'provider'         => 'turnstile',
				'secret'           => self::SECRETS['challenge'],
				'provider_options' => array(
					'turnstile' => array(
						'site_key'   => 'PUBLIC-site-key',
						'secret_key' => self::SECRETS['turnstile'],
					),
				),
			),
			'rules'     => array(
				array(
					'id'       => 'challenged',
					'type'     => 'url',
					'label'    => 'Challenged',
					'enabled'  => true,
					'response' => 'challenge',
					'weight'   => 40,
					'settings' => array(
						'match_type' => 'any',
						'conditions' => array(
							array(
								'variable' => 'path',
								'operator' => 'equals',
								'value'    => '/challenge-me',
							),
						),
					),
				),
				array(
					'id'       => 'reputation',
					'type'     => 'abuse_ipdb',
					'label'    => 'Reputation',
					'enabled'  => true,
					'response' => 'block',
					'weight'   => 20,
					'settings' => array(
						'threshold' => 75,
						'api_key'   => self::SECRETS['abuseipdb'],
					),
				),
				array(
					'id'       => 'login-limit',
					'type'     => 'rate_limit',
					'label'    => 'Login',
					'enabled'  => true,
					'response' => 'block',
					'weight'   => 30,
					'settings' => array(
						'paths'   => array( '/wp-login.php 20 60' ),
						'storage' => array(
							'backend'        => 'redis',
							'redis_host'     => '127.0.0.1',
							'redis_password' => self::SECRETS['rate_redis'],
						),
					),
				),
				array(
					'id'       => 'feed',
					'type'     => 'ip_address',
					'label'    => 'Feed',
					'enabled'  => true,
					'response' => 'block',
					'weight'   => 10,
					'settings' => array(
						'addresses' => array( '198.51.100.1' ),
						'sources'   => array(
							array(
								'url'      => 'https://feeds.example.com/bad.txt',
								'advanced' => array(
									'upstream' => array(
										'auth'    => array(
											'type'  => 'bearer',
											'token' => self::SECRETS['feed'],
										),
										'headers' => array( 'X-Api-Key' => self::SECRETS['header'] ),
									),
								),
							),
							array( 'url' => 'https://reader:' . self::SECRETS['url'] . '@feeds.example.com/allow.txt' ),
						),
					),
				),
			),
		);
	}
}
