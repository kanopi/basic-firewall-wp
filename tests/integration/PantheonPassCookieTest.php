<?php
/**
 * The challenge pass cookie on Pantheon (#35).
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Admin\Screen\Challenge_Screen;
use Kanopi\BasicFirewall\Health\Site_Health;
use Kanopi\BasicFirewall\Plugin;
use Symfony\Component\Yaml\Yaml;

// phpcs:disable WordPress.PHP.DiscouragedPHPFunctions.runtime_configuration_putenv -- simulating Pantheon's environment is the point, and tearDown() clears it.

/**
 * On Pantheon a pass cookie nobody chose compiles as STYXKEY_bfw_pass.
 *
 * Pantheon's CDN strips request cookies that match none of its pass-through
 * patterns, and `bfw_pass` matches none, so a solved challenge was challenged
 * again forever. PANTHEON_ENVIRONMENT is simulated the way Pantheon sets it:
 * in the process environment, where the compiler (running in this process)
 * reads it.
 *
 * @covers \Kanopi\BasicFirewall\Challenge\Pass_Cookie
 * @covers \Kanopi\BasicFirewall\Compiler\Config_Compiler
 * @covers \Kanopi\BasicFirewall\Compiler\Compiled_Config_Cache
 * @covers \Kanopi\BasicFirewall\Health\Site_Health
 */
final class PantheonPassCookieTest extends Settings_Snapshot {

	/**
	 * Undo the simulation before the parent rebuilds the compiled file.
	 */
	protected function tearDown(): void {
		putenv( 'PANTHEON_ENVIRONMENT' );

		parent::tearDown();
	}

	/**
	 * The compiled name for each stored name, on and off Pantheon.
	 */
	public function test_the_compiled_cookie_name(): void {
		$cases = array(
			array( false, '', 'bfw_pass' ),
			array( false, 'bfw_pass', 'bfw_pass' ),
			array( false, 'my_pass', 'my_pass' ),
			array( true, '', 'STYXKEY_bfw_pass' ),
			array( true, 'bfw_pass', 'STYXKEY_bfw_pass' ),
			array( true, 'my_pass', 'my_pass' ),
			array( true, 'STYXKEY_mine', 'STYXKEY_mine' ),
		);

		foreach ( $cases as $case ) {
			list( $pantheon, $stored, $expected ) = $case;

			putenv( $pantheon ? 'PANTHEON_ENVIRONMENT=live' : 'PANTHEON_ENVIRONMENT' );

			$this->given_challenge( $stored );

			$label = ( $pantheon ? 'on Pantheon' : 'off Pantheon' ) . ', stored "' . $stored . '"';

			$this->assertSame( $expected, $this->compiled()['challenge']['cookie_name'] ?? null, $label . ': the compiled file names the wrong cookie.' );
			$this->assertSame( $expected, Plugin::instance()->compiled()->pass_cookie(), $label . ': the runner would set a different cookie.' );
		}
	}

	/**
	 * The name a solved challenge is issued in follows the compile, not the environment.
	 *
	 * Compiled on Pantheon, then read where PANTHEON_ENVIRONMENT is missing --
	 * a CLI or a pool that does not pass the environment through. The runner
	 * still issues the name the library reads.
	 */
	public function test_the_issued_name_follows_the_compile(): void {
		putenv( 'PANTHEON_ENVIRONMENT=dev' );
		$this->given_challenge( '' );
		putenv( 'PANTHEON_ENVIRONMENT' );

		$this->assertSame( 'STYXKEY_bfw_pass', Plugin::instance()->compiled()->pass_cookie() );
	}

	/**
	 * Site Health: off Pantheon, forwarded, and stripped with and without challenges.
	 */
	public function test_site_health(): void {
		$this->given_challenge( 'my_pass' );
		$this->assertSame( 'good', Site_Health::check( 'pass_cookie' )['status'], 'Off Pantheon the check should only inform.' );

		putenv( 'PANTHEON_ENVIRONMENT=dev' );

		$this->given_challenge( '' );
		$this->assertSame( 'good', Site_Health::check( 'pass_cookie' )['status'], 'The Pantheon default was reported as stripped.' );

		$this->given_challenge( 'my_pass' );
		$result = Site_Health::check( 'pass_cookie' );
		$this->assertSame( 'critical', $result['status'], 'A stripped pass cookie with a challenge rule enabled was not critical.' );
		$this->assertStringContainsString( 'my_pass', $result['description'] );

		$this->given_challenge( 'my_pass', false );
		$this->assertSame( 'recommended', Site_Health::check( 'pass_cookie' )['status'], 'With nothing challenging, a stripped name is a recommendation.' );

		$this->assertArrayHasKey( 'pass_cookie', Site_Health::results() );
	}

	/**
	 * The Challenge screen names the cookie in use, and why.
	 */
	public function test_the_challenge_screen_names_the_effective_cookie(): void {
		require_once ABSPATH . 'wp-admin/includes/template.php';

		putenv( 'PANTHEON_ENVIRONMENT=dev' );
		$this->given_challenge( '' );

		$rendered = $this->render_screen();

		$this->assertStringContainsString( 'placeholder="STYXKEY_bfw_pass"', $rendered );
		$this->assertStringContainsString( 'id="cookie_name" value=""', $rendered, 'A name nobody chose was shown as though somebody had.' );
		$this->assertStringContainsString( 'On Pantheon, defaults to', $rendered );

		$this->given_challenge( 'my_pass' );
		$rendered = $this->render_screen();

		$this->assertStringContainsString( 'id="cookie_name" value="my_pass"', $rendered );
		$this->assertStringContainsString( 'Pantheon will strip this cookie', $rendered );
	}

	/**
	 * Store a challenge configuration with a secret, and compile it.
	 *
	 * @param string $cookie_name Stored `challenge.cookie_name`.
	 * @param bool   $rule        Whether an enabled challenge rule exists.
	 */
	private function given_challenge( string $cookie_name, bool $rule = true ): void {
		$this->given_settings(
			array(
				'challenge' => array(
					'provider'    => 'math',
					'secret'      => str_repeat( 'pantheon-cookie-secret-', 2 ),
					'cookie_name' => $cookie_name,
				),
				'presets'   => array(),
				'rules'     => array(
					array(
						'id'       => 'pantheon_cookie_challenge',
						'type'     => 'url',
						'label'    => 'Pantheon cookie challenge',
						'enabled'  => $rule,
						'response' => 'challenge',
						'settings' => array(
							'match_type' => 'any',
							'conditions' => array(
								array(
									'variable' => 'path',
									'operator' => 'equals',
									'value'    => '/bfw-pantheon-cookie',
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
