<?php
/**
 * Saving a screen unchanged stores what was there.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

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
}
