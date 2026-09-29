<?php
/**
 * The Rules screen lists rules in the order they are evaluated.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Admin\Screen\Rules_Screen;
use Kanopi\BasicFirewall\Plugin;

/**
 * By response first, then weight -- not by weight alone.
 *
 * The screen sorted by weight and said rules were evaluated in weight order,
 * so a block rule at -100 was listed above an allow rule at 50 that the
 * library consults first.
 *
 * @covers \Kanopi\BasicFirewall\Admin\Screen\Rules_Screen
 * @covers \Kanopi\BasicFirewall\Compiler\Evaluation_Order
 */
final class RulesScreenOrderTest extends Settings_Snapshot {

	/**
	 * The user before the test.
	 *
	 * @var int
	 */
	private int $user;

	/**
	 * Act as an administrator.
	 */
	protected function setUp(): void {
		parent::setUp();

		require_once ABSPATH . 'wp-admin/includes/template.php';

		$this->user = get_current_user_id();

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
	}

	/**
	 * Put the user back.
	 */
	protected function tearDown(): void {
		wp_set_current_user( $this->user );

		parent::tearDown();
	}

	/**
	 * An allow rule is listed above a lighter block rule, and a disabled rule last.
	 */
	public function test_rules_are_listed_by_response_then_weight(): void {
		Plugin::instance()->settings()->set(
			'rules',
			array(
				$this->rule( 'order-disabled-allow', 'allow', -500, false ),
				$this->rule( 'order-heavy-block', 'block', -100 ),
				$this->rule( 'order-challenge', 'challenge', -300 ),
				$this->rule( 'order-late-allow', 'allow', 50 ),
			)
		);

		$_GET = array();

		ob_start();
		( new Rules_Screen() )->render();
		$html = (string) ob_get_clean();

		$positions = array();

		foreach ( array( 'order-late-allow', 'order-challenge', 'order-heavy-block', 'order-disabled-allow' ) as $id ) {
			$found = strpos( $html, $id );

			$this->assertNotFalse( $found, sprintf( '%s is not on the screen.', $id ) );

			$positions[ $id ] = $found;
		}

		$sorted = $positions;
		asort( $sorted );

		$this->assertSame(
			array( 'order-late-allow', 'order-challenge', 'order-heavy-block', 'order-disabled-allow' ),
			array_keys( $sorted ),
			'The screen is not in evaluation order.'
		);
	}

	/**
	 * A stored rule.
	 *
	 * @param string $id       Identifier.
	 * @param string $response Response.
	 * @param int    $weight   Weight.
	 * @param bool   $enabled  Whether it is enabled.
	 *
	 * @return array<string, mixed>
	 */
	private function rule( string $id, string $response, int $weight, bool $enabled = true ): array {
		return array(
			'id'              => $id,
			'type'            => 'ip_address',
			'label'           => $id,
			'enabled'         => $enabled,
			'observe'         => false,
			'response'        => $response,
			'weight'          => $weight,
			'status_code'     => 0,
			'record'          => 'default',
			'redirect_to'     => '',
			'redirect_status' => 302,
			'mark_as'         => '',
			'mark_header'     => '',
			'expiration'      => 3600,
			'description'     => '',
			'settings'        => array( 'addresses' => array( '192.0.2.10' ) ),
		);
	}
}
