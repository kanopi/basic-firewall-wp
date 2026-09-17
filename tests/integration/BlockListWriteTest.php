<?php
/**
 * Adding to the block list by hand.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Plugin;
use PHPUnit\Framework\TestCase;

/**
 * The screen could take clients off the list and not put them on.
 *
 * `wp basic-firewall block` has always existed, so the capability was there and
 * only the route was missing — which meant the one thing an administrator
 * actually does with an address somebody emailed them needed a shell.
 *
 * @covers \Kanopi\BasicFirewall\Blocked_Clients
 */
final class BlockListWriteTest extends TestCase {

	/**
	 * An address used by no real network. RFC 5737 reserves this range.
	 */
	private const ADDRESS = '203.0.113.171';

	/**
	 * Leave the list as it was found.
	 */
	protected function tearDown(): void {
		Plugin::instance()->blocked()->unblock( self::ADDRESS );

		parent::tearDown();
	}

	/**
	 * Blocking stores the address, the reason and the expiry.
	 */
	public function test_an_address_can_be_added_with_a_reason(): void {
		$blocked = Plugin::instance()->blocked();

		$this->assertFalse( $blocked->check( self::ADDRESS )['blocked'], 'The fixture address was already blocked.' );

		$this->assertTrue( $blocked->block( self::ADDRESS, 3600, 'Added by hand' ) );

		$answer = $blocked->check( self::ADDRESS );

		$this->assertTrue( $answer['blocked'] );
		$this->assertSame(
			'Added by hand',
			(string) ( $answer['record']['reason'] ?? '' ),
			'The reason was not stored, so the field that asks why would file the answer nowhere.'
		);

		$expires = (int) ( $answer['record']['expire'] ?? 0 );

		$this->assertGreaterThan( time(), $expires );
		$this->assertLessThanOrEqual( time() + 3600 + 5, $expires );
	}

	/**
	 * Zero means permanent, and permanent is not "expired an instant ago".
	 */
	public function test_zero_duration_blocks_permanently(): void {
		$blocked = Plugin::instance()->blocked();

		$this->assertTrue( $blocked->block( self::ADDRESS, 0, 'Permanent' ) );

		$answer = $blocked->check( self::ADDRESS );

		$this->assertTrue( $answer['blocked'], 'A permanent block did not register as blocked.' );

		$listing = $blocked->all();

		if ( ! $listing['supported'] ) {
			return;
		}

		foreach ( $listing['clients'] as $client ) {
			if ( self::ADDRESS === $client['ip'] ) {
				$this->assertTrue( (bool) $client['permanent'], 'A zero duration was read as an expiry rather than as "never".' );
			}
		}
	}

	/**
	 * Releasing it puts things back.
	 */
	public function test_an_added_address_can_be_released(): void {
		$blocked = Plugin::instance()->blocked();

		$blocked->block( self::ADDRESS, 3600, 'Temporary' );

		$this->assertTrue( $blocked->unblock( self::ADDRESS ) );
		$this->assertFalse( $blocked->check( self::ADDRESS )['blocked'] );
	}
}
