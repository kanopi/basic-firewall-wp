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
	 * The expiry survives on whichever backend the site is using.
	 *
	 * This is the shape of a bug that hid for a whole development cycle. The
	 * expiry was read from isBlocked(), which reports it on database storage --
	 * it hydrates the whole row, `expire` column included -- and not on file
	 * storage, which returns the stored payload alone. The dev site ran on
	 * database storage and CI on file, so each half of the work was checked
	 * against the half that agreed with it.
	 *
	 * Both are exercised here in one run, because a backend-dependent read is
	 * only ever caught by looking at both.
	 *
	 * @dataProvider backends
	 *
	 * @param string $backend Storage backend to run against.
	 */
	public function test_the_expiry_is_reported_on_every_backend( string $backend ): void {
		$settings = Plugin::instance()->settings();
		$snapshot = $settings->all();

		try {
			$values                       = $settings->all();
			$values['storage']['backend'] = $backend;
			$settings->replace( $values );

			$blocked = Plugin::instance()->blocked();

			if ( ! $blocked->is_durable() ) {
				$this->markTestSkipped( sprintf( 'The %s backend is not usable on this site.', $backend ) );
			}

			$blocked->unblock( self::ADDRESS );
			$this->assertTrue( $blocked->block( self::ADDRESS, 3600, 'Backend round trip' ) );

			$record = Plugin::instance()->blocked()->check( self::ADDRESS )['record'] ?? array();

			$this->assertGreaterThan(
				time(),
				(int) ( $record['expire'] ?? 0 ),
				sprintf( 'On %s storage the expiry did not come back, so the block reads as permanent and nothing ever releases it.', $backend )
			);

			$this->assertSame(
				'Backend round trip',
				(string) ( $record['reason'] ?? '' ),
				sprintf( 'On %s storage the reason did not come back.', $backend )
			);
		} finally {
			Plugin::instance()->blocked()->unblock( self::ADDRESS );
			$settings->replace( $snapshot );
		}
	}

	/**
	 * The backends a site can be set to.
	 *
	 * @return array<string, array{string}>
	 */
	public static function backends(): array {
		return array(
			'file'     => array( 'file' ),
			'database' => array( 'database' ),
		);
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
