<?php
/**
 * Adding to the block list by hand.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Blocked_Clients;
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

	use Test_Services;

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

			/*
			 * Redis against a live server, under a prefix of its own. It
			 * stores the payload alone, as file storage does, so it is the
			 * third backend the expiry has to survive on.
			 */
			if ( 'redis' === $backend ) {
				$server                     = $this->redis_server();
				$prefix                     = 'bfwtest-blocklist:' . bin2hex( random_bytes( 4 ) ) . ':';
				$values['storage']['redis'] = array_merge(
					(array) ( $values['storage']['redis'] ?? array() ),
					array(
						'host'     => $server[0],
						'port'     => $server[1],
						'password' => $server[2],
						'prefix'   => $prefix,
					)
				);
			}

			$settings->replace( $values );

			$blocked = $this->fresh_block_list();

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
			$this->fresh_block_list();

			if ( isset( $prefix, $server ) ) {
				$this->delete_redis_keys( $server, $prefix );
			}
		}
	}

	/**
	 * A Redis-backed round trip leaves the key where the prefix says.
	 *
	 * The expiry test above proves the record comes back; this proves it was
	 * the server that held it, under the configured prefix, rather than a
	 * backend that quietly fell back to file storage.
	 */
	public function test_a_redis_block_is_stored_on_the_server_under_its_prefix(): void {
		$server   = $this->redis_server();
		$settings = Plugin::instance()->settings();
		$snapshot = $settings->all();
		$prefix   = 'bfwtest-blocklist:' . bin2hex( random_bytes( 4 ) ) . ':';
		$redis    = $this->redis_client( $server );

		try {
			$values                       = $settings->all();
			$values['storage']['backend'] = 'redis';
			$values['storage']['redis']   = array_merge(
				(array) ( $values['storage']['redis'] ?? array() ),
				array(
					'host'     => $server[0],
					'port'     => $server[1],
					'password' => $server[2],
					'prefix'   => $prefix,
				)
			);
			$settings->replace( $values );
			$this->fresh_block_list();

			$this->assertTrue( Plugin::instance()->blocked()->block( self::ADDRESS, 3600, 'Redis round trip' ) );

			$keys = $this->redis_keys( $redis, $prefix );

			$this->assertNotSame( array(), $keys, 'A block on Redis storage wrote nothing to the server under its prefix.' );
			$this->assertTrue( Plugin::instance()->blocked()->check( self::ADDRESS )['blocked'] ?? false, 'The address blocked on Redis is not reported as blocked.' );

			Plugin::instance()->blocked()->unblock( self::ADDRESS );

			$this->assertFalse( Plugin::instance()->blocked()->check( self::ADDRESS )['blocked'] ?? true, 'Releasing the address on Redis did not release it.' );
		} finally {
			Plugin::instance()->blocked()->unblock( self::ADDRESS );
			$settings->replace( $snapshot );
			$this->fresh_block_list();
			$this->delete_redis_keys( $server, $prefix );
			$redis->close();
		}
	}

	/**
	 * A block list built from the settings as they are now.
	 *
	 * Blocked_Clients builds its storage once and keeps it, which is right for
	 * a request and wrong for a test that changes the backend between
	 * assertions: without this every case of the backends provider ran
	 * against whichever backend the first test in the process happened to
	 * build, so "every backend" was one backend three times.
	 */
	private function fresh_block_list(): Blocked_Clients {
		$blocked = new Blocked_Clients();

		Plugin::instance()->set_service( 'blocked', $blocked );

		return $blocked;
	}

	/**
	 * Every key under a prefix.
	 *
	 * @param \Redis $redis  Connected client.
	 * @param string $prefix Key prefix, matched literally.
	 *
	 * @return list<string>
	 */
	private function redis_keys( \Redis $redis, string $prefix ): array {
		$found    = array();
		$iterator = null;
		$pattern  = addcslashes( $prefix, '*?[]\\' ) . '*';

		do {
			$batch = $redis->scan( $iterator, $pattern, 100 );

			if ( is_array( $batch ) ) {
				$found = array_merge( $found, array_map( 'strval', $batch ) );
			}
		} while ( $iterator > 0 );

		return $found;
	}

	/**
	 * Remove what a test left under its prefix.
	 *
	 * @param array{0: string, 1: int, 2: string} $server From redis_server().
	 * @param string                              $prefix Key prefix.
	 */
	private function delete_redis_keys( array $server, string $prefix ): void {
		try {
			$redis = $this->redis_client( $server );

			$keys = $this->redis_keys( $redis, $prefix );

			if ( array() !== $keys ) {
				$redis->del( $keys );
			}

			$redis->close();
		} catch ( \RedisException $e ) {
			return;
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
			'redis'    => array( 'redis' ),
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
