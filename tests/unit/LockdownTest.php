<?php
/**
 * Tests for the lockdown allowlist.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\unit;

use Kanopi\BasicFirewall\Runtime\Lockdown;
use PHPUnit\Framework\TestCase;

/**
 * The list decides who is still served, so what it accepts has to be what the
 * library matches.
 *
 * An IP rule accepts `start-end` ranges and this list looks like the same
 * field. The library does not match ranges here, so accepting one would keep an
 * entry that never matches anybody -- quite possibly the one naming the person
 * who typed it.
 *
 * @covers \Kanopi\BasicFirewall\Runtime\Lockdown
 */
final class LockdownTest extends TestCase {

	/**
	 * Entries the library will match.
	 *
	 * @return array<string, array{string}>
	 */
	public static function valid_entries(): array {
		return array(
			'IPv4 address' => array( '198.51.100.7' ),
			'IPv4 CIDR'    => array( '198.51.100.0/24' ),
			'IPv6 address' => array( '2001:db8::1' ),
			'IPv6 CIDR'    => array( '2001:db8::/32' ),
			'whole world'  => array( '0.0.0.0/0' ),
		);
	}

	/**
	 * Entries it will not.
	 *
	 * @return array<string, array{string}>
	 */
	public static function invalid_entries(): array {
		return array(
			'a range'           => array( '198.51.100.1-198.51.100.9' ),
			'IPv4 prefix /33'   => array( '198.51.100.0/33' ),
			'IPv6 prefix /129'  => array( '2001:db8::/129' ),
			'not a prefix'      => array( '198.51.100.0/abc' ),
			'a hostname'        => array( 'office.example.com' ),
			'a partial address' => array( '198.51.100' ),
		);
	}

	/**
	 * An address or a CIDR block is accepted.
	 *
	 * @dataProvider valid_entries
	 *
	 * @param string $entry Entry.
	 */
	public function test_it_accepts_what_the_library_matches( string $entry ): void {
		$this->assertTrue( Lockdown::is_valid_entry( $entry ) );
	}

	/**
	 * Anything else is refused.
	 *
	 * @dataProvider invalid_entries
	 *
	 * @param string $entry Entry.
	 */
	public function test_it_refuses_what_the_library_would_never_match( string $entry ): void {
		$this->assertFalse( Lockdown::is_valid_entry( $entry ) );
	}

	/**
	 * Lines are trimmed, blanks dropped, duplicates collapsed, and sorted.
	 */
	public function test_a_textarea_is_sorted_into_usable_and_unusable(): void {
		$sorted = Lockdown::sort( "198.51.100.0/24\n\n  2001:db8::1  \n198.51.100.0/24\n10.0.0.1-10.0.0.9\r\n" );

		$this->assertSame( array( '198.51.100.0/24', '2001:db8::1' ), $sorted['valid'] );
		$this->assertSame( array( '10.0.0.1-10.0.0.9' ), $sorted['invalid'] );
	}

	/**
	 * Coverage is matched the way the library matches it.
	 */
	public function test_an_address_is_covered_by_a_block_that_contains_it(): void {
		$allow = array( '198.51.100.0/24', '2001:db8::/32' );

		$this->assertTrue( Lockdown::covers( '198.51.100.200', $allow ) );
		$this->assertTrue( Lockdown::covers( '2001:db8:1::5', $allow ) );
		$this->assertFalse( Lockdown::covers( '198.51.101.1', $allow ) );
		$this->assertFalse( Lockdown::covers( '2001:db9::1', $allow ) );
	}

	/**
	 * Nothing is covered by an entry the library would not match.
	 *
	 * The warning this feeds exists to say "you are about to lock yourself
	 * out", so claiming a range covers somebody would be the one wrong answer.
	 */
	public function test_a_range_covers_nobody(): void {
		$this->assertFalse( Lockdown::covers( '10.0.0.5', array( '10.0.0.1-10.0.0.9' ) ) );
	}

	/**
	 * Something that is not an address is covered by nothing.
	 */
	public function test_a_non_address_is_never_covered(): void {
		$this->assertFalse( Lockdown::covers( '', array( '0.0.0.0/0' ) ) );
		$this->assertFalse( Lockdown::covers( 'unknown', array( '0.0.0.0/0' ) ) );
	}
}
