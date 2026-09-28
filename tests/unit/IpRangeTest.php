<?php
/**
 * Tests for writing an IPv6 range as CIDR blocks.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\unit;

use Kanopi\BasicFirewall\RuleType\Types\Ip_Address;
use PHPUnit\Framework\TestCase;

/**
 * The library's IpAddress plugin compares a start-end range with ip2long(),
 * which is IPv4 only, so an IPv6 range matched nobody. The rule type compiles
 * one as the CIDR blocks covering exactly the same addresses, which the plugin
 * does match. Exactly is the point: a block one bit too wide on a block rule
 * refuses somebody the range did not name.
 *
 * @covers \Kanopi\BasicFirewall\RuleType\Types\Ip_Address::range_to_cidrs
 */
final class IpRangeTest extends TestCase {

	/**
	 * Ranges and the blocks that cover them.
	 *
	 * @return array<string, array{0: string, 1: string, 2: list<string>}>
	 */
	public static function ranges(): array {
		return array(
			'one address'         => array( '2001:db8::5', '2001:db8::5', array( '2001:db8::5/128' ) ),
			'an aligned block'    => array( '2001:db8::', '2001:db8::ffff', array( '2001:db8::/112' ) ),
			'unaligned both ends' => array(
				'2001:db8::1',
				'2001:db8::ff',
				array( '2001:db8::1/128', '2001:db8::2/127', '2001:db8::4/126', '2001:db8::8/125', '2001:db8::10/124', '2001:db8::20/123', '2001:db8::40/122', '2001:db8::80/121' ),
			),
			'across a byte carry' => array( '2001:db8::ffff', '2001:db8::1:0', array( '2001:db8::ffff/128', '2001:db8::1:0/128' ) ),
			'everything'          => array( '::', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', array( '::/0' ) ),
			'IPv4 works the same' => array( '192.0.2.10', '192.0.2.20', array( '192.0.2.10/31', '192.0.2.12/30', '192.0.2.16/30', '192.0.2.20/32' ) ),
		);
	}

	/**
	 * The fewest blocks, covering the range exactly.
	 *
	 * @dataProvider ranges
	 *
	 * @param string       $start    First address.
	 * @param string       $end      Last address.
	 * @param list<string> $expected Blocks.
	 */
	public function test_a_range_becomes_its_blocks( string $start, string $end, array $expected ): void {
		$this->assertSame( $expected, Ip_Address::range_to_cidrs( (string) inet_pton( $start ), (string) inet_pton( $end ) ) );
	}
}
