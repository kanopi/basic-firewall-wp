<?php
/**
 * The order the library consults the rules in.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\unit;

use Kanopi\BasicFirewall\Compiler\Evaluation_Order;
use PHPUnit\Framework\TestCase;

/**
 * Response first, weight within it, disabled rules last and unnumbered.
 *
 * `wp basic-firewall rules` claimed evaluation order and sorted by weight
 * alone, which put a block rule at -100 ahead of an allow rule at 50 -- the
 * opposite of what the library does with them.
 *
 * @covers \Kanopi\BasicFirewall\Compiler\Evaluation_Order
 */
final class EvaluationOrderTest extends TestCase {

	/**
	 * The library's partitions, consulted in its sequence.
	 */
	public function test_rules_are_ordered_by_response_then_weight(): void {
		$order = Evaluation_Order::of(
			array(
				$this->rule( 'heavy-block', 'block', -100 ),
				$this->rule( 'late-allow', 'allow', 50 ),
				$this->rule( 'challenge', 'challenge', -50 ),
				$this->rule( 'honeypot', 'record', 10 ),
				$this->rule( 'flag', 'mark', 20 ),
				$this->rule( 'moved', 'redirect', -200 ),
				$this->rule( 'early-allow', 'allow', -10 ),
				$this->rule( 'light-block', 'block', 5 ),
			)
		);

		$this->assertSame(
			array( 'early-allow', 'late-allow', 'flag', 'honeypot', 'challenge', 'moved', 'heavy-block', 'light-block' ),
			array_map( static fn ( array $row ): string => (string) $row['rule']['id'], $order )
		);
		$this->assertSame( range( 1, 8 ), array_column( $order, 'position' ) );
		$this->assertSame( 'allow', $order[0]['stage'] );
		$this->assertSame( 'block', $order[7]['stage'] );
	}

	/**
	 * A disabled rule is never evaluated, so it has no place in the order.
	 */
	public function test_disabled_rules_come_last_without_a_position(): void {
		$order = Evaluation_Order::of(
			array(
				$this->rule( 'off', 'allow', -1000, false ),
				$this->rule( 'on', 'block', 0 ),
			)
		);

		$this->assertSame( 'on', $order[0]['rule']['id'] );
		$this->assertSame( 1, $order[0]['position'] );
		$this->assertSame( 'off', $order[1]['rule']['id'] );
		$this->assertNull( $order[1]['position'] );
		$this->assertSame( '', $order[1]['stage'] );
	}

	/**
	 * An unrecognised response is a block, as the library treats it, and a tie keeps settings order.
	 */
	public function test_an_unknown_response_blocks_and_ties_keep_their_order(): void {
		$order = Evaluation_Order::of(
			array(
				$this->rule( 'typo', 'refuse', 0 ),
				$this->rule( 'first', 'block', 0 ),
				$this->rule( 'allow', 'allow', 0 ),
			)
		);

		$this->assertSame( array( 'allow', 'typo', 'first' ), array_map( static fn ( array $row ): string => (string) $row['rule']['id'], $order ) );
		$this->assertSame( 'block', $order[1]['stage'] );
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
			'id'       => $id,
			'type'     => 'ip_address',
			'response' => $response,
			'weight'   => $weight,
			'enabled'  => $enabled,
		);
	}
}
