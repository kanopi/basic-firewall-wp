<?php
/**
 * The order the library consults the rules in.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Compiler;

use Kanopi\Firewall\Utility\PluginConfigNormalizer;

/**
 * Puts stored rules in the order the firewall evaluates them.
 *
 * Weight alone is not that order. The library partitions rules by response
 * first and consults the partitions in a fixed sequence, sorting by weight
 * only within each -- so a block rule at weight -100 still runs after an
 * allow rule at weight 50. A listing sorted by weight across the whole set
 * reads as the evaluation order and is not it.
 *
 * The partitioning and the per-partition sort are the library's own
 * (PluginConfigNormalizer::partitionAndSort(), which Firewall::create()
 * calls), so this agrees with it by construction: an unrecognised response
 * falls into the block partition, and a disabled rule is dropped, exactly as
 * there. Only the sequence the partitions are consulted in is written out
 * here, because the library keeps it inside evaluateRequest() and a private
 * buckets() -- see STAGES.
 *
 * Free of WordPress, so the unit suite can pin it.
 */
final class Evaluation_Order {

	/**
	 * Partitions in the order Firewall::evaluateRequest() consults them.
	 *
	 * Between `allow` and `mark` the library consults the durable block list,
	 * so a client already blocked is refused before any rule below runs. Mark,
	 * record and tarpit do not end evaluation; allow, challenge, redirect and
	 * block do. Nothing this plugin writes responds `tarpit`, but an imported
	 * document can, and the library honours it there.
	 */
	public const STAGES = array( 'allow', 'mark', 'record', 'tarpit', 'challenge', 'redirect', 'block' );

	/**
	 * Whether the installed library can say how it would order the rules.
	 */
	public static function is_available(): bool {
		return class_exists( PluginConfigNormalizer::class );
	}

	/**
	 * The rules in evaluation order, each with its position and stage.
	 *
	 * Disabled rules come last, with no position: the library never sees
	 * them. Settings order breaks a tie in weight, because both sorts are
	 * stable and the compiler hands the library the rules in that order.
	 *
	 * @param array<int|string, mixed> $rules Stored rules.
	 *
	 * @return list<array{position: int|null, stage: string, rule: array<string, mixed>}>
	 */
	public static function of( array $rules ): array {
		$entries  = array();
		$disabled = array();

		foreach ( array_values( $rules ) as $index => $rule ) {
			if ( ! is_array( $rule ) ) {
				continue;
			}

			if ( empty( $rule['enabled'] ) ) {
				$disabled[] = array(
					'position' => null,
					'stage'    => '',
					'rule'     => $rule,
				);

				continue;
			}

			// The shape partitionAndSort() reads, carrying the rule along.
			$entries[] = array(
				'response' => (string) ( $rule['response'] ?? 'block' ),
				'weight'   => (int) ( $rule['weight'] ?? 0 ),
				'enable'   => true,
				'bfw_rule' => $index,
			);
		}

		$partitioned = PluginConfigNormalizer::partitionAndSort( $entries );
		$ordered     = array();
		$position    = 0;
		$rules       = array_values( $rules );

		foreach ( self::STAGES as $stage ) {
			foreach ( (array) ( $partitioned[ $stage ] ?? array() ) as $entry ) {
				$ordered[] = array(
					'position' => ++$position,
					'stage'    => $stage,
					'rule'     => (array) $rules[ (int) $entry['bfw_rule'] ],
				);
			}
		}

		return array_merge( $ordered, $disabled );
	}
}
