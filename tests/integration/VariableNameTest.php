<?php
/**
 * Naming a query parameter, header or cookie.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\RuleType\Types\Url;
use Kanopi\BasicFirewall\RuleType\Types\User_Agent;
use PHPUnit\Framework\TestCase;

/**
 * A family and a name are two columns on screen and one string in storage.
 *
 * The library resolves `query.test`, `header.x-api-key` and any cookie by name,
 * and the validator accepted all of them — but the rule screen offered a select
 * of the ten named variables, so none of it could be entered. The only routes
 * to a named variable were WP-CLI, an imported document, or the advanced YAML,
 * which is no route at all for the person the screen exists for.
 *
 * Storage is unchanged: one string is what the library reads and what every
 * export, import and CLI command already carries.
 *
 * @covers \Kanopi\BasicFirewall\RuleType\Condition_Rule_Type_Base
 */
final class VariableNameTest extends TestCase {

	/**
	 * Validate one condition and hand back what was stored.
	 *
	 * @param array<string, mixed>  $condition The condition.
	 * @param array<string, string> $errors    Collected errors.
	 *
	 * @return string|null The stored variable, or null when the row was dropped.
	 */
	private function stored( array $condition, array &$errors = array() ): ?string {
		$clean = ( new Url() )->validate_settings(
			array(
				'match_type' => 'any',
				'sources'    => array(),
				'conditions' => array(
					array_merge(
						array(
							'operator' => 'equals',
							'value'    => '1',
						),
						$condition
					),
				),
			),
			$errors
		);

		return isset( $clean['conditions'][0] ) ? (string) $clean['conditions'][0]['variable'] : null;
	}

	/**
	 * A family and a name join into the one string the library reads.
	 *
	 * @dataProvider joins
	 *
	 * @param string $family   The chosen family.
	 * @param string $name     The name beside it.
	 * @param string $expected What gets stored.
	 */
	public function test_a_family_and_name_are_joined( string $family, string $name, string $expected ): void {
		$this->assertSame(
			$expected,
			$this->stored(
				array(
					'variable'      => $family,
					'variable_name' => $name,
				)
			)
		);
	}

	/**
	 * Each family, with a name a real site would use.
	 *
	 * @return array<string, array{0: string, 1: string, 2: string}>
	 */
	public static function joins(): array {
		return array(
			'a query parameter' => array( 'query', 'test', 'query.test' ),
			'a header'          => array( 'header', 'x-api-key', 'header.x-api-key' ),
			'a cookie'          => array( 'cookie', 'wordpress_logged_in', 'cookie.wordpress_logged_in' ),
			'a posted field'    => array( 'post', 'log', 'post.log' ),
			'a server variable' => array( 'server', 'request_method', 'server.request_method' ),
		);
	}

	/**
	 * A name given for something that does not take one is discarded.
	 *
	 * The column is hidden for those, so a value in it is a leftover from a
	 * different selection rather than an instruction.
	 */
	public function test_a_stray_name_is_discarded(): void {
		$this->assertSame(
			'path',
			$this->stored(
				array(
					'variable'      => 'path',
					'variable_name' => 'ignored',
				)
			)
		);
	}

	/**
	 * A family with no name is refused rather than stored.
	 *
	 * `query` on its own reads nothing, so a condition on it would match
	 * nothing — saved, reported active, and silent, which is the failure this
	 * plugin exists to prevent.
	 */
	public function test_a_family_without_a_name_is_refused(): void {
		$errors = array();

		$this->assertNull(
			$this->stored(
				array(
					'variable'      => 'query',
					'variable_name' => '',
				),
				$errors
			)
		);
		$this->assertArrayHasKey( 'conditions.0.variable', $errors );
	}

	/**
	 * A dotted variable that is not a family is left whole.
	 *
	 * The user agent type reads `client.name` and `bot.category`. Splitting on
	 * the first dot regardless would have turned those into a `client` family
	 * that does not exist.
	 */
	public function test_a_dotted_variable_that_is_not_a_family_survives(): void {
		$errors = array();

		$clean = ( new User_Agent() )->validate_settings(
			array(
				'match_type' => 'any',
				'sources'    => array(),
				'conditions' => array(
					array(
						'variable'      => 'client.name',
						'variable_name' => '',
						'operator'      => 'equals',
						'value'         => 'curl',
					),
					array(
						'variable'      => 'bot.category',
						'variable_name' => '',
						'operator'      => 'equals',
						'value'         => 'Search bot',
					),
				),
			),
			$errors
		);

		$this->assertSame( array(), $errors );
		$this->assertSame( 'client.name', $clean['conditions'][0]['variable'] );
		$this->assertSame( 'bot.category', $clean['conditions'][1]['variable'] );
	}

	/**
	 * And it compiles to something the library resolves.
	 */
	public function test_a_named_variable_compiles(): void {
		$entry = ( new Url() )->compile(
			array(
				'id'       => 'r',
				'response' => 'challenge',
				'settings' => array(
					'match_type' => 'any',
					'sources'    => array(),
					'conditions' => array(
						array(
							'variable' => 'query.test',
							'operator' => 'equals',
							'value'    => '1',
						),
					),
				),
			)
		);

		$this->assertSame( 'query.test', $entry['config'][0]['variable'] );
	}
}
