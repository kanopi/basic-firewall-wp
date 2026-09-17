<?php
/**
 * Referenced lists on a condition rule.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\RuleType\Condition_Rule_Type_Base;
use Kanopi\BasicFirewall\RuleType\Types\Ip_Address;
use Kanopi\BasicFirewall\RuleType\Types\Url;
use PHPUnit\Framework\TestCase;

/**
 * A list of names is as referenceable as a list of addresses.
 *
 * Referenced lists shipped supporting the IP rule alone, on the grounds that a
 * source on a condition type feeds condition *values* rather than a flat list
 * and is therefore a different shape. It is a different shape and not a harder
 * one, and the types that most want a list are these: crawler names, scanner
 * agents and probe paths all change on somebody else's schedule.
 *
 * @covers \Kanopi\BasicFirewall\RuleType\Condition_Rule_Type_Base
 * @covers \Kanopi\BasicFirewall\RuleType\Has_Sources
 */
final class ConditionSourceTest extends TestCase {

	/**
	 * A rule referencing one list.
	 *
	 * @param array<string, mixed> $source Overrides for the referenced list.
	 *
	 * @return array<string, mixed>
	 */
	private function rule( array $source = array() ): array {
		return array(
			'id'       => 'ai-crawlers',
			'type'     => 'url',
			'response' => 'block',
			'settings' => array(
				'match_type' => 'any',
				'conditions' => array(),
				'sources'    => array(
					array_merge(
						Ip_Address::source_defaults(),
						array(
							'name'     => 'ai-crawlers',
							'url'      => 'https://example.test/crawlers.txt',
							'format'   => 'txt',
							'variable' => 'header.user-agent',
							'operator' => 'contains',
						),
						$source
					),
				),
			),
		);
	}

	/**
	 * Every type that can use a list says so.
	 */
	public function test_condition_types_accept_lists(): void {
		foreach ( array( 'url', 'user_agent', 'asn', 'geolocation' ) as $id ) {
			$type = Plugin::instance()->rule_types()->get( $id );

			$this->assertNotNull( $type );
			$this->assertTrue(
				$type->supports_sources(),
				sprintf( 'The %s type cannot reference a list, so its screen will not offer one.', $id )
			);
		}
	}

	/**
	 * An entry becomes a condition, in the shape a typed one compiles to.
	 *
	 * Structured rather than the `variable@operator:{value}` shorthand the
	 * library also accepts, so an entry from a list and an entry from the form
	 * are evaluated by identical code — including the operator names this
	 * plugin uses, which the shorthand parser spells differently in places.
	 */
	public function test_an_entry_compiles_into_a_condition(): void {
		$entry = ( new Url() )->compile( $this->rule() );

		$template = $entry['metadata']['sources'][0]['template'] ?? null;

		$this->assertIsArray( $template, 'The template is not structured, so entries go through the shorthand parser.' );
		$this->assertSame( 'header.user-agent', $template['variable'] );
		$this->assertSame( 'contains', $template['operator'] );
		$this->assertSame( '{value}', $template['value'], 'Without the placeholder every entry compares against the literal string.' );
		$this->assertFalse( $template['negate'] );
	}

	/**
	 * Inverting is offered, and reaches the template.
	 */
	public function test_a_list_can_be_inverted(): void {
		$entry = ( new Url() )->compile( $this->rule( array( 'negate' => true ) ) );

		$this->assertTrue( $entry['metadata']['sources'][0]['template']['negate'] );
	}

	/**
	 * A hand-written template is left alone.
	 */
	public function test_an_explicit_template_wins(): void {
		$entry = ( new Url() )->compile(
			$this->rule( array( 'template' => 'header.user-agent@contains:{value}' ) )
		);

		$this->assertSame(
			'header.user-agent@contains:{value}',
			$entry['metadata']['sources'][0]['template'],
			'Somebody who wrote a template meant it.'
		);
	}

	/**
	 * A variable the type cannot read is refused.
	 *
	 * The library would accept the name, resolve it to nothing, and compare
	 * against nothing on every request — a rule reporting itself active and
	 * matching nothing, which is the failure this plugin exists to prevent.
	 */
	public function test_an_unreadable_variable_is_refused(): void {
		$errors = array();
		$clean  = ( new Url() )->validate_settings(
			$this->rule( array( 'variable' => 'not_a_real_variable' ) )['settings'],
			$errors
		);

		$this->assertArrayHasKey( 'sources.0.variable', $errors );
		$this->assertSame( '', $clean['sources'][0]['variable'] );
	}

	/**
	 * A prefixed variable is accepted, because the list names families.
	 */
	public function test_a_prefixed_variable_is_accepted(): void {
		$errors = array();

		( new Url() )->validate_settings( $this->rule()['settings'], $errors );

		$this->assertArrayNotHasKey(
			'sources.0.variable',
			$errors,
			'header.user-agent is a real variable; the options list names the family and the suffix is whatever the site sends.'
		);
	}

	/**
	 * A relative file reference is made absolute.
	 *
	 * The library does not resolve `metadata.sources.*.upstream` against the
	 * configuration directory the way it resolves storage and log paths. Left
	 * relative it resolves against the process working directory — a different
	 * answer under php-fpm, WP-CLI and cron, and all three wrong — so the list
	 * loads nothing and the error policy hides why.
	 */
	public function test_a_relative_file_reference_is_resolved(): void {
		$entry = ( new Url() )->compile( $this->rule( array( 'url' => 'lists/crawlers.txt' ) ) );

		$upstream = $entry['metadata']['sources'][0]['upstream'];

		$this->assertStringStartsWith( Plugin::instance()->paths()->base(), $upstream );
		$this->assertStringEndsWith( 'lists/crawlers.txt', $upstream );
	}

	/**
	 * The operator vocabulary the screen offers is the one conditions use.
	 */
	public function test_the_operators_are_the_condition_operators(): void {
		$this->assertArrayHasKey( 'contains', Condition_Rule_Type_Base::OPERATORS );
		$this->assertArrayHasKey( 'regex', Condition_Rule_Type_Base::OPERATORS );
	}
}
