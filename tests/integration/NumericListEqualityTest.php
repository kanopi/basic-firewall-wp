<?php
/**
 * An equality against a referenced list on an integer variable.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Compiler\Config_Compiler;
use Kanopi\BasicFirewall\Library_Capabilities;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\RuleType\Types\Url;
use Kanopi\BasicFirewall\Support\Schema;
use Kanopi\Firewall\Plugins\Url as LibraryUrl;
use Symfony\Component\HttpFoundation\Request;

/**
 * A list-backed equality on port or query_count is refused, not saved dead.
 *
 * The library (2.36.0) compares `equals`, `not_equals` and `in` strictly, and
 * `port` and `query_count` resolve to integers. A typed condition is cast when
 * it compiles; a referenced list's entries are substituted afterwards, as
 * text. So "port is one of" a list never matched, and "port is not equal to"
 * a list matched every request -- on a block rule, every visitor. Refused on
 * the rule screen, skipped and reported by the compiler, and both lift on a
 * library that compares numerics by value (kanopi/firewall#443).
 *
 * @covers \Kanopi\BasicFirewall\RuleType\Condition_Rule_Type_Base
 * @covers \Kanopi\BasicFirewall\RuleType\Types\Url
 * @covers \Kanopi\BasicFirewall\Compiler\Config_Compiler
 * @covers \Kanopi\BasicFirewall\Library_Capabilities
 */
final class NumericListEqualityTest extends Settings_Snapshot {

	/**
	 * Go back to the real probe.
	 */
	protected function tearDown(): void {
		Library_Capabilities::simulate_loose_numeric_equality( null );

		parent::tearDown();
	}

	/**
	 * Settings with one referenced list.
	 *
	 * @param array<string, mixed> $source Overrides for the list.
	 *
	 * @return array<string, mixed>
	 */
	private function settings( array $source ): array {
		return array(
			'match_type' => 'any',
			'conditions' => array(),
			'sources'    => array(
				array_merge(
					Url::source_defaults(),
					array(
						'name'   => 'ports',
						'url'    => 'https://example.test/ports.txt',
						'format' => 'txt',
					),
					$source
				),
			),
		);
	}

	/**
	 * Validate settings with one referenced list and hand back the errors.
	 *
	 * @param array<string, mixed> $source Overrides for the list.
	 *
	 * @return array<string, string>
	 */
	private function errors_for( array $source ): array {
		$errors = array();

		( new Url() )->validate_settings( $this->settings( $source ), $errors );

		return $errors;
	}

	/**
	 * Every integer variable, with every strict operator.
	 *
	 * @return array<string, array{0: string, 1: string}>
	 */
	public function strict(): array {
		$cases = array();

		foreach ( array( 'port', 'query_count', 'query_count.f' ) as $variable ) {
			foreach ( array( 'equals', 'not_equals', 'in' ) as $operator ) {
				$cases[ $variable . ' ' . $operator ] = array( $variable, $operator );
			}
		}

		return $cases;
	}

	/**
	 * The save is refused, on the list's operator, saying why and what to use.
	 *
	 * @dataProvider strict
	 *
	 * @param string $variable The list's variable.
	 * @param string $operator The list's operator.
	 */
	public function test_an_equality_against_a_list_is_refused( string $variable, string $operator ): void {
		Library_Capabilities::simulate_loose_numeric_equality( false );

		$errors = $this->errors_for(
			array(
				'variable' => $variable,
				'operator' => $operator,
			)
		);

		$this->assertArrayHasKey( 'sources.0.operator', $errors );
		$this->assertStringContainsString( $variable, $errors['sources.0.operator'] );
		$this->assertStringContainsString( 'is greater than', $errors['sources.0.operator'] );
		$this->assertStringContainsString( '^(8443|9443)$', $errors['sources.0.operator'] );
	}

	/**
	 * What does work against a list on these variables is still allowed.
	 *
	 * @return array<string, array{0: string, 1: string}>
	 */
	public function allowed(): array {
		return array(
			'port, greater than'          => array( 'port', 'gt' ),
			'port, regex'                 => array( 'port', 'regex' ),
			'query_count, less than'      => array( 'query_count', 'lt' ),
			'query_count.f, greater than' => array( 'query_count.f', 'gte' ),
			'query_count.f, regex'        => array( 'query_count.f', 'regex' ),
			'a header, equals'            => array( 'header.x', 'equals' ),
			'a header, one of'            => array( 'header.x', 'in' ),
			'a query parameter, not'      => array( 'query.f', 'not_equals' ),
		);
	}

	/**
	 * A numeric operator, a pattern, or equality on a text variable is fine.
	 *
	 * @dataProvider allowed
	 *
	 * @param string $variable The list's variable.
	 * @param string $operator The list's operator.
	 */
	public function test_other_comparisons_against_a_list_are_allowed( string $variable, string $operator ): void {
		Library_Capabilities::simulate_loose_numeric_equality( false );

		$this->assertSame(
			array(),
			$this->errors_for(
				array(
					'variable' => $variable,
					'operator' => $operator,
				)
			)
		);
	}

	/**
	 * A template in the library's shorthand is read the same way.
	 *
	 * @return array<string, array{0: string, 1: bool}>
	 */
	public function templates(): array {
		return array(
			'explicit equals' => array( 'port@equals:{value}', true ),
			'implicit equals' => array( 'query_count.f:{value}', true ),
			'negated'         => array( '!port@not_equals:{value}', true ),
			'greater than'    => array( 'port@greater_than:{value}', false ),
			'a header'        => array( 'header.x@equals:{value}', false ),
		);
	}

	/**
	 * An explicit shorthand template on an integer variable is refused too.
	 *
	 * @dataProvider templates
	 *
	 * @param string $template The template.
	 * @param bool   $refused  Whether it should be refused.
	 */
	public function test_a_shorthand_template_is_checked( string $template, bool $refused ): void {
		Library_Capabilities::simulate_loose_numeric_equality( false );

		$errors = $this->errors_for( array( 'template' => $template ) );

		$this->assertSame( $refused, isset( $errors['sources.0.operator'] ) );
	}

	/**
	 * On a library that compares numerics by value, nothing is refused.
	 *
	 * @dataProvider strict
	 *
	 * @param string $variable The list's variable.
	 * @param string $operator The list's operator.
	 */
	public function test_a_fixed_library_lifts_the_refusal( string $variable, string $operator ): void {
		Library_Capabilities::simulate_loose_numeric_equality( true );

		$this->assertSame(
			array(),
			$this->errors_for(
				array(
					'variable' => $variable,
					'operator' => $operator,
				)
			)
		);
	}

	/**
	 * The probe says what the bundled library actually does.
	 *
	 * Checked against the library itself rather than a version, so this holds
	 * before #443 ships and after: a string port equal to the request's port
	 * matches exactly when the probe says numerics compare loosely.
	 */
	public function test_the_probe_agrees_with_the_bundled_library(): void {
		$plugin = new LibraryUrl(
			array( 'name' => 'probe-check' ),
			array(
				array(
					'variable' => 'port',
					'operator' => 'equals',
					'value'    => '8443',
				),
			)
		);

		$this->assertSame(
			$plugin->evaluate( Request::create( 'https://example.test:8443/' ) ),
			( new Library_Capabilities() )->compares_numbers_loosely()
		);
	}

	/**
	 * Store a document holding one list-backed rule, as an import would.
	 *
	 * Written to the option directly, so the rule screen's validation never
	 * sees it -- the route an import, WP-CLI or a hand edit takes.
	 */
	private function store_imported_rule(): void {
		$errors            = array();
		$document          = array_replace_recursive( Schema::defaults(), (array) get_option( Schema::OPTION, array() ) );
		$document['rules'] = array(
			array(
				'id'       => 'not-port-list',
				'type'     => 'url',
				'label'    => 'Not a listed port',
				'enabled'  => true,
				'response' => 'block',
				'weight'   => 0,
				'settings' => ( new Url() )->validate_settings(
					$this->settings(
						array(
							'variable' => 'port',
							'operator' => 'not_equals',
						)
					),
					$errors
				),
			),
		);

		update_option( Schema::OPTION, $document, false );
		Plugin::instance()->settings()->flush();
	}

	/**
	 * The compiled rule names, from a compile.
	 *
	 * @param array<string, mixed> $compiled What the compiler produced.
	 *
	 * @return list<string>
	 */
	private static function names( array $compiled ): array {
		return array_map(
			static fn ( $entry ): string => (string) ( $entry['metadata']['name'] ?? '' ),
			array_values( (array) ( $compiled['plugins'] ?? array() ) )
		);
	}

	/**
	 * An imported rule with the combination is skipped and named.
	 */
	public function test_an_imported_rule_is_skipped_and_reported(): void {
		Library_Capabilities::simulate_loose_numeric_equality( false );
		$this->store_imported_rule();

		$compiler = new Config_Compiler();
		$compiled = $compiler->compile();

		$this->assertNotContains( 'not-port-list', self::names( $compiled ) );

		$reported = array_filter(
			$compiler->problems(),
			static fn ( string $problem ): bool => false !== strpos( $problem, '"not-port-list"' ) && false !== strpos( $problem, 'skipped' )
		);

		$this->assertCount( 1, $reported );
	}

	/**
	 * The same rule compiles on a library that compares numerics by value.
	 */
	public function test_an_imported_rule_compiles_on_a_fixed_library(): void {
		Library_Capabilities::simulate_loose_numeric_equality( true );
		$this->store_imported_rule();

		$compiler = new Config_Compiler();
		$compiled = $compiler->compile();

		$this->assertContains( 'not-port-list', self::names( $compiled ) );

		foreach ( $compiler->problems() as $problem ) {
			$this->assertStringNotContainsString( '"not-port-list"', $problem );
		}
	}
}
