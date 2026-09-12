<?php
/**
 * Settings validation and coercion.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\unit;

use Kanopi\BasicFirewall\Support\Validator;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Kanopi\BasicFirewall\Support\Validator
 */
final class ValidatorTest extends TestCase {

	/**
	 * The validator under test.
	 */
	private Validator $validator;

	/**
	 * Set up.
	 */
	protected function setUp(): void {
		parent::setUp();

		$this->validator = new Validator();
	}

	/**
	 * An empty document validates to the safe defaults.
	 */
	public function test_empty_input_produces_safe_defaults(): void {
		$result = $this->validator->validate( array() );

		$this->assertTrue( $this->validator->is_valid() );
		$this->assertSame( 'log', $result['global']['mode'] );
	}

	/**
	 * A bad value falls back to its default and is reported.
	 *
	 * Both halves matter. Falling back keeps the firewall running on a document
	 * that is mostly fine; reporting is what stops the fallback being silent.
	 */
	public function test_invalid_value_falls_back_and_is_reported(): void {
		$result = $this->validator->validate( array( 'global' => array( 'mode' => 'pancakes' ) ) );

		$this->assertSame( 'log', $result['global']['mode'] );
		$this->assertFalse( $this->validator->is_valid() );
		$this->assertSame( 'global.mode', $this->validator->errors()[0]['path'] );
	}

	/**
	 * Numbers outside their bounds are rejected rather than clamped.
	 *
	 * Clamping would turn a typo into a plausible-looking value that nobody
	 * questions. A status code of 9999 is a mistake, and silently storing 599
	 * hides it.
	 */
	public function test_out_of_range_numbers_are_rejected_not_clamped(): void {
		$result = $this->validator->validate(
			array( 'global' => array( 'banning_status_code' => 9999 ) )
		);

		$this->assertSame( 403, $result['global']['banning_status_code'] );
		$this->assertFalse( $this->validator->is_valid() );
	}

	/**
	 * YAML reads an unquoted `no` as boolean false.
	 *
	 * `behind_proxy: no` is a real and meaningful value -- it asserts there is
	 * no proxy. An importer that stringified the boolean to '' would turn a
	 * deliberate answer into the unanswered state, silently re-enabling a
	 * warning the administrator had answered. Or worse, fail the choice check
	 * and fall back to a different meaning entirely.
	 */
	public function test_yaml_boolean_no_survives_as_the_string_no(): void {
		$result = $this->validator->validate(
			array( 'global' => array( 'behind_proxy' => false ) )
		);

		$this->assertSame( 'no', $result['global']['behind_proxy'] );
		$this->assertTrue( $this->validator->is_valid() );
	}

	/**
	 * Unknown keys survive validation.
	 *
	 * A rule type contributed through the `basic_firewall_rule_types` filter
	 * owns its own settings sub-tree. If validation dropped what it did not
	 * recognise, disabling the plugin that supplies a type -- or downgrading
	 * this one -- would silently delete that configuration on the next save,
	 * and the loss would only be discovered after the type came back.
	 */
	public function test_unknown_rule_settings_are_preserved(): void {
		$result = $this->validator->validate(
			array(
				'rules' => array(
					array(
						'id'       => 'r1',
						'type'     => 'contributed_type',
						'settings' => array(
							'api_key' => 'kept',
							'nested'  => array( 'deep' => true ),
						),
					),
				),
			)
		);

		$this->assertSame( 'kept', $result['rules'][0]['settings']['api_key'] );
		$this->assertTrue( $result['rules'][0]['settings']['nested']['deep'] );
	}

	/**
	 * Missing keys on a rule are filled from the schema.
	 */
	public function test_partial_rule_is_completed_from_defaults(): void {
		$result = $this->validator->validate(
			array( 'rules' => array( array( 'id' => 'r1', 'type' => 'ip_address' ) ) )
		);

		$this->assertSame( 3600, $result['rules'][0]['expiration'] );
		$this->assertSame( 'block', $result['rules'][0]['response'] );
		$this->assertTrue( $result['rules'][0]['enabled'] );
	}

	/**
	 * Checkbox and YAML spellings of a boolean both coerce.
	 *
	 * @dataProvider boolean_spellings
	 *
	 * @param mixed $input    What arrived.
	 * @param bool  $expected What it means.
	 */
	public function test_boolean_spellings_coerce( $input, bool $expected ): void {
		$result = $this->validator->validate( array( 'enabled' => $input ) );

		$this->assertSame( $expected, $result['enabled'] );
	}

	/**
	 * Spellings a boolean arrives in, from HTML forms and from YAML.
	 *
	 * @return array<string, array{0: mixed, 1: bool}>
	 */
	public static function boolean_spellings(): array {
		return array(
			'unchecked checkbox'  => array( '0', false ),
			'checked checkbox'    => array( '1', true ),
			'html on'             => array( 'on', true ),
			'empty string'        => array( '', false ),
			'yaml false'          => array( false, false ),
			'yaml true'           => array( true, true ),
			'string false'        => array( 'false', false ),
			'string no'           => array( 'no', false ),
		);
	}
}
