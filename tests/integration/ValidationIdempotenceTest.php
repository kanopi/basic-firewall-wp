<?php
/**
 * Validating settings twice must not change them.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Transfer\Exporter;
use Kanopi\BasicFirewall\Transfer\Importer;
use PHPUnit\Framework\TestCase;

/**
 * Every rule type must be able to read back what it just wrote.
 *
 * This stopped being a nicety the moment the importer began running incoming
 * rule settings through their own type's validator. Before that, the rule form
 * was the only caller and it always passed what a human had typed; now the
 * input is as likely to be a document this plugin exported, which holds the
 * *validated* shape.
 *
 * A type that cannot read its own output fails in the worst available way: the
 * import succeeds, the rule appears, and part of its configuration is gone.
 * Rate limiting was exactly that -- a path stored as a map went through a
 * line-splitting helper, stringified to "Array", and was rejected, so importing
 * a rate limit rule exported from this plugin produced a rule with no limits
 * and no complaint.
 *
 * @covers \Kanopi\BasicFirewall\RuleType\Registry
 */
final class ValidationIdempotenceTest extends TestCase {

	/**
	 * Validating a type's own output returns that output unchanged.
	 *
	 * @dataProvider rule_types
	 *
	 * @param string $id Rule type identifier.
	 */
	public function test_validation_is_idempotent( string $id ): void {
		$type = Plugin::instance()->rule_types()->get( $id );

		$this->assertNotNull( $type, sprintf( 'The %s rule type is not registered.', $id ) );

		$errors = array();
		$once   = $type->validate_settings( $type->default_settings(), $errors );
		$twice  = $type->validate_settings( $once, $errors );

		$this->assertSame(
			$once,
			$twice,
			sprintf( 'The %s type cannot read back its own validated settings, so an import of a document it exported loses configuration.', $id )
		);
	}

	/**
	 * Every registered type.
	 *
	 * @return array<string, array{0: string}>
	 */
	public static function rule_types(): array {
		$cases = array();

		foreach ( array_keys( Plugin::instance()->rule_types()->all() ) as $id ) {
			$cases[ (string) $id ] = array( (string) $id );
		}

		return $cases;
	}

	/**
	 * Export a rule, delete it, import it back, get the same rule.
	 *
	 * The pair the screens now offer, exercised as one. An export button with
	 * no counterpart is a one-way door; a counterpart that loses configuration
	 * on the way through is worse than none, because the rule comes back
	 * looking right.
	 */
	public function test_a_rule_survives_export_delete_import(): void {
		$settings = Plugin::instance()->settings();
		$snapshot = $settings->all();

		$rules = (array) $settings->get( 'rules', array() );

		if ( array() === $rules ) {
			$this->markTestSkipped( 'This site has no rules to round-trip.' );
		}

		$original = $rules[0];
		$id       = (string) $original['id'];

		try {
			$yaml = ( new Exporter() )->rule_to_yaml( $id );

			$this->assertIsString( $yaml );

			$without          = $snapshot;
			$without['rules'] = array_values(
				array_filter( $rules, static fn ( $rule ): bool => (string) ( $rule['id'] ?? '' ) !== $id )
			);

			$settings->replace( $without );

			$this->assertCount( count( $rules ) - 1, (array) $settings->get( 'rules', array() ) );

			$result = ( new Importer() )->import( $yaml, 'merge' );

			$this->assertTrue( $result['ok'], 'The exported rule would not import.' );

			$restored = null;

			foreach ( (array) $settings->get( 'rules', array() ) as $rule ) {
				if ( (string) ( $rule['id'] ?? '' ) === $id ) {
					$restored = $rule;
				}
			}

			$this->assertIsArray( $restored, sprintf( 'Rule "%s" did not come back.', $id ) );

			/*
			 * Nothing may be lost, and new keys may appear.
			 *
			 * An exact comparison was too strict to be useful: settings stored
			 * before a type grew a field gain that field's default on their
			 * next write, which is ordinary schema evolution and changes
			 * nothing about what the rule does. What must never happen is a
			 * value going out and not coming back -- which is precisely the
			 * rate limit bug this class exists for, where a path list made the
			 * round trip as an empty array.
			 */
			foreach ( $original['settings'] as $key => $value ) {
				$this->assertArrayHasKey(
					$key,
					$restored['settings'],
					sprintf( 'Rule "%s" lost its %s setting on the way through.', $id, $key )
				);

				$this->assertSame(
					$value,
					$restored['settings'][ $key ],
					sprintf( 'Rule "%s" came back with a different %s than it went out with.', $id, $key )
				);
			}
			$this->assertSame( $original['response'], $restored['response'] );
			$this->assertSame( $original['weight'], $restored['weight'] );
		} finally {
			$settings->replace( $snapshot );
			Plugin::instance()->compiled()->rebuild();
		}
	}

	/**
	 * A rule exported from this site survives being validated again.
	 *
	 * The round trip that matters, against this site's real rules rather than
	 * against defaults: export, re-validate, compare.
	 */
	public function test_exported_rules_survive_revalidation(): void {
		$rules = (array) Plugin::instance()->settings()->get( 'rules', array() );

		if ( array() === $rules ) {
			$this->markTestSkipped( 'This site has no rules to round-trip.' );
		}

		$exporter = new Exporter();

		foreach ( $rules as $rule ) {
			$id       = (string) ( $rule['id'] ?? '' );
			$exported = $exporter->export_rule( $id );

			$this->assertIsArray( $exported, sprintf( 'Rule %s could not be exported.', $id ) );

			$document = $exported['document']['rules'][0] ?? array();
			$type     = Plugin::instance()->rule_types()->get( (string) ( $document['type'] ?? '' ) );

			if ( null === $type ) {
				continue;
			}

			$errors      = array();
			$revalidated = $type->validate_settings( (array) ( $document['settings'] ?? array() ), $errors );

			$this->assertSame(
				(array) ( $document['settings'] ?? array() ),
				$revalidated,
				sprintf( 'Importing the exported rule "%s" would change its settings.', $id )
			);
		}
	}
}
