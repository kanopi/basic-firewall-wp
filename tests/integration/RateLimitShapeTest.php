<?php
/**
 * Rate limit paths, in both shapes they arrive in.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\RuleType\Types\Rate_Limit;
use Kanopi\BasicFirewall\Support\Schema;
use Kanopi\BasicFirewall\Transfer\Importer;
use Symfony\Component\Yaml\Yaml;
use PHPUnit\Framework\TestCase;

/**
 * A path arrives parsed or unparsed, and neither may throw.
 *
 * The rule form is the only thing that runs `validate_settings()`. An imported
 * configuration document, a deploy writing the settings option and a hand edit
 * all reach the rest of the plugin with whatever they stored — which for this
 * type is the `"pattern limit window"` line as typed, not the map the validator
 * produces.
 *
 * Reading only the map threw where the value was used. That was the rules
 * listing, so an import could leave the screen you would go to in order to find
 * the bad rule unable to load at all.
 *
 * Integration rather than unit because the type's own messages are translated,
 * and the unit suite is deliberately WordPress-free.
 *
 * @covers \Kanopi\BasicFirewall\RuleType\Types\Rate_Limit
 */
final class RateLimitShapeTest extends TestCase {

	/**
	 * Settings with the given paths.
	 *
	 * @param array<int, mixed> $paths Whatever is stored.
	 *
	 * @return array<string, mixed>
	 */
	private function settings( array $paths ): array {
		return array(
			'paths'                => $paths,
			'default_limit'        => 60,
			'default_window'       => 60,
			'limit_unlisted_paths' => false,
			'status_code'          => 429,
			'storage'              => array( 'backend' => 'file' ),
		);
	}

	/**
	 * The validated shape, which is what the form stores.
	 */
	public function test_a_validated_path_summarises(): void {
		$summary = ( new Rate_Limit() )->summarize(
			$this->settings(
				array(
					array(
						'pattern' => '/wp-login.php',
						'limit'   => 20,
						'window'  => 60,
					),
				)
			)
		);

		$this->assertStringContainsString( '/wp-login.php', $summary[0] );
		$this->assertStringContainsString( '20', $summary[0] );
	}

	/**
	 * The unvalidated shape, which is what an import stores.
	 */
	public function test_a_raw_line_summarises_rather_than_throwing(): void {
		$summary = ( new Rate_Limit() )->summarize(
			$this->settings( array( '/wp-login.php 20 60' ) )
		);

		$this->assertStringContainsString( '/wp-login.php', $summary[0] );
		$this->assertStringContainsString( '20', $summary[0], 'The limit has to survive the line being read here rather than by the validator.' );
	}

	/**
	 * And it compiles, rather than compiling to fewer paths in silence.
	 */
	public function test_a_raw_line_compiles(): void {
		$entry = ( new Rate_Limit() )->compile(
			array(
				'id'       => 'login-rate-limit',
				'response' => 'block',
				'settings' => $this->settings( array( '/wp-login.php 20 60', '/xmlrpc.php 5 60' ) ),
			)
		);

		$this->assertCount( 2, $entry['config'], 'A raw line skipped here compiles a rate limit covering fewer paths than were configured.' );
		$this->assertSame( '/wp-login.php', $entry['config'][0]['path'] );
		$this->assertSame( 20, $entry['config'][0]['rate'] );
		$this->assertSame( 60, $entry['config'][0]['sample'] );
	}

	/**
	 * Something neither shape can rescue is dropped, not fatal.
	 *
	 * @dataProvider unusable_paths
	 *
	 * @param array<int, mixed> $paths What is stored.
	 */
	public function test_unusable_paths_are_dropped( array $paths ): void {
		$type = new Rate_Limit();

		$this->assertIsArray( $type->summarize( $this->settings( $paths ) ) );

		$entry = $type->compile(
			array(
				'id'       => 'r',
				'response' => 'block',
				'settings' => $this->settings( $paths ),
			)
		);

		$this->assertSame( array(), $entry['config'] );
	}

	/**
	 * An imported document does not leave unvalidated settings behind.
	 *
	 * The root cause rather than the symptom. Until this was fixed the rule
	 * form was the only caller of `validate_settings()`, so a document could
	 * write any shape it liked straight into the settings option -- and the
	 * shapes are not interchangeable, so the next screen to read them threw.
	 */
	public function test_an_import_normalises_rule_settings(): void {
		$snapshot = get_option( Schema::OPTION, null );

		$document = Yaml::dump(
			array(
				'rules' => array(
					array(
						'id'       => 'imported-rate-limit',
						'type'     => 'rate_limit',
						'label'    => 'Imported',
						'enabled'  => true,
						'response' => 'block',
						'weight'   => 30,
						'settings' => array(
							// As typed, which is what a hand-written or
							// exported-then-edited document carries.
							'paths' => array( '/wp-login.php 20 60' ),
						),
					),
				),
			)
		);

		try {
			$result = ( new Importer() )->import( $document, 'merge' );

			$this->assertTrue( $result['ok'], 'The document did not import.' );

			$rules = (array) Plugin::instance()->settings()->get( 'rules', array() );
			$paths = null;

			foreach ( $rules as $rule ) {
				if ( 'imported-rate-limit' === ( $rule['id'] ?? '' ) ) {
					$paths = $rule['settings']['paths'] ?? null;
				}
			}

			$this->assertIsArray( $paths, 'The imported rule is missing.' );
			$this->assertIsArray(
				$paths[0],
				'An imported path was stored as the raw line, so every screen that reads it has to cope with a shape the form never produces.'
			);
			$this->assertSame( '/wp-login.php', $paths[0]['pattern'] );
			$this->assertSame( 20, $paths[0]['limit'] );
		} finally {
			if ( null === $snapshot ) {
				delete_option( Schema::OPTION );
			} else {
				update_option( Schema::OPTION, $snapshot, false );
			}

			Plugin::instance()->settings()->flush();
			Plugin::instance()->compiled()->rebuild();
		}
	}

	/**
	 * Shapes with nothing usable in them.
	 *
	 * @return array<string, array{0: array<int, mixed>}>
	 */
	public static function unusable_paths(): array {
		return array(
			'a map with no pattern' => array( array( array( 'nonsense' => true ) ) ),
			'an empty line'         => array( array( '' ) ),
			'a number'              => array( array( 42 ) ),
			'null'                  => array( array( null ) ),
		);
	}
}
