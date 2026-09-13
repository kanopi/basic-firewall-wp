<?php
/**
 * The rule type registry, and the filter third parties extend it through.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\RuleType\Registry;
use Kanopi\BasicFirewall\RuleType\Rule_Type_Base;
use Kanopi\Firewall\Plugins\Url as LibraryUrl;
use PHPUnit\Framework\TestCase;

/**
 * That another plugin can add a rule type, and cannot quietly replace one.
 *
 * Drupal discovers rule types by scanning for an attribute. WordPress has no
 * discovery at all, so `basic_firewall_rule_types` is the entire extension
 * story -- and an extension point nobody has exercised is a claim, not a
 * feature.
 *
 * The interesting assertion is the last one. A contributed type declares which
 * of its own settings are credentials, and the exporter reads that declaration
 * rather than a list of its own. So a secret belonging to a rule type this
 * plugin has never heard of is still stripped from an export, which is the only
 * way that guarantee can hold for code that did not exist when the exporter was
 * written.
 */
final class RuleTypeRegistryTest extends TestCase {

	/**
	 * Filters added by a test, removed afterwards.
	 *
	 * @var list<callable>
	 */
	private array $filters = array();

	/**
	 * Leave the registry as it was found.
	 */
	protected function tearDown(): void {
		foreach ( $this->filters as $filter ) {
			remove_filter( 'basic_firewall_rule_types', $filter );
		}

		$this->filters = array();

		Plugin::instance()->rule_types()->reset();

		parent::tearDown();
	}

	/**
	 * Register a contributed type for the duration of one test.
	 *
	 * @param string $id       The type's id.
	 * @param int    $weight   Where it sorts.
	 * @param int    $priority Filter priority.
	 */
	private function given_contributed_type( string $id, int $weight = 500, int $priority = 10 ): void {
		$filter = static function ( array $types ) use ( $id, $weight ): array {
			$types[ $id ] = new class( $id, $weight ) extends Rule_Type_Base {

				/**
				 * Construct.
				 *
				 * @param string $id     The type's id.
				 * @param int    $weight Where it sorts.
				 */
				public function __construct( private string $id, private int $weight ) {}

				/**
				 * {@inheritDoc}
				 */
				public function id(): string {
					return $this->id;
				}

				/**
				 * {@inheritDoc}
				 */
				public function label(): string {
					return 'Contributed ' . $this->id;
				}

				/**
				 * {@inheritDoc}
				 */
				public function description(): string {
					return 'A rule type contributed by another plugin.';
				}

				/**
				 * {@inheritDoc}
				 */
				public function library_class(): string {
					return LibraryUrl::class;
				}

				/**
				 * {@inheritDoc}
				 */
				public function weight(): int {
					return $this->weight;
				}

				/**
				 * {@inheritDoc}
				 */
				public function default_settings(): array {
					return array( 'contributed_key' => '' );
				}

				/**
				 * {@inheritDoc}
				 */
				public function secret_settings(): array {
					return array( 'contributed_key' );
				}

				/**
				 * {@inheritDoc}
				 *
				 * @param array<string, mixed>  $settings Raw settings.
				 * @param array<string, string> $errors   Problems, by reference.
				 */
				public function validate_settings( array $settings, array &$errors ): array {
					return array( 'contributed_key' => (string) ( $settings['contributed_key'] ?? '' ) );
				}

				/**
				 * {@inheritDoc}
				 *
				 * @param array<string, mixed> $rule The whole rule.
				 */
				public function compile( array $rule ): array {
					$entry = $this->base_entry( $rule );

					$entry['config'] = array(
						array(
							'variable' => 'path',
							'operator' => 'equals',
							'value'    => '/contributed',
						),
					);

					return $entry;
				}
			};

			return $types;
		};

		add_filter( 'basic_firewall_rule_types', $filter, $priority );

		$this->filters[] = $filter;

		Plugin::instance()->rule_types()->reset();
	}

	/**
	 * The filter adds a type, and it is a first-class one.
	 */
	public function test_the_filter_can_add_a_rule_type(): void {
		$registry = Plugin::instance()->rule_types();

		$this->assertFalse( $registry->has( 'contributed_one' ), 'The type exists before it was contributed.' );

		$this->given_contributed_type( 'contributed_one' );

		$registry = Plugin::instance()->rule_types();

		$this->assertTrue( $registry->has( 'contributed_one' ), 'The filter did not add the type.' );
		$this->assertNotContains( 'contributed_one', $registry->shipped_ids(), 'A contributed type must not claim to be shipped.' );
	}

	/**
	 * A contributed type sorts by its own weight, like any other.
	 */
	public function test_a_contributed_type_sorts_by_weight(): void {
		$this->given_contributed_type( 'contributed_first', -500 );

		$ids = array_keys( Plugin::instance()->rule_types()->all() );

		$this->assertSame(
			'contributed_first',
			$ids[0],
			'A contributed type with the lowest weight should be evaluated first.'
		);
	}

	/**
	 * A contributed type cannot take the id of a shipped one.
	 *
	 * Silently replacing a shipped type would let a plugin change what an
	 * existing rule compiles to without anything in the interface changing.
	 */
	public function test_a_shipped_type_wins_a_collision(): void {
		$this->given_contributed_type( 'ip_address', 500, 99 );

		$type = Plugin::instance()->rule_types()->get( 'ip_address' );

		$this->assertNotNull( $type );
		$this->assertSame(
			'Kanopi\\Firewall\\Plugins\\IpAddress',
			$type->library_class(),
			'A contributed type hijacked a shipped id.'
		);
	}

	/**
	 * The filter can remove a type a site must not offer.
	 */
	public function test_the_filter_can_remove_a_type(): void {
		$filter = static function ( array $types ): array {
			unset( $types['geolocation'] );

			return $types;
		};

		add_filter( 'basic_firewall_rule_types', $filter );

		$this->filters[] = $filter;

		Plugin::instance()->rule_types()->reset();

		$this->assertFalse(
			Plugin::instance()->rule_types()->has( 'geolocation' ),
			'A type removed through the filter is still registered.'
		);
	}

	/**
	 * A contributed type's credentials are redacted from an export.
	 *
	 * The exporter has never heard of `contributed_key`. It is stripped because
	 * the type declares it, which is what makes the guarantee hold for code
	 * written after the exporter was.
	 */
	public function test_a_contributed_types_secret_is_redacted(): void {
		$this->given_contributed_type( 'contributed_secrets' );

		$settings = Plugin::instance()->settings();
		$snapshot = $settings->all();

		$values          = $snapshot;
		$values['rules'] = array(
			array(
				'id'       => 'contributed',
				'type'     => 'contributed_secrets',
				'label'    => 'Contributed',
				'enabled'  => true,
				'response' => 'block',
				'weight'   => 0,
				'settings' => array( 'contributed_key' => 'SECRET-contributed-must-not-leak' ),
			),
		);

		$settings->replace( $values );
		$settings->flush();

		$exporter = new \Kanopi\BasicFirewall\Transfer\Exporter();
		$export   = $exporter->export();
		$yaml     = $exporter->to_yaml();

		$settings->replace( $snapshot );
		$settings->flush();

		$this->assertStringNotContainsString(
			'SECRET-contributed-must-not-leak',
			$yaml,
			'A contributed rule type\'s credential reached the export.'
		);

		$this->assertContains(
			'rules.0.settings.contributed_key',
			$export['redacted'],
			'The export did not say it had removed the contributed credential.'
		);
	}
}
