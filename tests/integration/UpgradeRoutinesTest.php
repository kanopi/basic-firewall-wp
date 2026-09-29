<?php
/**
 * Upgrade routines, run over documents as earlier releases stored them.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Install\Upgrader;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Support\Schema;

/**
 * What an upgrade leaves in the option, given what an older release wrote.
 *
 * Each test writes the option raw at an older schema version and runs the
 * upgrader from there, so the routines run in the order and combination a real
 * site would meet them -- which is where two routines can undo each other.
 *
 * @covers \Kanopi\BasicFirewall\Install\Upgrader
 */
final class UpgradeRoutinesTest extends Settings_Snapshot {

	/**
	 * Schema version as found, put back afterwards.
	 *
	 * @var mixed
	 */
	private $version;

	/**
	 * Remember the schema version.
	 */
	protected function setUp(): void {
		parent::setUp();

		$this->version = get_option( Schema::VERSION_OPTION, null );
	}

	/**
	 * Put the schema version back.
	 */
	protected function tearDown(): void {
		if ( null === $this->version ) {
			delete_option( Schema::VERSION_OPTION );
		} else {
			update_option( Schema::VERSION_OPTION, $this->version, false );
		}

		delete_option( Upgrader::FAILURE_OPTION );

		parent::tearDown();
	}

	/**
	 * Write a document with these rules raw, at a schema version, and upgrade.
	 *
	 * @param list<array<string, mixed>> $rules   Rules as the older release stored them.
	 * @param int                        $version The schema version the site is on.
	 *
	 * @return array<string, array<string, mixed>> The upgraded rules, by id.
	 */
	private function upgrade( array $rules, int $version ): array {
		$this->given_settings( array() );

		$document          = Plugin::instance()->settings()->all();
		$document['rules'] = $rules;

		update_option( Schema::OPTION, $document, false );
		update_option( Schema::VERSION_OPTION, $version, false );
		Plugin::instance()->settings()->flush();

		Upgrader::maybe_upgrade();
		Plugin::instance()->settings()->flush();

		$this->assertNull( Upgrader::failure() );
		$this->assertSame( Schema::VERSION, (int) get_option( Schema::VERSION_OPTION ) );

		$stored = (array) get_option( Schema::OPTION );

		return array_column( (array) $stored['rules'], null, 'id' );
	}

	/**
	 * A stored Request / URL rule.
	 *
	 * @param string                     $id         Rule id.
	 * @param list<array<string, mixed>> $conditions Conditions, as stored.
	 * @param string                     $match_type any or all.
	 *
	 * @return array<string, mixed>
	 */
	private static function url_rule( string $id, array $conditions, string $match_type = 'any' ): array {
		return array(
			'id'       => $id,
			'type'     => 'url',
			'label'    => $id,
			'enabled'  => true,
			'response' => 'block',
			'settings' => array(
				'match_type' => $match_type,
				'conditions' => $conditions,
				'sources'    => array(),
			),
		);
	}

	/**
	 * A stored condition.
	 *
	 * @param string $variable Variable.
	 * @param string $operator Operator.
	 * @param string $value    Value.
	 * @param bool   $negate   Negated.
	 *
	 * @return array<string, mixed>
	 */
	private static function condition( string $variable, string $operator, string $value, bool $negate = false ): array {
		return array(
			'variable' => $variable,
			'operator' => $operator,
			'value'    => $value,
			'negate'   => $negate,
		);
	}

	/**
	 * Routine 9 stores `referer` and `content_type` as the headers they are,
	 * and keeps the variables with no equivalent exactly as they were.
	 */
	public function test_url_variables_are_renamed_and_the_rest_kept(): void {
		$rules = $this->upgrade(
			array(
				self::url_rule(
					'url',
					array(
						self::condition( 'referer', 'not_contains', 'example.com' ),
						self::condition( 'content_type', 'contains', 'json' ),
						self::condition( 'uri', 'contains', 'x', true ),
						self::condition( 'server.SERVER_NAME', 'equals', 'example.com' ),
						self::condition( 'path', 'starts_with', '/wp-admin' ),
					),
					'all'
				),
			),
			8
		);

		$this->assertSame(
			array( 'header.referer', 'header.content-type', 'uri', 'server.SERVER_NAME', 'path' ),
			array_column( $rules['url']['settings']['conditions'], 'variable' )
		);
		$this->assertTrue( $rules['url']['settings']['conditions'][2]['negate'], 'A kept condition lost its negation.' );
	}
}
