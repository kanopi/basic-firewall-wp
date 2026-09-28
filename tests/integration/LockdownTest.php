<?php
/**
 * Lockdown, refusing everyone but an allowlist.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Compiler\Library_Map;
use Kanopi\BasicFirewall\Health\Site_Health;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Runtime\Lockdown;
use Kanopi\Firewall\Exception\FirewallLockdownException;
use Kanopi\Firewall\Firewall;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Yaml\Yaml;

/**
 * The "let only the office in" switch, and the ways in and out of it.
 *
 * What makes it worth having over an allow rule plus a block-everything rule is
 * that nobody is recorded: that pairing refuses the same traffic and writes
 * every refused client to the block list. What makes it dangerous is that the
 * library reads an empty allowlist as "serve nobody" -- so the refusals here
 * matter as much as the lockdown does.
 *
 * @covers \Kanopi\BasicFirewall\Runtime\Lockdown
 * @covers \Kanopi\BasicFirewall\Runtime\Runner
 * @covers \Kanopi\BasicFirewall\Compiler\Config_Compiler
 * @covers \Kanopi\BasicFirewall\Health\Site_Health
 */
final class LockdownTest extends Settings_Snapshot {

	/**
	 * The office. RFC 5737 documentation space.
	 */
	private const OFFICE = '198.51.100.0/24';

	/**
	 * The panic file, relative, so it resolves inside the private directory.
	 */
	private const PANIC_FILE = 'test-lockdown-panic';

	/**
	 * Never leave a panic file on a real site.
	 */
	protected function tearDown(): void {
		$this->remove_panic_file();

		parent::tearDown();
	}

	/**
	 * An armed lockdown reaches the compiled file with its allowlist.
	 */
	public function test_an_armed_lockdown_is_compiled(): void {
		$this->arm( array( self::OFFICE ) );

		$global = $this->compiled_global();

		$this->assertTrue( $global['lockdown'] ?? false );
		$this->assertSame( array( self::OFFICE ), $global['lockdown_allow'] ?? null );
	}

	/**
	 * A site that has not armed it writes no lockdown key at all.
	 *
	 * The list is kept while lockdown is off, so it is ready mid-incident --
	 * but compiling it would be a list nothing reads.
	 */
	public function test_an_unarmed_lockdown_writes_nothing(): void {
		$this->given_settings(
			array(
				'global' => array(
					'lockdown'       => false,
					'lockdown_allow' => array( self::OFFICE ),
				),
			)
		);
		Plugin::instance()->compiled()->rebuild();

		$global = $this->compiled_global();

		$this->assertArrayNotHasKey( 'lockdown', $global );
		$this->assertArrayNotHasKey( 'lockdown_allow', $global );
		$this->assertFalse( Plugin::instance()->runner()->is_locked_down() );
	}

	/**
	 * An empty allowlist is refused at compile time, not applied.
	 *
	 * The screen refuses it too; this is every other way a document arrives --
	 * an import, WP-CLI, a hand-edited option. Applying it would refuse
	 * everybody, including whoever is trying to switch it off.
	 */
	public function test_an_empty_allowlist_is_not_applied(): void {
		$result = $this->arm( array() );

		$this->assertArrayNotHasKey( 'lockdown', $this->compiled_global() );
		$this->assertFalse( Plugin::instance()->runner()->is_locked_down(), 'An empty allowlist locked everybody out.' );
		$this->assertNotEmpty( $result['problems'], 'Refusing it silently would leave somebody wondering why lockdown is not on.' );
	}

	/**
	 * An entry the library cannot match is dropped, and said so.
	 */
	public function test_a_range_is_dropped_and_reported(): void {
		$result = $this->arm( array( self::OFFICE, '203.0.113.1-203.0.113.9' ) );

		$this->assertSame( array( self::OFFICE ), $this->compiled_global()['lockdown_allow'] ?? null );
		$this->assertNotEmpty( $result['problems'] );
	}

	/**
	 * The runner reports an armed lockdown, and Site Health calls it critical.
	 *
	 * While it is on, nothing else in Site Health describes what the site does
	 * to traffic.
	 */
	public function test_an_armed_lockdown_is_reported_as_critical(): void {
		$this->arm( array( self::OFFICE ) );

		$this->assertTrue( Plugin::instance()->runner()->is_locked_down() );
		$this->assertSame( 'critical', Site_Health::check( 'lockdown' )['status'] );
	}

	/**
	 * A site not in lockdown is not told it is.
	 */
	public function test_an_inactive_lockdown_is_not_reported(): void {
		$this->given_settings( array( 'global' => array( 'lockdown' => false ) ) );
		Plugin::instance()->compiled()->rebuild();

		$this->assertSame( 'good', Site_Health::check( 'lockdown' )['status'] );
	}

	/**
	 * A panic file naming lockdown arms it without touching settings.
	 *
	 * The case the feature exists for: no deploy and no edit to reach it, and
	 * none to leave it. Settings alone would say lockdown is off.
	 */
	public function test_a_panic_file_can_arm_lockdown(): void {
		$this->given_settings(
			array(
				'global' => array(
					'mode'           => 'block',
					'panic_file'     => self::PANIC_FILE,
					'lockdown'       => false,
					'lockdown_allow' => array( self::OFFICE ),
				),
			)
		);
		Plugin::instance()->compiled()->rebuild();

		$this->assertFalse( Plugin::instance()->runner()->is_locked_down() );

		file_put_contents( $this->panic_path(), 'lockdown' ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- a local fixture file.

		$this->assertTrue( Plugin::instance()->runner()->is_locked_down(), 'The panic file did not arm lockdown.' );
		$this->assertSame(
			'lockdown',
			Plugin::instance()->runner()->panic_switch()['effective'] ?? null,
			'The library unpacks lockdown into block; reporting "forcing block, configured block" would describe a closed site as unchanged.'
		);

		$this->remove_panic_file();

		$this->assertFalse( Plugin::instance()->runner()->is_locked_down(), 'Removing the file did not lift the lockdown it armed.' );
	}

	/**
	 * The compiled lockdown refuses outsiders, serves the list, records nobody.
	 *
	 * Evaluated in `exception` mode, the one mode the library does not bypass
	 * under CLI, against in-memory storage so the test leaves no trace.
	 */
	public function test_the_compiled_lockdown_refuses_outsiders_and_records_nobody(): void {
		$this->arm( array( self::OFFICE ) );

		$store = sys_get_temp_dir() . '/bfw-lockdown-' . bin2hex( random_bytes( 6 ) );

		$overrides = array(
			'[global][mode]'    => 'exception',
			'[storage][type]'   => Library_Map::STORAGE['file'],
			'[storage][config]' => array(
				'storage_file' => $store . '.data',
				'offense_file' => $store . '.offenses',
			),
		);

		$firewall = Firewall::create( array( Plugin::instance()->paths()->compiled_file() ), $overrides );

		$this->assertTrue(
			$firewall->evaluate( Request::create( '/', 'GET', array(), array(), array(), array( 'REMOTE_ADDR' => '198.51.100.20' ) ) ),
			'An allowlisted address was refused.'
		);

		try {
			$firewall->evaluate( Request::create( '/', 'GET', array(), array(), array(), array( 'REMOTE_ADDR' => '203.0.113.20' ) ) );
			$this->fail( 'An address off the allowlist was served.' );
		} catch ( FirewallLockdownException $e ) {
			$this->assertSame( 503, $e->getStatusCode(), 'A lockdown is temporary, and the status has to say so.' );
		}

		$recorded = '';

		foreach ( array( $store . '.data', $store . '.offenses' ) as $file ) {
			if ( is_file( $file ) ) {
				$recorded .= (string) file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- a local file this test's firewall wrote.
				unlink( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- a local fixture file.
			}
		}

		$this->assertStringNotContainsString(
			'203.0.113.20',
			$recorded,
			'The refused visitor was recorded, so lifting the lockdown would leave them banned.'
		);
	}

	/**
	 * The screen's review refuses an empty list and warns about yourself.
	 */
	public function test_the_review_refuses_an_empty_list_and_warns_about_you(): void {
		$empty = Lockdown::review( true, Lockdown::sort( '' ), '198.51.100.20' );
		$this->assertNotNull( $empty['error'], 'An empty allowlist could be armed from the screen.' );

		$not_you = Lockdown::review( true, Lockdown::sort( self::OFFICE ), '203.0.113.20' );
		$this->assertNull( $not_you['error'], 'Allowlisting somewhere else is a real thing to want.' );
		$this->assertNotNull( $not_you['warning'], 'Nobody was told they are about to be locked out.' );

		$you = Lockdown::review( true, Lockdown::sort( self::OFFICE ), '198.51.100.20' );
		$this->assertNull( $you['error'] );
		$this->assertNull( $you['warning'] );
	}

	/**
	 * A range is refused even while lockdown is off.
	 *
	 * The list is kept so it is ready mid-incident, and discovering then that
	 * an entry never matched is the worst time to find out.
	 */
	public function test_the_review_refuses_a_range_even_while_off(): void {
		$review = Lockdown::review( false, Lockdown::sort( "198.51.100.0/24\n203.0.113.1-203.0.113.9" ), '' );

		$this->assertNotNull( $review['error'] );
	}

	/**
	 * Arm lockdown with the given allowlist and recompile.
	 *
	 * @param list<string> $allow Allowlist.
	 *
	 * @return array{written: bool, path: string, problems: list<string>}
	 */
	private function arm( array $allow ): array {
		$this->given_settings(
			array(
				'global' => array(
					'lockdown'       => true,
					'lockdown_allow' => $allow,
				),
			)
		);

		return Plugin::instance()->compiled()->rebuild();
	}

	/**
	 * The compiled global section.
	 *
	 * @return array<string, mixed>
	 */
	private function compiled_global(): array {
		$compiled = Yaml::parseFile( Plugin::instance()->paths()->compiled_file() );

		return is_array( $compiled ) ? (array) ( $compiled['global'] ?? array() ) : array();
	}

	/**
	 * Where the panic file resolves to.
	 */
	private function panic_path(): string {
		return Plugin::instance()->paths()->resolve( self::PANIC_FILE );
	}

	/**
	 * Remove the panic file, if there is one.
	 */
	private function remove_panic_file(): void {
		if ( is_file( $this->panic_path() ) ) {
			unlink( $this->panic_path() ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- a local fixture file.
		}
	}
}
