<?php
/**
 * The panic file, the lever that does not need a deploy.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Health\Site_Health;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Request_Tester;

/**
 * Turning the firewall down mid-incident used to mean editing wp-config.php.
 *
 * On most hosting that is a release -- the fix gated behind the slowest thing
 * available, while a rule refuses real customers.
 *
 * The design fails safe in a way worth pinning down, because the obvious design
 * does not. The file has to *name* a mode: a `touch`ed file, a typo, or one that
 * cannot be read changes nothing at all. If any file meant "off", one left
 * behind from an incident last month would silently disable the firewall and
 * nothing would say so.
 *
 * The other half is noticing. A switch nobody remembers flipping is the
 * realistic failure, so Site Health has to say it is on -- and, being critical,
 * so does an admin notice on every screen.
 *
 * @covers \Kanopi\BasicFirewall\Runtime\Runner
 * @covers \Kanopi\BasicFirewall\Compiler\Config_Compiler
 * @covers \Kanopi\BasicFirewall\Health\Site_Health
 */
final class PanicSwitchTest extends Settings_Snapshot {

	/**
	 * The configured path, relative, so it resolves inside the private directory.
	 */
	private const PANIC_FILE = 'test-panic';

	/**
	 * Arm the switch, with nothing at its path yet.
	 */
	protected function setUp(): void {
		parent::setUp();

		$this->remove_panic_file();

		$this->given_settings(
			array(
				'enabled' => true,
				'global'  => array(
					'mode'       => 'block',
					'panic_file' => self::PANIC_FILE,
				),
			)
		);

		$this->assertTrue( Plugin::instance()->compiled()->rebuild()['written'] );
	}

	/**
	 * Never leave a panic file on a real site.
	 */
	protected function tearDown(): void {
		$this->remove_panic_file();

		parent::tearDown();
	}

	/**
	 * An armed but idle switch is not reported, and changes nothing.
	 *
	 * The ordinary state of a site that has configured the lever and not pulled
	 * it. Reporting that would make the signal worthless.
	 */
	public function test_an_armed_but_idle_switch_is_silent(): void {
		$this->assertNull( Plugin::instance()->runner()->panic_switch() );
		$this->assertSame( 'good', Site_Health::check( 'panic' )['status'] );
	}

	/**
	 * A file naming a mode takes effect, and both modes are reported.
	 */
	public function test_a_named_mode_takes_effect(): void {
		$this->write_panic_file( 'log' );

		$switch = Plugin::instance()->runner()->panic_switch();

		$this->assertIsArray( $switch );
		$this->assertTrue( $switch['active'] );
		$this->assertSame( 'log', $switch['effective'] );
		$this->assertSame( 'block', $switch['configured'], 'What the mode returns to is reported too.' );
	}

	/**
	 * Case and surrounding whitespace do not matter.
	 *
	 * `echo LOG > panic` at two in the morning should work.
	 */
	public function test_case_and_whitespace_are_forgiven(): void {
		$this->write_panic_file( "  LOG\n" );

		$switch = Plugin::instance()->runner()->panic_switch();

		$this->assertIsArray( $switch );
		$this->assertTrue( $switch['active'] );
		$this->assertSame( 'log', $switch['effective'] );
	}

	/**
	 * A misspelled mode changes nothing, and is reported as a problem.
	 *
	 * The half that keeps a leftover file from disabling a firewall silently.
	 */
	public function test_a_misspelled_mode_changes_nothing(): void {
		$this->write_panic_file( 'lgo' );

		$switch = Plugin::instance()->runner()->panic_switch();

		$this->assertIsArray( $switch );
		$this->assertFalse( $switch['active'], 'A typo turned the firewall down.' );
		$this->assertNotNull( $switch['problem'], 'But it is not silently ignored either.' );
		$this->assertSame( 'block', $switch['effective'], 'The configured mode still governs.' );
	}

	/**
	 * An empty file changes nothing either.
	 *
	 * `touch panic` is the most likely way somebody arms this by accident.
	 */
	public function test_an_empty_file_changes_nothing(): void {
		$this->write_panic_file( '' );

		$switch = Plugin::instance()->runner()->panic_switch();

		$this->assertIsArray( $switch );
		$this->assertFalse( $switch['active'] );
		$this->assertNotNull( $switch['problem'] );
	}

	/**
	 * Removing the file returns the firewall to its configured mode.
	 */
	public function test_removing_the_file_restores_the_configured_mode(): void {
		$this->write_panic_file( 'log' );

		$this->assertTrue( Plugin::instance()->runner()->panic_switch()['active'] ?? false );

		$this->remove_panic_file();

		$this->assertNull( Plugin::instance()->runner()->panic_switch() );
	}

	/**
	 * An active switch is critical in Site Health, naming both modes.
	 *
	 * Critical rather than recommended: while it is on, every other entry on
	 * that page describes a firewall that is not the one running.
	 */
	public function test_an_active_switch_is_critical(): void {
		$this->write_panic_file( 'log' );

		$result = Site_Health::check( 'panic' );

		$this->assertSame( 'critical', $result['status'] );
		$this->assertStringContainsString( 'log', $result['description'] );
		$this->assertStringContainsString( 'block', $result['description'], 'The mode it returns to is not named.' );
	}

	/**
	 * An unusable file is a recommendation rather than critical.
	 *
	 * Nothing is being overridden, so critical would overstate it -- but
	 * somebody wrote that file expecting it to do something.
	 */
	public function test_an_unusable_file_is_a_recommendation(): void {
		$this->write_panic_file( 'lgo' );

		$this->assertSame( 'recommended', Site_Health::check( 'panic' )['status'] );
	}

	/**
	 * A site that arms nothing pays for nothing.
	 *
	 * The key is only written when set, so the library is not asked to stat a
	 * path on every request for a switch that does not exist.
	 */
	public function test_an_unconfigured_switch_writes_no_key(): void {
		$this->given_settings( array( 'global' => array( 'panic_file' => '' ) ) );
		Plugin::instance()->compiled()->rebuild();

		$this->assertStringNotContainsString( 'panic_file', $this->compiled() );
	}

	/**
	 * The configured path is resolved, so the library can stat it.
	 *
	 * It is read with a bare is_file(), which resolves a relative path against
	 * the working directory -- the web root under php-fpm, somewhere else under
	 * WP-CLI. Written as typed, the same setting would arm different files
	 * depending on who asked.
	 */
	public function test_the_configured_path_is_resolved_in_the_compiled_file(): void {
		$this->assertStringContainsString( $this->panic_path(), $this->compiled() );
	}

	/**
	 * The request tester answers for the rules, not for the incident.
	 *
	 * Its firewall runs in `exception` mode so a block throws rather than ending
	 * the admin page. A panic file is applied over that -- so without the tester
	 * disarming it, `block` in the file would call exit() mid-screen, and `log`
	 * would report every request as allowed.
	 */
	public function test_the_request_tester_ignores_the_panic_file(): void {
		$this->given_settings(
			array(
				'enabled' => true,
				'global'  => array(
					'mode'       => 'block',
					'panic_file' => self::PANIC_FILE,
				),
				'rules'   => array(
					array(
						'id'       => 'panic_tester',
						'label'    => 'Panic tester',
						'type'     => 'ip_address',
						'response' => 'block',
						'enabled'  => true,
						'weight'   => 0,
						'settings' => array( 'addresses' => array( '203.0.113.99' ) ),
					),
				),
			)
		);
		Plugin::instance()->compiled()->rebuild();

		$this->write_panic_file( 'log' );

		$result = ( new Request_Tester() )->test(
			array(
				'path' => '/',
				'ip'   => '203.0.113.99',
			)
		);

		$this->assertSame( 'block', $result['verdict'], 'The panic file decided the tester\'s answer.' );
	}

	/**
	 * Where the configured file resolves to.
	 */
	private function panic_path(): string {
		return Plugin::instance()->paths()->resolve( self::PANIC_FILE );
	}

	/**
	 * Write the panic file.
	 *
	 * @param string $contents What to put in it.
	 */
	private function write_panic_file( string $contents ): void {
		file_put_contents( $this->panic_path(), $contents ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- a local fixture file.
	}

	/**
	 * Remove the panic file, if there is one.
	 */
	private function remove_panic_file(): void {
		if ( is_file( $this->panic_path() ) ) {
			unlink( $this->panic_path() ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- a local fixture file.
		}
	}

	/**
	 * The compiled configuration, as written.
	 */
	private function compiled(): string {
		return (string) file_get_contents( Plugin::instance()->paths()->compiled_file() ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- a local file this test just wrote.
	}
}
