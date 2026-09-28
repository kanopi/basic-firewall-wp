<?php
/**
 * Keeping the installed mu-plugin loader in step with the shipped one.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Health\Site_Health;
use Kanopi\BasicFirewall\Install\Mu_Loader;
use PHPUnit\Framework\TestCase;

/**
 * The loader is a copy, and a copy goes stale.
 *
 * Until this existed the copy was written by activation and never again, so a
 * release that changed the loader reached a site only if somebody deactivated
 * and reactivated the firewall -- and the only instruction to do so was in the
 * changelog. These pin the refresh that replaced that instruction: what it
 * replaces, what it must leave alone, and that a directory it cannot write is
 * reported rather than fatal.
 *
 * Most of them run against a scratch directory, which is why Mu_Loader takes
 * its directory as an argument. The ones that prove a trigger is wired up have
 * to use the real mu-plugins directory, and they put the site's own loader
 * back byte for byte, with its modification time, whatever happens.
 */
final class MuLoaderRefreshTest extends TestCase {

	/**
	 * Scratch mu-plugins directory.
	 *
	 * @var string
	 */
	private string $directory = '';

	/**
	 * The loader this copy of the plugin ships.
	 *
	 * @var string
	 */
	private string $source = '';

	/**
	 * The network option as it stood before the test.
	 *
	 * @var mixed
	 */
	private $failure_before = null;

	/**
	 * Make the scratch directory.
	 */
	protected function setUp(): void {
		parent::setUp();

		$this->source    = dirname( __DIR__, 2 ) . '/mu-plugin/' . Mu_Loader::FILENAME;
		$this->directory = sys_get_temp_dir() . '/bfw-mu-' . bin2hex( random_bytes( 4 ) );

		wp_mkdir_p( $this->directory );

		$this->failure_before = get_site_option( Mu_Loader::REFRESH_FAILURE_OPTION, null );
	}

	/**
	 * Remove it, and the failure any test recorded.
	 */
	protected function tearDown(): void {
		// phpcs:disable WordPress.WP.AlternativeFunctions -- test scaffolding; WP_Filesystem is not initialised in the test bootstrap.
		chmod( $this->directory, 0755 );

		foreach ( $this->directory_listing() as $name ) {
			$file = $this->directory . '/' . $name;

			if ( is_file( $file ) ) {
				chmod( $file, 0644 );
				unlink( $file );
			}
		}

		rmdir( $this->directory );
		// phpcs:enable

		if ( null === $this->failure_before ) {
			delete_site_option( Mu_Loader::REFRESH_FAILURE_OPTION );
		} else {
			update_site_option( Mu_Loader::REFRESH_FAILURE_OPTION, $this->failure_before );
		}

		parent::tearDown();
	}

	/**
	 * A loader from an older release is replaced with the shipped one.
	 */
	public function test_an_older_version_is_replaced(): void {
		$loader = $this->scratch_loader();

		$this->put( $loader->path(), $this->older_loader() );

		$this->assertSame( Mu_Loader::REFRESHED, $loader->refresh() );
		$this->assertSame(
			$this->shipped(),
			$this->contents( $loader->path() ),
			'An older loader was left in place, so the site keeps whatever the release that changed it fixed.'
		);
		$this->assertSame(
			array( Mu_Loader::FILENAME ),
			$this->directory_listing(),
			'The refresh left a temporary file behind in mu-plugins.'
		);
	}

	/**
	 * A loader whose version matches but whose contents do not is replaced too.
	 *
	 * The content comparison is what catches a release that changed the loader
	 * without bumping its version, and a copy somebody edited by hand.
	 */
	public function test_different_contents_under_the_same_version_are_replaced(): void {
		$loader = $this->scratch_loader();

		$this->put( $loader->path(), $this->shipped() . "\n// edited on the server\n" );

		$this->assertSame( Mu_Loader::REFRESHED, $loader->refresh() );
		$this->assertSame( $this->shipped(), $this->contents( $loader->path() ) );
	}

	/**
	 * An up-to-date loader is not written at all.
	 */
	public function test_a_current_loader_is_not_rewritten(): void {
		$loader = $this->scratch_loader();
		$then   = time() - 3600;

		$this->put( $loader->path(), $this->shipped() );
		touch( $loader->path(), $then ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- test scaffolding.
		clearstatcache();

		$this->assertSame( Mu_Loader::CURRENT, $loader->refresh() );

		clearstatcache();

		$this->assertSame(
			$then,
			filemtime( $loader->path() ),
			'A current loader was rewritten. Every trigger would then rewrite mu-plugins for nothing, and invalidate its opcode cache each time.'
		);
	}

	/**
	 * A loader that is not there is not put back.
	 *
	 * It may have been removed on purpose, and the plugin may not be active on
	 * the site that happened to trigger the refresh. Only activation installs.
	 */
	public function test_a_removed_loader_is_not_recreated(): void {
		$loader = $this->scratch_loader();

		$this->assertSame( Mu_Loader::ABSENT, $loader->refresh() );
		$this->assertFileDoesNotExist(
			$loader->path(),
			'A refresh recreated a loader that had been removed, overriding whoever removed it.'
		);
	}

	/**
	 * A file under the loader's name that is not the loader is left alone.
	 */
	public function test_a_file_that_is_not_ours_is_left_alone(): void {
		$loader  = $this->scratch_loader();
		$foreign = "<?php\n// Somebody else's mu-plugin that happens to share the name.\n";

		$this->put( $loader->path(), $foreign );

		$this->assertSame( Mu_Loader::FOREIGN, $loader->refresh() );
		$this->assertSame( $foreign, $this->contents( $loader->path() ) );
	}

	/**
	 * An unwritable directory is reported in Site Health, not fatal.
	 */
	public function test_an_unwritable_directory_is_reported_not_fatal(): void {
		$loader = $this->scratch_loader();

		$this->put( $loader->path(), $this->older_loader() );

		// phpcs:disable WordPress.WP.AlternativeFunctions -- test scaffolding.
		chmod( $loader->path(), 0444 );
		chmod( $this->directory, 0555 );
		// phpcs:enable
		clearstatcache();

		if ( wp_is_writable( $this->directory ) ) {
			$this->markTestSkipped( 'This process can write to a read-only directory (running as root?), so it cannot be made unwritable.' );
		}

		$this->assertSame( Mu_Loader::FAILED, $loader->refresh() );
		$this->assertSame( $this->older_loader(), $this->contents( $loader->path() ), 'The loader changed although the directory was read-only.' );

		$failure = Mu_Loader::refresh_failure();

		$this->assertNotNull( $failure, 'The failure was not recorded, so nothing would tell an administrator.' );
		$this->assertStringContainsString( 'not writable', (string) $failure );

		$result = Site_Health::check( 'evaluation' );

		if ( 'critical' === $result['status'] && false === strpos( $result['description'], (string) $failure ) ) {
			$this->markTestSkipped( 'The evaluation check returned an earlier critical result on this site: ' . $result['label'] );
		}

		$this->assertNotSame( 'good', $result['status'], 'A loader that could not be refreshed was reported as healthy.' );
		$this->assertStringContainsString(
			esc_html( (string) $failure ),
			$result['description'],
			'Site Health does not say why the loader could not be refreshed.'
		);

		// And once it can be written, the next refresh succeeds and the report clears.
		chmod( $this->directory, 0755 ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- test scaffolding.
		chmod( $loader->path(), 0644 ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- test scaffolding.
		clearstatcache();

		$this->assertSame( Mu_Loader::REFRESHED, $loader->refresh() );
		$this->assertNull( Mu_Loader::refresh_failure(), 'A successful refresh left the old failure on record.' );
	}

	/**
	 * Updating this plugin through the WordPress updater refreshes the loader.
	 */
	public function test_updating_this_plugin_refreshes_the_real_loader(): void {
		$this->with_stale_real_loader(
			function ( string $target ): void {
				Mu_Loader::refresh_after_update(
					null,
					array(
						'type'    => 'plugin',
						'action'  => 'update',
						'plugins' => array( 'hello.php' ),
					)
				);

				$this->assertNotSame( $this->shipped(), $this->contents( $target ), 'Updating some other plugin refreshed the loader.' );

				Mu_Loader::refresh_after_update(
					null,
					array(
						'type'    => 'plugin',
						'action'  => 'update',
						'plugins' => array( plugin_basename( BASIC_FIREWALL_FILE ) ),
					)
				);

				$this->assertSame( $this->shipped(), $this->contents( $target ), 'Updating this plugin did not refresh the loader.' );
			}
		);
	}

	/**
	 * A schema upgrade refreshes the loader.
	 */
	public function test_a_schema_upgrade_refreshes_the_real_loader(): void {
		$this->with_stale_real_loader(
			function ( string $target ): void {
				do_action( 'basic_firewall_upgraded' );

				$this->assertSame( $this->shipped(), $this->contents( $target ), 'basic_firewall_upgraded did not refresh the loader.' );
			}
		);
	}

	/**
	 * Running the Site Health test refreshes the loader before reporting on it.
	 */
	public function test_the_site_health_test_refreshes_the_real_loader(): void {
		$this->with_stale_real_loader(
			function ( string $target ): void {
				$tests = Site_Health::add_tests( array() );

				$tests['direct']['basic_firewall_evaluation']['test']();

				$this->assertSame( $this->shipped(), $this->contents( $target ), 'Opening Site Health did not refresh the loader.' );
			}
		);
	}

	/**
	 * Replace the site's real loader with a stale one, run a check, put it back.
	 *
	 * Restored from the bytes and the modification time read before anything
	 * was touched, in a finally, so a failing assertion cannot leave the DDEV
	 * site -- or anyone's -- with a different loader from the one it had.
	 *
	 * @param callable(string): void $check Receives the real loader's path.
	 */
	private function with_stale_real_loader( callable $check ): void {
		$real   = Mu_Loader::instance();
		$target = $real->path();

		if ( ! is_file( $target ) ) {
			$this->markTestSkipped( 'The loader is not installed on this site, and a refresh never creates one.' );
		}

		if ( ! wp_is_writable( dirname( $target ) ) ) {
			$this->markTestSkipped( 'The real mu-plugins directory is not writable here.' );
		}

		$before_bytes = $this->contents( $target );
		$before_mtime = (int) filemtime( $target );
		$before_mode  = fileperms( $target ) & 0777;

		try {
			$this->put( $target, $this->older_loader() );

			$check( $target );
		} finally {
			$this->put( $target, $before_bytes );
			chmod( $target, $before_mode ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- restoring what the test changed.
			touch( $target, $before_mtime ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- restoring what the test changed.
			clearstatcache();

			if ( function_exists( 'opcache_invalidate' ) ) {
				opcache_invalidate( $target, true );
			}
		}

		$this->assertSame( $before_bytes, $this->contents( $target ), 'The site\'s own loader was not restored.' );
	}

	/**
	 * A Mu_Loader pointed at the scratch directory.
	 */
	private function scratch_loader(): Mu_Loader {
		return new Mu_Loader( $this->directory, $this->source );
	}

	/**
	 * The shipped loader.
	 */
	private function shipped(): string {
		return $this->contents( $this->source );
	}

	/**
	 * The shipped loader as a release before versioned loaders would have had it.
	 */
	private function older_loader(): string {
		$older = preg_replace( "/^define\\( 'BASIC_FIREWALL_MU_LOADER_VERSION'.*\$\\n/m", '', $this->shipped() );
		$older = str_replace( 'Version:     ' . Mu_Loader::VERSION, 'Version:     1.0.0', (string) $older );

		$this->assertNotSame( $this->shipped(), $older, 'Could not derive an older loader from the shipped one.' );

		return $older;
	}

	/**
	 * A file's contents.
	 *
	 * @param string $path File.
	 */
	private function contents( string $path ): string {
		clearstatcache();

		return (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- a local file.
	}

	/**
	 * Write a file.
	 *
	 * @param string $path     File.
	 * @param string $contents Contents.
	 */
	private function put( string $path, string $contents ): void {
		file_put_contents( $path, $contents ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- test scaffolding.
		clearstatcache();
	}

	/**
	 * Every file in the scratch directory, dot files included.
	 *
	 * @return list<string>
	 */
	private function directory_listing(): array {
		return array_values( array_diff( (array) scandir( $this->directory ), array( '.', '..' ) ) );
	}
}
