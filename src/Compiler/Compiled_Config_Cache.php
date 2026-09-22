<?php
/**
 * Writes and reads the compiled configuration file.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Compiler;

use Kanopi\BasicFirewall\Plugin;
use Symfony\Component\Yaml\Yaml;

/**
 * The compiled file: written here, read by the runtime.
 *
 * The file is a cache of the settings option. It is rebuilt when settings are
 * saved, when a document is imported, on activation, after an upgrade routine,
 * and on demand from the Rebuild screen or `wp basic-firewall rebuild`. It is
 * safe to delete.
 *
 * Two things about how it is written are deliberate.
 *
 * **It is written atomically**, to a temporary file in the same directory and
 * then renamed. A partial file is a file the library parses into a partial
 * ruleset, and a partial ruleset enforces less than it claims to -- so the file
 * has to appear complete or not at all. Same directory because rename() is only
 * atomic within a filesystem.
 *
 * **The connection paths are stored alongside it**, not in it. The compiler
 * records where live database credentials belong; that list is kept in an option
 * so the runner can apply them without re-running the compiler on every request.
 */
final class Compiled_Config_Cache {

	/**
	 * Option holding the injection paths and compile metadata.
	 */
	public const META_OPTION = 'basic_firewall_compiled_meta';

	/**
	 * Header written at the top of every compiled file.
	 */
	private const HEADER = <<<'TXT'
# Basic Firewall compiled configuration. DO NOT EDIT.
#
# This file is generated from the plugin's settings and is overwritten whenever
# they are saved, whenever a configuration is imported, and whenever the
# firewall is rebuilt. Anything you change here is lost on the next rebuild.
#
# It is a cache and is safe to delete. Do not commit it: it contains absolute
# paths specific to this environment.
TXT;

	/**
	 * Rebuild the compiled file.
	 *
	 * Never throws. A failure to compile must leave the site serving traffic and
	 * report the problem, not take the site down.
	 *
	 * @return array{written: bool, path: string, problems: list<string>}
	 */
	public function rebuild(): array {
		$paths = Plugin::instance()->paths();
		$path  = $paths->compiled_file();

		$problems = $paths->ensure();

		if ( array() !== $problems ) {
			$this->record_meta( array(), false, $problems );

			return array(
				'written'  => false,
				'path'     => $path,
				'problems' => $problems,
			);
		}

		$compiler = new Config_Compiler();

		try {
			$compiled = $compiler->compile();
		} catch ( \Throwable $e ) {
			$problems = array(
				sprintf(
					/* translators: %s: error message. */
					__( 'The configuration could not be compiled: %s', 'basic-firewall' ),
					$e->getMessage()
				),
			);

			$this->record_meta( array(), false, $problems );

			return array(
				'written'  => false,
				'path'     => $path,
				'problems' => $problems,
			);
		}

		$problems = $compiler->problems();
		$yaml     = self::HEADER . "\n\n" . Yaml::dump( $compiled, 10, 2, Yaml::DUMP_MULTI_LINE_LITERAL_BLOCK );

		if ( ! $this->write_atomically( $path, $yaml ) ) {
			$problems[] = sprintf(
				/* translators: %s: file path. */
				__( 'The compiled configuration could not be written to %s.', 'basic-firewall' ),
				$path
			);

			$this->record_meta( $compiler->connection_paths(), false, $problems );

			return array(
				'written'  => false,
				'path'     => $path,
				'problems' => $problems,
			);
		}

		$this->record_meta( $compiler->connection_paths(), true, $problems );

		/**
		 * Fires after the compiled configuration has been written.
		 *
		 * @param string       $path     Path of the compiled file.
		 * @param list<string> $problems Problems encountered while compiling.
		 */
		do_action( 'basic_firewall_compiled', $path, $problems );

		return array(
			'written'  => true,
			'path'     => $path,
			'problems' => $problems,
		);
	}

	/**
	 * Write a file atomically.
	 *
	 * @param string $path     Destination.
	 * @param string $contents What to write.
	 */
	private function write_atomically( string $path, string $contents ): bool {
		$directory = dirname( $path );

		if ( ! is_dir( $directory ) && ! wp_mkdir_p( $directory ) ) {
			return false;
		}

		// Same directory: rename() is only atomic within one filesystem.
		$temporary = tempnam( $directory, 'bfw' );

		if ( false === $temporary ) {
			return false;
		}

		if ( false === file_put_contents( $temporary, $contents ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
			wp_delete_file( $temporary );

			return false;
		}

		// tempnam() creates at 0600, which the web server may not be able to read
		// back if the rebuild ran as a different user under WP-CLI.
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions -- WP_Filesystem cannot be relied on here, and a failure to widen permissions is not fatal.
		@chmod( $temporary, 0644 );

		/*
		 * rename() rather than WP_Filesystem::move(), deliberately: this is the
		 * atomic step. WP_Filesystem offers no guarantee of atomicity, and a
		 * half-written compiled file is a partial rule set that enforces less
		 * than it claims to.
		 */
		// phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename
		if ( ! rename( $temporary, $path ) ) {
			wp_delete_file( $temporary );

			return false;
		}

		return true;
	}

	/**
	 * Record what the compile produced.
	 *
	 * @param list<string> $connection_paths Where credentials must be injected.
	 * @param bool         $written          Whether the file was written.
	 * @param list<string> $problems         Problems encountered.
	 */
	private function record_meta( array $connection_paths, bool $written, array $problems ): void {
		$this->write_connection_paths( $connection_paths );

		update_option(
			self::META_OPTION,
			array(
				'connection_paths' => $connection_paths,
				'written'          => $written,
				'problems'         => $problems,
				'compiled_at'      => time(),
				'plugin_version'   => BASIC_FIREWALL_VERSION,
			),
			false
		);
	}

	/**
	 * Mirror the connection paths into the private directory.
	 *
	 * The normal path reads this list from an option. The wp-config.php path
	 * runs before WordPress exists and has no options, so without a copy on
	 * disk it could not inject credentials and database-backed block storage
	 * fell open there. The file carries path strings only -- `[storage][...]`
	 * and the like -- and never a credential, so the invariant that no password
	 * reaches disk is unchanged.
	 *
	 * A failure to write is not fatal: the early path then finds no file and
	 * behaves as it did before, which Site Health reports.
	 *
	 * @param list<string> $connection_paths Where credentials must be injected.
	 */
	private function write_connection_paths( array $connection_paths ): void {
		$path = Plugin::instance()->paths()->connection_paths_file();

		if ( array() === $connection_paths ) {
			if ( file_exists( $path ) ) {
				wp_delete_file( $path );
			}

			return;
		}

		$json = wp_json_encode( array_values( $connection_paths ) );

		if ( is_string( $json ) ) {
			$this->write_atomically( $path, $json );
		}
	}

	/**
	 * What the last compile recorded.
	 *
	 * @return array<string, mixed>
	 */
	public function meta(): array {
		$meta = get_option( self::META_OPTION, array() );

		return is_array( $meta ) ? $meta : array();
	}

	/**
	 * Where live credentials must be injected on every request.
	 *
	 * @return list<string>
	 */
	public function connection_paths(): array {
		$paths = $this->meta()['connection_paths'] ?? array();

		return is_array( $paths ) ? array_values( array_map( 'strval', $paths ) ) : array();
	}

	/**
	 * Whether a usable compiled file exists.
	 */
	public function exists(): bool {
		return is_readable( Plugin::instance()->paths()->compiled_file() );
	}

	/**
	 * The compiled file's contents, for the "view compiled configuration" screen.
	 */
	public function contents(): ?string {
		$path = Plugin::instance()->paths()->compiled_file();

		if ( ! is_readable( $path ) ) {
			return null;
		}

		$contents = file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- a local file, not a remote URL; WP_Filesystem is not loaded this early.

		return false === $contents ? null : $contents;
	}

	/**
	 * Delete the compiled file and its metadata.
	 */
	public function clear(): void {
		$path = Plugin::instance()->paths()->compiled_file();

		if ( is_readable( $path ) ) {
			wp_delete_file( $path );
		}

		$sidecar = Plugin::instance()->paths()->connection_paths_file();

		if ( file_exists( $sidecar ) ) {
			wp_delete_file( $sidecar );
		}

		delete_option( self::META_OPTION );
	}
}
