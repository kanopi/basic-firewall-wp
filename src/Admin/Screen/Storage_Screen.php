<?php
/**
 * Blocked client storage settings.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Admin\Screen;

use Kanopi\BasicFirewall\Admin\Notices;
use Kanopi\BasicFirewall\Admin\Screen;
use Kanopi\BasicFirewall\Database_Credentials;

/**
 * Where the block list lives.
 */
final class Storage_Screen extends Screen {

	/**
	 * {@inheritDoc}
	 */
	public function slug(): string {
		return 'basic-firewall-storage';
	}

	/**
	 * {@inheritDoc}
	 */
	public function page_title(): string {
		return __( 'Storage', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function intro(): string {
		return wp_kses_post(
			__( 'When a rule blocks a request, the client is recorded so later requests are refused immediately without re-evaluating every rule. <strong>Switching backends does not move the block list</strong> — each keeps its own, so a client blocked under file storage is not blocked after a switch to database, and is blocked again if you switch back.', 'basic-firewall' )
		);
	}

	/**
	 * {@inheritDoc}
	 */
	public function handle(): void {
		if ( ! $this->verify() ) {
			return;
		}

		$settings = $this->plugin()->settings();
		$all      = $settings->all();

		$all['storage']['backend'] = $this->posted( 'backend', 'file' );

		$all['storage']['file']['storage_file'] = $this->posted( 'storage_file' );
		$all['storage']['file']['offense_file'] = $this->posted( 'offense_file' );

		$all['storage']['database']['storage_table']     = $this->posted( 'storage_table' );
		$all['storage']['database']['offenses_table']    = $this->posted( 'offenses_table' );
		$all['storage']['database']['connection_source'] = $this->posted( 'connection_source', 'wordpress' );

		$dsn = $this->posted( 'dsn' );

		/*
		 * An empty DSN field means "not carried", never "clear the stored one" --
		 * the same rule the importer follows, for the same reason. Somebody who
		 * genuinely wants to clear it changes the connection source.
		 */
		if ( '' !== $dsn ) {
			$all['storage']['database']['dsn'] = $dsn;
		}

		$problems = $settings->replace( $all );

		foreach ( $problems as $problem ) {
			Notices::add( sprintf( '<strong>%s</strong>: %s', esc_html( $problem['path'] ), esc_html( $problem['message'] ) ), 'error' );
		}

		if ( array() === $problems ) {
			Notices::add( __( 'Storage settings saved, and the firewall recompiled.', 'basic-firewall' ) );
		}

		$this->redirect( $this->slug() );
	}

	/**
	 * {@inheritDoc}
	 */
	public function render(): void {
		$settings    = $this->plugin()->settings();
		$credentials = new Database_Credentials();
		$backend     = (string) $settings->get( 'storage.backend', 'file' );

		$this->open_form();

		echo '<table class="form-table" role="presentation"><tbody>';

		$this->row(
			__( 'Backend', 'basic-firewall' ),
			self::select(
				'backend',
				array(
					'file'     => __( 'File — single web node, no database needed', 'basic-firewall' ),
					'database' => __( 'Database — shared between web nodes, flat lookup cost', 'basic-firewall' ),
				),
				$backend
			),
			wp_kses_post(
				__( '<strong>File</strong> is faster on a quiet site (0.007 ms against 0.07 ms) and is the only option that works on the wp-config.php evaluation path. Its lookup cost grows with the size of the block list — about 0.75 ms at 2,000 clients — so it gets slower exactly when the firewall is busiest. <strong>Database</strong> stays flat. File is the default because most sites never block at volume; switch once yours does.', 'basic-firewall' )
			)
		);

		echo '</tbody></table>';

		$this->open_section( __( 'File storage', 'basic-firewall' ), 'backend:file' );

		echo '<table class="form-table" role="presentation"><tbody>';

		$this->row(
			__( 'Blocked client file', 'basic-firewall' ),
			self::text( 'storage_file', (string) $settings->get( 'storage.file.storage_file', '' ) ),
			__( 'A relative path resolves inside the firewall\'s private directory, which is where this belongs — it stays portable between environments and is per-site on a network. An absolute path is used exactly as given.', 'basic-firewall' )
		);

		$this->row(
			__( 'Offense history file', 'basic-firewall' ),
			self::text( 'offense_file', (string) $settings->get( 'storage.file.offense_file', '' ) ),
			__( 'Left blank, this is derived from the file above. Two block lists sharing one offense history would escalate each other\'s clients, so the derived path is written out explicitly rather than left to a library default that has moved before.', 'basic-firewall' )
		);

		echo '</tbody></table>';

		$this->close_section();

		$this->open_section(
			__( 'Database storage', 'basic-firewall' ),
			'backend:database',
			__( 'Reusing WordPress\'s connection reads the credentials fresh on every request and hands them to the firewall then. They are <strong>never written into the compiled file</strong>, so exports stay free of secrets, a plaintext password never reaches disk, and a rotated password takes effect on the next request rather than at the next rebuild.', 'basic-firewall' )
		);

		echo '<table class="form-table" role="presentation"><tbody>';

		$this->row(
			__( 'Connection', 'basic-firewall' ),
			self::select(
				'connection_source',
				array(
					'wordpress' => __( 'Reuse WordPress\'s database credentials', 'basic-firewall' ),
					'dsn'       => __( 'A connection DSN I supply', 'basic-firewall' ),
					'preset'    => __( 'Let an enabled preset supply the connection', 'basic-firewall' ),
				),
				(string) $settings->get( 'storage.database.connection_source', 'wordpress' )
			),
			__( '<strong>Let a preset supply it</strong> exists because every other choice defeats the preset, silently: this plugin\'s compiled file is the base of the merge, so any connection it writes survives whatever the preset sets — and reusing WordPress\'s credentials is applied later still, replacing the preset\'s outright. Contributing nothing is the only way the preset\'s connection reaches the backend.', 'basic-firewall' )
		);

		$this->row(
			__( 'Connection DSN', 'basic-firewall' ),
			self::text( 'dsn', '', 'text', 'placeholder="mysqli://user:password@host:3306/database"' ),
			wp_kses_post(
				/* translators: the %env()% below is a literal token the firewall reads, not a placeholder. */
				__( 'The scheme must be a <strong>Doctrine driver name</strong>, not a database name: <code>mysqli://</code> works, <code>mysql://</code> is an unknown driver, and <code>pdo_mysql://</code> is not a valid URL scheme. Usable schemes are <code>mysqli</code>, <code>pgsql</code>, <code>sqlsrv</code>, <code>oci8</code> and <code>sqlite3</code>. A DSN embeds the password, so the whole string has to be a <code>%env()%</code> token or none of it can be. Leave blank to keep the stored value.', 'basic-firewall' )
			),
			'connection_source:dsn'
		);

		$storage_table  = (string) $settings->get( 'storage.database.storage_table', '' );
		$offenses_table = (string) $settings->get( 'storage.database.offenses_table', '' );

		$this->row(
			__( 'Blocked client table', 'basic-firewall' ),
			self::text( 'storage_table', $storage_table ),
			$this->prefix_note( $credentials, $storage_table )
		);

		$this->row(
			__( 'Offense history table', 'basic-firewall' ),
			self::text( 'offenses_table', $offenses_table ),
			$this->prefix_note( $credentials, $offenses_table )
		);

		echo '</tbody></table>';

		$this->close_section();

		$this->close_form();
	}

	/**
	 * Explain the resulting table name when a prefix applies.
	 *
	 * The form must never disagree with what is in the database.
	 *
	 * @param Database_Credentials $credentials Credentials reader.
	 * @param string               $table       The typed table name.
	 */
	private function prefix_note( Database_Credentials $credentials, string $table ): string {
		$prefix = $credentials->prefix();

		if ( '' === $prefix || '' === $table ) {
			return '';
		}

		$resolved = $credentials->prefix_table( $table );

		if ( $resolved === $table ) {
			return __( 'Already carries this site\'s table prefix, so it is used as typed.', 'basic-firewall' );
		}

		return sprintf(
			/* translators: %s: the resulting table name. */
			__( 'This site\'s table prefix is applied, so the real table is <code>%s</code>. The firewall reaches the database directly rather than through WordPress, so nothing else would apply it — and without it, every site in a network would share one block list.', 'basic-firewall' ),
			esc_html( $resolved )
		);
	}
}
