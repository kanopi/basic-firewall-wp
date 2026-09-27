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
use Kanopi\BasicFirewall\Cache\Cache_Backend;
use Kanopi\BasicFirewall\Cache\Cache_Clearer;
use Kanopi\BasicFirewall\Database_Credentials;
use Kanopi\BasicFirewall\Library_Capabilities;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Settings;
use Kanopi\BasicFirewall\Support\Paths;

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

		if ( 'clear_cache' === $this->posted( 'storage_action' ) ) {
			$this->clear_cache();
		}

		$settings = $this->plugin()->settings();
		$all      = $settings->all();

		$previous = (string) ( $all['storage']['backend'] ?? 'file' );
		$backend  = $this->posted( 'backend', 'file' );

		/*
		 * Redis is only offered where it can work, so choosing it here without
		 * it is a stale form or a hand-built request. Refused rather than
		 * stored: the block list would keep nothing. A site already on Redis
		 * keeps it -- it did not choose anything just now, and flipping it to
		 * file would move the block list without asking.
		 */
		if ( 'redis' === $backend && 'redis' !== $previous && ! ( new Library_Capabilities() )->has_redis_storage() ) {
			Notices::add( esc_html( $this->redis_unavailable_reason() ), 'error' );

			$backend = $previous;
		}

		$all['storage']['backend'] = $backend;

		$all['storage']['file']['storage_file'] = $this->posted( 'storage_file' );
		$all['storage']['file']['offense_file'] = $this->posted( 'offense_file' );

		$all['storage']['database']['storage_table']     = $this->posted( 'storage_table' );
		$all['storage']['database']['offenses_table']    = $this->posted( 'offenses_table' );
		$all['storage']['database']['connection_source'] = $this->posted( 'connection_source', 'wordpress' );

		foreach ( array( 'cookies', 'headers', 'query', 'body' ) as $bucket ) {
			$all['storage']['record_request'][ $bucket ] = $this->posted_textarea( 'record_' . $bucket );
		}

		$this->take_redis( $all );
		$this->take_cache( $all );

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

		if ( 'redis' === $backend && ! ( new Library_Capabilities() )->has_redis_storage() ) {
			Notices::add( esc_html( $this->redis_unavailable_reason() ), 'error' );
		}

		$this->redirect( $this->slug() );
	}

	/**
	 * {@inheritDoc}
	 */
	public function render(): void {
		$settings     = $this->plugin()->settings();
		$credentials  = new Database_Credentials();
		$backend      = (string) $settings->get( 'storage.backend', 'file' );
		$redis_usable = ( new Library_Capabilities() )->has_redis_storage();

		$options = array(
			'file'     => __( 'File — single web node, no database needed', 'basic-firewall' ),
			'database' => __( 'Database — shared between web nodes, flat lookup cost', 'basic-firewall' ),
		);

		/*
		 * Offered where it can work, and shown where it is already chosen even
		 * though it cannot. Dropping the option outright for a site already on
		 * it would leave the select on its first entry, and the next save --
		 * of anything on this screen -- would move the block list to file
		 * storage without anybody deciding to.
		 */
		if ( $redis_usable ) {
			$options['redis'] = __( 'Redis — shared between web nodes, and expiry costs nothing', 'basic-firewall' );
		} elseif ( 'redis' === $backend ) {
			$options['redis'] = __( 'Redis — not usable on this server; change it', 'basic-firewall' );
		}

		$backend_note = __( '<strong>File</strong> is faster on a quiet site (0.007 ms against 0.07 ms), but its lookup cost grows with the size of the block list — about 0.75 ms at 2,000 clients — so it gets slower exactly when the firewall is busiest. <strong>Database</strong> stays flat. File is the default because most sites never block at volume; switch once yours does. Both work on the wp-config.php evaluation path, provided the bootstrap is required below the DB_ constants — the Dashboard shows the snippet and the placement.', 'basic-firewall' );

		if ( $redis_usable ) {
			$backend_note .= '<br><br>' . __( '<strong>Redis</strong> also works on the wp-config.php path, because it needs no WordPress credentials — everything it connects with is in the compiled file.', 'basic-firewall' );
		} elseif ( 'redis' !== $backend ) {
			$backend_note .= '<br><br>' . esc_html( $this->redis_unavailable_reason() );
		}

		if ( 'redis' === $backend && ! $redis_usable ) {
			printf(
				'<div class="notice notice-error inline"><p>%s</p></div>',
				esc_html( $this->redis_unavailable_reason() . ' ' . __( 'The firewall is still evaluating every rule, but on this server it keeps no block list at all: no client is recorded, repeat offenders are never recognised, and escalation never happens.', 'basic-firewall' ) )
			);
		}

		$this->open_form();

		echo '<table class="form-table" role="presentation"><tbody>';

		$this->row(
			__( 'Backend', 'basic-firewall' ),
			self::select( 'backend', $options, $backend ),
			wp_kses_post( $backend_note )
		);

		echo '</tbody></table>';

		if ( isset( $options['redis'] ) ) {
			$this->render_redis( $settings );
		}

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
			wp_kses_post(
				__( '<strong>Reuse WordPress\'s credentials</strong> does not copy anything into the compiled file. Nothing is written there to look at — the compiled configuration carries the two table names and no connection at all, and the host, user and password are read fresh from <code>wp-config.php</code> on every request and handed to the library in memory. That is deliberate: the compiled file lives under uploads, which on nginx this plugin has measured to be readable over the web, and an exported configuration cannot leak a password it never contained. It also means a rotated password takes effect on the next request rather than the next rebuild, which is what makes this work on a host that rotates credentials for you.', 'basic-firewall' )
				. '<br><br>' . __( '<strong>Let a preset supply it</strong> exists because every other choice defeats the preset, silently: this plugin\'s compiled file is the base of the merge, so any connection it writes survives whatever the preset sets — and reusing WordPress\'s credentials is applied later still, replacing the preset\'s outright. Contributing nothing is the only way the preset\'s connection reaches the backend.', 'basic-firewall' )
			)
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

		$this->render_record_request( $settings );

		$this->render_cache( $settings );

		$this->close_form();

		$this->render_cache_actions();
	}

	/**
	 * Copy the posted cache backend into the document.
	 *
	 * A backend that cannot work here is refused when newly chosen and kept
	 * when already chosen, for the reason Redis is: refusing protects a site
	 * from a choice that does nothing, and keeping stops an unrelated save from
	 * changing a setting nobody touched.
	 *
	 * @param array<string, mixed> $all The settings document, by reference.
	 */
	private function take_cache( array &$all ): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verify() is called by handle().
		if ( ! isset( $_POST['cache_backend'] ) ) {
			return;
		}

		$previous = (string) ( $all['cache']['backend'] ?? 'filesystem' );
		$backend  = $this->posted( 'cache_backend', 'filesystem' );
		$refusal  = $backend === $previous ? null : $this->cache_backend_refusal( $backend );

		if ( null !== $refusal ) {
			Notices::add( esc_html( $refusal ), 'error' );

			$backend = $previous;
		}

		$all['cache']['backend']   = $backend;
		$all['cache']['directory'] = $this->posted( 'cache_directory' );
		$all['cache']['apcu_ttl']  = $this->posted( 'cache_apcu_ttl', '86400' );
	}

	/**
	 * Why a cache backend cannot be chosen on this server, or null.
	 *
	 * @param string $backend The backend.
	 */
	private function cache_backend_refusal( string $backend ): ?string {
		if ( 'object_cache' === $backend && ! Cache_Backend::has_persistent_object_cache() ) {
			return __( 'The object cache was not chosen: this site has no persistent object cache, so it forgets everything when the request ends. The firewall would rebuild its agent detection corpus — the better part of a second — on every request. Install an object-cache.php drop-in for Redis or Memcached first.', 'basic-firewall' );
		}

		if ( 'apcu' === $backend && ! Cache_Backend::has_apcu() ) {
			return __( 'APCu was not chosen: it is not enabled in this server\'s PHP. Agent detection would run uncached — roughly 600 ms a request — rather than falling back to files.', 'basic-firewall' );
		}

		return null;
	}

	/**
	 * Discard the cached data on every backend, then return to the screen.
	 *
	 * Unsaved changes on the form are deliberately not applied first: this
	 * clears what is cached now, under the settings actually in force, which
	 * is what somebody reaching for it is asking for.
	 */
	private function clear_cache(): void {
		$cleared = ( new Cache_Clearer() )->clear();

		Notices::add(
			array() === $cleared
				? __( 'There was no cached data to clear.', 'basic-firewall' )
				: __( 'The firewall\'s cached data was cleared. It is built again as requests need it.', 'basic-firewall' )
		);

		$this->redirect( $this->slug() );
	}

	/**
	 * Where the firewall caches what it works out.
	 *
	 * @param Settings $settings Current settings.
	 */
	private function render_cache( Settings $settings ): void {
		$backend    = (string) $settings->get( 'cache.backend', 'filesystem' );
		$persistent = Cache_Backend::has_persistent_object_cache();
		$apcu       = Cache_Backend::has_apcu();
		$constant   = Paths::cache_dir_constant();

		$this->open_section(
			__( 'Where the firewall caches what it works out', 'basic-firewall' ),
			'',
			wp_kses_post(
				__( 'Separate from the block list above, and holding different things: parsed user agents and verified crawler names. All of it can be worked out again — losing it costs a rebuild, never a client going unblocked. Where uploads is a network mount, which it is on most managed hosting, this is usually where the firewall spends its time: not one slow read but many small ones through the request.', 'basic-firewall' )
			)
		);

		$options = array(
			'filesystem' => __( 'Files — the default', 'basic-firewall' ),
		);

		/*
		 * Each offered where it can work, and shown where already chosen even
		 * though it cannot, so the select does not quietly land on files and
		 * the next save switch it without anybody deciding to.
		 */
		if ( $persistent ) {
			$options['object_cache'] = __( 'The WordPress object cache — whatever the object-cache.php drop-in connects to', 'basic-firewall' );
		} elseif ( 'object_cache' === $backend ) {
			$options['object_cache'] = __( 'The WordPress object cache — not persistent on this site; files are used instead', 'basic-firewall' );
		}

		if ( $apcu ) {
			$options['apcu'] = __( 'APCu — memory on each web node, not shared between them', 'basic-firewall' );
		} elseif ( 'apcu' === $backend ) {
			$options['apcu'] = __( 'APCu — not enabled on this server', 'basic-firewall' );
		}

		$note = __( 'Files and APCu are written into the compiled configuration, so the wp-config.php evaluation path honours them too. The object cache cannot be: it is handed over as an object while WordPress is loading, and that path runs before WordPress exists — it keeps using files there, and only there.', 'basic-firewall' );

		if ( ! $persistent && 'object_cache' !== $backend ) {
			$note .= '<br><br>' . __( 'The object cache is not offered: this site has no persistent object cache, and WordPress\'s default one forgets everything when the request ends.', 'basic-firewall' );
		}

		if ( ! $apcu && 'apcu' !== $backend ) {
			$note .= '<br><br>' . __( 'APCu is not offered: it is not enabled in this server\'s PHP.', 'basic-firewall' );
		}

		echo '<table class="form-table" role="presentation"><tbody>';

		$this->row( __( 'Cache backend', 'basic-firewall' ), self::select( 'cache_backend', $options, $backend ), wp_kses_post( $note ) );

		$this->row(
			__( 'Cache directory', 'basic-firewall' ),
			self::text( 'cache_directory', (string) $settings->get( 'cache.directory', '' ), 'text', 'placeholder="/tmp/basic-firewall"' ),
			sprintf(
				/* translators: %s: the directory used when the field is left empty. */
				__( 'Left empty, the firewall caches in <code>%s</code>. Somewhere local such as <code>/tmp/basic-firewall</code> keeps these off a network mount, and losing them costs a rebuild and nothing else. A relative path resolves inside the firewall\'s private directory.', 'basic-firewall' ),
				esc_html( Plugin::instance()->paths()->library_cache_dir() )
			),
			'cache_backend:filesystem'
		);

		$this->row(
			__( 'How long an entry lives', 'basic-firewall' ),
			self::text( 'cache_apcu_ttl', (string) $settings->get( 'cache.apcu_ttl', 86400 ), 'number', 'min="60"' ) . ' ' . esc_html__( 'seconds', 'basic-firewall' ),
			__( 'APCu is memory on this web node and is not shared with any other, so each node warms its own copy, and all of them lose it when PHP restarts. That costs a rebuild and nothing else.', 'basic-firewall' ),
			'cache_backend:apcu'
		);

		$this->row(
			__( 'What stays on files', 'basic-firewall' ),
			'',
			null === $constant
				? sprintf(
					/* translators: 1: the constant, as PHP. 2: the directory in use. */
					__( 'Two caches are files whatever is chosen above, because the wp-config.php path reads them before WordPress exists: the parsed configuration and the bodies of imported rule lists, in <code>%2$s</code>. Move them with a constant in wp-config.php, which both evaluation paths read: <code>%1$s</code>. A setting here could not reach the early path, and the two paths disagreeing would leave imported lists matching nothing there.', 'basic-firewall' ),
					esc_html( "define( 'BASIC_FIREWALL_CACHE_DIR', '/tmp/basic-firewall' );" ),
					esc_html( Plugin::instance()->paths()->library_cache_dir() )
				)
				: sprintf(
					/* translators: %s: directory path. */
					__( 'BASIC_FIREWALL_CACHE_DIR is set, so the parsed configuration and the bodies of imported rule lists are kept in <code>%s</code>, on both evaluation paths.', 'basic-firewall' ),
					esc_html( $constant )
				)
		);

		echo '</tbody></table>';

		$this->close_section();
	}

	/**
	 * The controls that act on the cache rather than configure it.
	 *
	 * A form of its own, below the settings, so pressing one never saves a
	 * half-edited settings form -- and so saving the settings never clears
	 * anything.
	 */
	private function render_cache_actions(): void {
		$this->open_form();

		echo '<h2>' . esc_html__( 'Cached data', 'basic-firewall' ) . '</h2>';

		printf(
			'<p class="description" style="max-width:48rem">%s</p>',
			wp_kses_post(
				__( 'Discards what the firewall has cached, on every backend rather than only the current one, and lets it be built again as requests need it. The parsed configuration and imported list bodies are kept: losing either would weaken the firewall until they came back. APCu belongs to the web server\'s processes, so this button — which runs in a web request — is the only place its clear can reach; <code>wp basic-firewall clear-cache</code> clears everything else.', 'basic-firewall' )
			)
		);

		printf(
			'<p><button type="submit" name="storage_action" value="clear_cache" class="button">%s</button></p>',
			esc_html__( 'Clear cached data', 'basic-firewall' )
		);

		echo '</form>';
	}

	/**
	 * Why Redis is not offered here, naming whichever half is missing.
	 *
	 * The two are different fixes made by different people -- a library update
	 * against the host's PHP build -- so saying only "unavailable" would send
	 * somebody to the wrong one.
	 */
	private function redis_unavailable_reason(): string {
		if ( ! ( new Library_Capabilities() )->has_redis_storage_class() ) {
			return __( 'Redis block list storage is not offered: the installed firewall library does not provide it. It needs kanopi/firewall 2.22.0 or later.', 'basic-firewall' );
		}

		return __( 'Redis block list storage is not offered: this server\'s PHP does not have the redis extension loaded. The library lists it as a suggestion rather than a requirement, so it can be present without it — ask your host to enable ext-redis.', 'basic-firewall' );
	}

	/**
	 * Copy the posted Redis fields into the document.
	 *
	 * Only when the section was rendered. On a server where Redis is neither
	 * usable nor chosen the fields are absent, and reading them as empty would
	 * blank a stored configuration every time anything else on this screen was
	 * saved.
	 *
	 * @param array<string, mixed> $all The settings document, by reference.
	 */
	private function take_redis( array &$all ): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verify() is called by handle().
		if ( ! isset( $_POST['redis_host'] ) ) {
			return;
		}

		$all['storage']['redis']['host']     = $this->posted( 'redis_host', '127.0.0.1' );
		$all['storage']['redis']['port']     = $this->posted( 'redis_port', '6379' );
		$all['storage']['redis']['prefix']   = $this->posted( 'redis_prefix' );
		$all['storage']['redis']['username'] = $this->posted( 'redis_username' );

		if ( '' !== $this->posted( 'redis_password_clear' ) ) {
			$all['storage']['redis']['password'] = '';

			return;
		}

		/*
		 * Read as typed rather than through sanitize_text_field(), which trims
		 * and strips: a password is whatever was issued, and quietly altering
		 * it produces an authentication failure nobody can see on this screen.
		 * It is never echoed back into the page, so nothing here reaches HTML.
		 *
		 * Empty means "keep the stored one" -- the field is never pre-filled,
		 * so the stored password does not travel to the browser on every visit.
		 */
		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- verified in handle(); a password is kept byte for byte.
		$password = isset( $_POST['redis_password'] ) && is_string( $_POST['redis_password'] ) ? wp_unslash( $_POST['redis_password'] ) : '';

		if ( '' !== $password ) {
			$all['storage']['redis']['password'] = $password;
		}
	}

	/**
	 * The Redis connection.
	 *
	 * @param Settings $settings Current settings.
	 */
	private function render_redis( Settings $settings ): void {
		$this->open_section(
			__( 'Redis storage', 'basic-firewall' ),
			'backend:redis',
			wp_kses_post(
				__( 'File and database storage both sweep expired blocks as they go. Redis does not need to: a block is stored with a TTL and Redis evicts it itself, so the sweep has nothing to do at all. That matters most during an attack, which is when the block list is largest and when you least want a lapsed batch landing on one unlucky visitor. If the server cannot be reached the firewall carries on enforcing every rule and Site Health names the backend it is running without.', 'basic-firewall' )
			)
		);

		echo '<table class="form-table" role="presentation"><tbody>';

		$this->row(
			__( 'Host', 'basic-firewall' ),
			self::text( 'redis_host', (string) $settings->get( 'storage.redis.host', '127.0.0.1' ) ),
			wp_kses_post( __( 'A hostname or address. A Unix socket path such as <code>/var/run/redis/redis.sock</code> also works.', 'basic-firewall' ) )
		);

		$this->row(
			__( 'Port', 'basic-firewall' ),
			self::text( 'redis_port', (string) $settings->get( 'storage.redis.port', 6379 ), 'number', 'min="1" max="65535"' )
		);

		$credentials = new Database_Credentials();

		$this->row(
			__( 'Key prefix', 'basic-firewall' ),
			self::text( 'redis_prefix', (string) $settings->get( 'storage.redis.prefix', '' ), 'text', 'placeholder="' . esc_attr( $credentials->block_list_key_prefix() ) . '"' ),
			sprintf(
				/* translators: %s: the prefix used when the field is left empty. */
				__( 'Every key this site writes starts with it. Left empty, it is <code>%s</code>, which on a network includes this site\'s table prefix — so sites sharing one Redis do not share one block list. Anything typed here is used exactly, so give each site its own.', 'basic-firewall' ),
				esc_html( $credentials->block_list_key_prefix() )
			)
		);

		$this->row(
			__( 'Username', 'basic-firewall' ),
			self::text( 'redis_username', (string) $settings->get( 'storage.redis.username', '' ), 'text', 'autocomplete="off"' ),
			wp_kses_post( __( 'Only for a server using ACL authentication. Leave empty for the ordinary <code>requirepass</code> case, where a password alone is enough.', 'basic-firewall' ) )
		);

		$stored = (string) $settings->get( 'storage.redis.password', '' );

		$this->row(
			__( 'Password', 'basic-firewall' ),
			self::text( 'redis_password', '', 'password', 'autocomplete="new-password"' )
				. ( '' !== $stored ? '<br>' . self::checkbox( 'redis_password_clear', false, __( 'Remove the stored password', 'basic-firewall' ) ) : '' ),
			wp_kses_post(
				( '' !== $stored ? __( 'A password is stored. Leave blank to keep it. ', 'basic-firewall' ) : '' )
				/* translators: the %env()% below is a literal token the firewall reads, not a placeholder. */
				. __( 'Stored in the settings as typed and written into the compiled file, and stripped from an export. Type <code>%env(YOUR_VARIABLE)%</code> to read it from the environment instead: that is not a credential, survives an export, and never reaches the database.', 'basic-firewall' )
			)
		);

		echo '</tbody></table>';

		$this->close_section();
	}

	/**
	 * What a block record keeps about the request that caused it.
	 *
	 * Needs library 2.31.0, which stopped records keeping the whole cookie jar
	 * and header set. Surfaced rather than left at the library's defaults
	 * because three of the four buckets are a settled answer and the fourth is
	 * a decision this plugin cannot make for a site.
	 *
	 * @param Settings $settings Current settings.
	 */
	private function render_record_request( Settings $settings ): void {
		$this->open_section(
			__( 'What a block record keeps', 'basic-firewall' ),
			'',
			wp_kses_post(
				__( 'When a rule blocks a request, the request is recorded alongside the address so an operator can see what was blocked and why. That record outlives the request by the length of the ban, and it is the thing that gets pasted into a ticket — so it keeps an <strong>allowlist</strong> of each part of the request rather than all of it. One name per line. A single <code>*</code> keeps everything in that bucket; an empty field keeps nothing.', 'basic-firewall' )
			)
		);

		echo '<table class="form-table" role="presentation"><tbody>';

		$this->row(
			__( 'Cookies', 'basic-firewall' ),
			self::textarea( 'record_cookies', (string) $settings->get( 'storage.record_request.cookies', '' ), 3 ),
			wp_kses_post(
				__( 'Empty by default, and the one bucket with no argument on the other side: a blocked visitor\'s session cookie is not the firewall\'s to hold, and a record that keeps it is a stored login for the duration of the ban.', 'basic-firewall' )
			)
		);

		$this->row(
			__( 'Headers', 'basic-firewall' ),
			self::textarea( 'record_headers', (string) $settings->get( 'storage.record_request.headers', '' ), 8 ),
			wp_kses_post(
				__( 'Matched case-insensitively. The default list is the one the library ships: the headers that <em>describe</em> a client rather than authenticate it, so nothing in it can be replayed to become somebody. <code>Cookie</code>, <code>Authorization</code> and anything ending in <code>-Token</code> are the reason this is an allowlist.', 'basic-firewall' )
			)
		);

		$this->row(
			__( 'Query parameters', 'basic-firewall' ),
			self::textarea( 'record_query', (string) $settings->get( 'storage.record_request.query', '' ), 3 ),
			wp_kses_post(
				__( '<strong>Everything, by default, and this is the one to think about.</strong> For a scanner — the commonest reason anybody reads a block record — the query string <em>is</em> the attack, so narrowing this guts the record for the thing it is most often read about. But WordPress puts working secrets in query strings: <code>wp-login.php?action=rp&amp;key=…</code> is a password reset, and <code>wp-activate.php?key=…</code> is an account. A blocked request to one of those stores a usable credential. Site Health counts how many of your current records hold one.', 'basic-firewall' )
			)
		);

		$this->row(
			__( 'Request body fields', 'basic-firewall' ),
			self::textarea( 'record_body', (string) $settings->get( 'storage.record_request.body', '' ), 3 ),
			wp_kses_post(
				__( 'Empty by default. A blocked login attempt has the password in it.', 'basic-firewall' )
			)
		);

		echo '</tbody></table>';

		$this->close_section();
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
