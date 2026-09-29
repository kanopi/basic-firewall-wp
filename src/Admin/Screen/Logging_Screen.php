<?php
/**
 * Logging settings.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Admin\Screen;

use Kanopi\BasicFirewall\Admin\Notices;
use Kanopi\BasicFirewall\Admin\Screen;
use Kanopi\BasicFirewall\Compiler\Library_Map;

/**
 * Where firewall events go.
 */
final class Logging_Screen extends Screen {

	/**
	 * {@inheritDoc}
	 */
	public function slug(): string {
		return 'basic-firewall-logging';
	}

	/**
	 * {@inheritDoc}
	 */
	public function page_title(): string {
		return __( 'Logging', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function intro(): string {
		return wp_kses_post(
			__( 'The firewall logs through Monolog rather than through WordPress, because it runs before WordPress\'s logging exists. Blocks — and, in log-only mode, would-be blocks — are recorded at <code>warning</code>. Keep logs in the private directory: a log under a public directory is downloadable by anyone and discloses exactly which addresses you are blocking.', 'basic-firewall' )
		);
	}

	/**
	 * One log handler, as a card.
	 *
	 * Every type's fields are rendered in every card and shown by condition,
	 * rather than only the chosen type's. Two reasons. Choosing a type used to
	 * show nothing until the form had been saved, so adding a handler took two
	 * round trips to discover what it even asked for. And a card cloned by the
	 * "Add handler" button has to be able to become any type without going back
	 * to the server for the fields.
	 *
	 * The conditions name this card's own type select by its indexed field
	 * name, so two cards cannot read each other's state. With JavaScript off
	 * every field stays visible, which is the behaviour this replaced.
	 *
	 * @param int                   $index    Position in the list.
	 * @param array<string, mixed>  $handler  Its settings.
	 * @param array<string, string> $types    Available handler types.
	 * @param array<string, string> $levels   Available log levels.
	 * @param bool                  $blank    Whether this is the empty "new" card.
	 */
	private function render_handler( int $index, array $handler, array $types, array $levels, bool $blank ): void {
		$name  = sprintf( 'handlers[%d]', $index );
		$type  = (string) ( $handler['type'] ?? '' );
		$when  = static fn ( string $values ): string => sprintf( '%s[type]:%s', $name, $values );
		$title = '' !== $type ? (string) ( $types[ $type ] ?? $type ) : __( 'New handler', 'basic-firewall' );

		printf(
			'<div class="bfw-repeat__item%s" data-bfw-item>',
			$blank ? ' bfw-repeat__item--new' : ''
		);

		printf(
			'<div class="bfw-repeat__head"><strong>%s</strong>%s</div>',
			esc_html( $title ),
			$blank
				? ''
				: sprintf(
					'<button type="button" class="button-link bfw-repeat__remove" data-bfw-remove>%s</button>',
					esc_html__( 'Remove', 'basic-firewall' )
				)
		);

		echo '<table class="form-table" role="presentation"><tbody>';

		$this->row(
			__( 'Handler', 'basic-firewall' ),
			self::select( $name . '[type]', array( '' => __( '— none —', 'basic-firewall' ) ) + $types, $type )
			. ' ' . self::checkbox( $name . '[enabled]', $blank ? true : ! empty( $handler['enabled'] ), __( 'Enabled', 'basic-firewall' ) ),
			esc_html__( 'Setting this back to "none" removes the handler.', 'basic-firewall' )
		);

		$this->row(
			__( 'Minimum level', 'basic-firewall' ),
			self::select( $name . '[level]', $levels, (string) ( $handler['level'] ?? 'warning' ) ),
			wp_kses_post( __( '<strong>debug</strong> costs roughly 100 KB per allowed request on a file handler — about 97 MB per thousand requests. Right for diagnosing a rule; wrong to leave on.', 'basic-firewall' ) ),
			$when( 'rotating_file|stream|error_log|database' )
		);

		$this->row(
			__( 'Path', 'basic-firewall' ),
			self::text( $name . '[path]', (string) ( $handler['path'] ?? 'logs/firewall.log' ) ),
			wp_kses_post( __( 'A relative path resolves inside the firewall\'s private directory. Keep it there: a log under a public directory is downloadable by anyone and discloses exactly which addresses you are blocking. <code>php://stdout</code> and <code>php://stderr</code> are passed through for a container that collects the process output.', 'basic-firewall' ) ),
			$when( 'rotating_file|stream' )
		);

		$this->row(
			__( 'Days to keep', 'basic-firewall' ),
			self::text( $name . '[max_files]', (string) ( $handler['max_files'] ?? 14 ), 'number', 'min="0"' ),
			'',
			$when( 'rotating_file' )
		);

		$this->row(
			__( 'Table', 'basic-firewall' ),
			self::text( $name . '[table]', (string) ( $handler['table'] ?? 'basic_firewall_log' ) ),
			esc_html__( 'Created on first write. This site\'s table prefix is applied when the log shares WordPress\'s database.', 'basic-firewall' ),
			$when( 'database' )
		);

		/*
		 * Where a database handler connects. Not on this screen at first, and
		 * its handler rebuilt every handler from the fields it did render --
		 * so a handler imported with a DSN or individual parameters came back
		 * from the next save of this screen, by somebody who changed nothing,
		 * pointed at the WordPress database with its credentials gone.
		 *
		 * A tbody of its own so the whole group hides with the type, and each
		 * row inside it hides with the connection source.
		 */
		$source     = (string) ( $handler['connection_source'] ?? 'wordpress' );
		$dsn_stored = '' !== (string) ( $handler['dsn'] ?? '' );

		printf( '</tbody><tbody data-bfw-show-when="%s">', esc_attr( $when( 'database' ) ) );

		$this->row(
			__( 'Connection', 'basic-firewall' ),
			self::select(
				$name . '[connection_source]',
				array(
					'wordpress'  => __( 'Reuse WordPress\'s database credentials', 'basic-firewall' ),
					'dsn'        => __( 'A connection DSN I supply', 'basic-firewall' ),
					'parameters' => __( 'Individual connection parameters', 'basic-firewall' ),
				),
				$source
			),
			esc_html__( 'WordPress\'s credentials are read fresh on every request and never written into the compiled file. A log on another database server is where "Off the request path" below earns its keep.', 'basic-firewall' )
		);

		$this->row(
			__( 'Connection DSN', 'basic-firewall' ),
			self::secret_text( $name . '[dsn]', $name . '[dsn_clear]', $dsn_stored ),
			wp_kses_post(
				trim(
					( $dsn_stored ? __( 'A value is stored. Leave blank to keep it.', 'basic-firewall' ) . ' ' : '' )
					/* translators: the %env()% below is a literal token the firewall reads, not a placeholder. */
					. __( 'The scheme is a Doctrine driver name, such as <code>mysqli://user:password@host:3306/database</code>. A DSN embeds the password, so the whole string has to be a <code>%env()%</code> token or none of it can be. A stored one is kept only while the handler type and table are unchanged.', 'basic-firewall' )
				)
			),
			$name . '[connection_source]:dsn'
		);

		$this->render_connection_parameters(
			$name . '[parameters]',
			is_array( $handler['parameters'] ?? null ) ? $handler['parameters'] : array(),
			$name . '[connection_source]:parameters'
		);

		echo '</tbody><tbody>';

		$this->row(
			__( 'Keep history for', 'basic-firewall' ),
			self::text( $name . '[retain_days]', (string) ( $handler['retain_days'] ?? 30 ), 'number', 'min="0"' ),
			wp_kses_post( __( 'Days. <code>0</code> keeps everything, which for a busy firewall is a table that only grows.', 'basic-firewall' ) ),
			$when( 'database' )
		);

		$this->row(
			__( 'Buffering', 'basic-firewall' ),
			self::checkbox( $name . '[buffered]', ! empty( $handler['buffered'] ), __( 'Hold records and write them in one go', 'basic-firewall' ) ),
			esc_html__( 'Worth leaving on. Unbuffered means one insert per record while the request is being served, and the requests producing the most records are the ones already under attack. The cost is that a fatal error loses that request\'s buffered rows.', 'basic-firewall' ),
			$when( 'database' )
		);

		$this->row(
			__( 'Off the request path', 'basic-firewall' ),
			self::checkbox( $name . '[deferred]', ! empty( $handler['deferred'] ), __( 'Send after the visitor has their response', 'basic-firewall' ) ),
			wp_kses_post( __( 'Holds records in memory and writes them after the response has been sent, so a slow destination is not a slow page. Worth nothing for a local file, which is already fast, and worth a lot for anything that makes a network round trip — a database on another host, or a handler added through the advanced YAML that posts to a log service. The cost is that a fatal error before shutdown loses the buffer, which is the right trade for a firewall log and the wrong one for an audit log.', 'basic-firewall' ) )
		);

		echo '</tbody></table></div>';
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

		$all['logging']['redact_extra'] = array_values(
			array_filter(
				array_map( 'trim', self::split_lines( $this->posted_textarea( 'redact_extra' ) ) )
			)
		);

		$handlers = array();

		/*
		 * The handlers as stored, by position, for the two credentials this
		 * screen never renders. Cards are posted under the index they were
		 * rendered with, and the rendered list is the stored one, so the
		 * posted key finds the handler a card came from. A credential is kept
		 * only while what it belongs with is unchanged -- the same binding the
		 * importer applies.
		 */
		$stored = array_values( array_filter( (array) ( $all['logger'] ?? array() ), 'is_array' ) );

		foreach ( $this->posted_array( 'handlers' ) as $index => $handler ) {
			if ( ! is_array( $handler ) || '' === (string) ( $handler['type'] ?? '' ) ) {
				continue;
			}

			$previous = is_int( $index ) && isset( $stored[ $index ] ) ? $stored[ $index ] : array();
			$type     = (string) $handler['type'];
			$table    = (string) ( $handler['table'] ?? 'basic_firewall_log' );

			$handlers[] = array(
				'type'              => $type,
				'enabled'           => ! empty( $handler['enabled'] ),
				'level'             => (string) ( $handler['level'] ?? 'warning' ),
				'path'              => (string) ( $handler['path'] ?? 'logs/firewall.log' ),
				'max_files'         => (int) ( $handler['max_files'] ?? 14 ),
				'table'             => $table,
				'connection_source' => (string) ( $handler['connection_source'] ?? 'wordpress' ),
				'dsn'               => self::kept_secret(
					(string) ( $handler['dsn'] ?? '' ),
					! empty( $handler['dsn_clear'] ),
					(string) ( $previous['dsn'] ?? '' ),
					( $previous['type'] ?? null ) === $type && ( $previous['table'] ?? null ) === $table
				),
				'parameters'        => self::posted_connection_parameters(
					is_array( $handler['parameters'] ?? null ) ? $handler['parameters'] : array(),
					is_array( $previous['parameters'] ?? null ) ? $previous['parameters'] : array()
				),
				'retain_days'       => (int) ( $handler['retain_days'] ?? 30 ),
				'buffered'          => ! empty( $handler['buffered'] ),
				'deferred'          => ! empty( $handler['deferred'] ),
			);
		}

		$all['logger'] = $handlers;

		$problems = $settings->replace( $all );

		foreach ( $problems as $problem ) {
			Notices::add( sprintf( '<strong>%s</strong>: %s', esc_html( $problem['path'] ), esc_html( $problem['message'] ) ), 'error' );
		}

		foreach ( $handlers as $handler ) {
			if ( $handler['enabled'] && 'debug' === $handler['level'] ) {
				Notices::add(
					__( 'A handler is set to <strong>debug</strong>. That records what every condition compared against — roughly 100 KB per allowed request on a file handler, about 97 MB per thousand requests. Exactly right while working out why a rule does or does not match, and not a level to leave on. Set it, reproduce the request, set it back.', 'basic-firewall' ),
					'warning'
				);

				break;
			}
		}

		if ( array() === $problems ) {
			Notices::add( __( 'Logging settings saved, and the firewall recompiled.', 'basic-firewall' ) );
		}

		$this->redirect( $this->slug() );
	}

	/**
	 * Split a textarea into lines, tolerating a preg_split() failure.
	 *
	 * @param string $value Raw textarea content.
	 *
	 * @return array<int, string>
	 */
	private static function split_lines( string $value ): array {
		$split = preg_split( '/\R/', $value );

		return is_array( $split ) ? $split : array();
	}

	/**
	 * {@inheritDoc}
	 */
	public function render(): void {
		$settings = $this->plugin()->settings();
		$handlers = (array) $settings->get( 'logger', array() );

		$levels = array();

		foreach ( array_keys( Library_Map::log_levels() ) as $level ) {
			$levels[ $level ] = $level;
		}

		$types = array(
			'rotating_file' => __( 'Rotating file — one file per day', 'basic-firewall' ),
			'stream'        => __( 'Single file', 'basic-firewall' ),
			'error_log'     => __( 'PHP error log', 'basic-firewall' ),
			'database'      => __( 'Database table — queryable from the Log screen', 'basic-firewall' ),
		);

		$this->open_form();

		printf( '<h2>%s</h2>', esc_html__( 'Handlers', 'basic-firewall' ) );

		printf(
			'<p class="bfw-repeat-intro">%s</p>',
			esc_html__( 'Add as many as you need. Several at once is the normal arrangement rather than the exception: a rotating file at warning to keep, a database handler at notice so the Log screen has something to show, and a stream to php://stderr on a containerised host where the platform collects the output. Each decides its own level independently.', 'basic-firewall' )
		);

		/*
		 * Existing handlers, then one blank card. The blank one is what makes
		 * "Add handler" work with JavaScript off: the button clones it and
		 * renumbers the fields, and where it cannot, the blank card is still a
		 * usable form that adds a handler per save.
		 */
		$rows = array_values(
			array_filter(
				$handlers,
				static fn ( $handler ): bool => is_array( $handler ) && '' !== (string) ( $handler['type'] ?? '' )
			)
		);

		echo '<div data-bfw-repeatable="handlers">';

		foreach ( $rows as $index => $handler ) {
			$this->render_handler( $index, (array) $handler, $types, $levels, false );
		}

		$this->render_handler( count( $rows ), array(), $types, $levels, true );

		echo '</div>';

		printf(
			'<p><button type="button" class="button" data-bfw-add="handlers">%s</button></p>',
			esc_html__( '+ Add handler', 'basic-firewall' )
		);

		/*
		 * Where "send events to WordPress" used to be. WordPress has no log
		 * to send them to, and nothing ever did; the actions are what a site
		 * wanting firewall events inside WordPress actually has.
		 */
		printf(
			'<p class="description" style="max-width:48rem">%s</p>',
			wp_kses_post( __( 'WordPress has no log of its own for these to go to. Every decision is also announced as the <code>basic_firewall_decision</code> action, so an activity log plugin — or a few lines of your own — can record them inside WordPress.', 'basic-firewall' ) )
		);

		printf( '<h2>%s</h2>', esc_html__( 'Redaction', 'basic-firewall' ) );

		echo '<table class="form-table" role="presentation"><tbody>';

		$this->row(
			__( 'Additional variables to redact', 'basic-firewall' ),
			self::textarea( 'redact_extra', implode( "\n", (array) $settings->get( 'logging.redact_extra', array() ) ), 4 ),
			__( 'At debug level the firewall records the value a condition matched, so a rule inspecting a header or cookie would write session tokens into the log. A sensible set is redacted already — the <code>cookie</code>, <code>authorization</code>, <code>x-api-key</code>, <code>x-auth-token</code> and <code>x-csrf-token</code> headers, plus every individual cookie. Add your own the way the firewall names them — <code>header.x-session-id</code>, <code>query.token</code> — one per line, with a trailing <code>.*</code> for a prefix, such as <code>query.*</code>. They are added to that set, never in place of it, and apply on both evaluation paths. Redaction affects the log only: evaluation always sees the real value, so it can never change whether a request is blocked.', 'basic-firewall' )
		);

		echo '</tbody></table>';

		$this->close_form();
	}
}
