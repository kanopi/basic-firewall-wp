<?php
/**
 * The log report.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Admin\Screen;

use Kanopi\BasicFirewall\Admin\Admin;
use Kanopi\BasicFirewall\Admin\Screen;
use Kanopi\BasicFirewall\Install\Capabilities;
use Kanopi\BasicFirewall\Logging\Log_Reader;

/**
 * What the firewall has been doing.
 */
final class Log_Screen extends Screen {

	/**
	 * {@inheritDoc}
	 */
	public function slug(): string {
		return 'basic-firewall-log';
	}

	/**
	 * {@inheritDoc}
	 */
	public function page_title(): string {
		return __( 'Firewall log', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function menu_title(): string {
		return __( 'Log', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function capability(): string {
		return Capabilities::VIEW_REPORTS;
	}

	/**
	 * {@inheritDoc}
	 */
	public function render(): void {
		$reader = new Log_Reader();

		if ( ! $reader->is_available() ) {
			printf(
				'<div class="bfw-warning"><p>%s</p><p>%s</p></div>',
				esc_html__( 'There is no readable log to show.', 'basic-firewall' ),
				sprintf(
					/* translators: %s: URL of the logging screen. */
					wp_kses_post( __( 'Enable a <strong>Database table</strong> handler on the <a href="%s">Logging screen</a> to read events back here. A file handler answers "what happened just now" if you can reach a shell; a table answers the questions that actually get asked — which rule has blocked the most clients this week, whether a rule has matched anything at all since it was added, what the firewall did to an address before its owner complained.', 'basic-firewall' ) ),
					esc_url( Admin::url( 'basic-firewall-logging' ) )
				)
			);

			return;
		}

		$filters = $this->filters( $reader );

		$this->render_filters( $reader, $filters );

		$entries = $reader->recent( 200, $filters );

		if ( array() === $entries ) {
			printf(
				'<p>%s</p>',
				array() === array_filter( $filters )
					? esc_html__( 'The log is empty.', 'basic-firewall' )
					: esc_html__( 'Nothing in the log matches that. Widen the filters above.', 'basic-firewall' )
			);

			return;
		}

		echo '<table class="widefat striped bfw-log"><thead><tr>';

		foreach ( array(
			'when'    => __( 'When', 'basic-firewall' ),
			'level'   => __( 'Level', 'basic-firewall' ),
			'rule'    => __( 'Rule', 'basic-firewall' ),
			'client'  => __( 'Client', 'basic-firewall' ),
			'request' => __( 'Request', 'basic-firewall' ),
			'why'     => __( 'What happened', 'basic-firewall' ),
		) as $column => $heading ) {
			printf( '<th class="column-%s">%s</th>', esc_attr( $column ), esc_html( $heading ) );
		}

		echo '</tr></thead><tbody>';

		foreach ( $entries as $entry ) {
			$this->render_entry( $entry );
		}

		echo '</tbody></table>';
	}

	/**
	 * One log entry, with the detail folded underneath it.
	 *
	 * The table used to show five columns and throw the rest away, which meant
	 * the one question somebody brings to a firewall log -- *why was this
	 * blocked* -- was the one it could not answer. Everything needed to answer
	 * it was already in the row: the library gives this table dedicated columns
	 * for the method, the path, the agent and the rule that fired.
	 *
	 * @param array<string, mixed> $entry One entry.
	 */
	private function render_entry( array $entry ): void {
		echo '<tr>';

		printf( '<td class="column-when">%s</td>', esc_html( (string) $entry['time'] ) );

		printf(
			'<td class="column-level"><span class="bfw-level bfw-level--%s">%s</span></td>',
			esc_attr( strtolower( (string) $entry['level'] ) ),
			esc_html( (string) $entry['level'] )
		);

		printf(
			'<td class="column-rule">%s</td>',
			'' !== (string) $entry['rule']
				? '<code>' . esc_html( (string) $entry['rule'] ) . '</code>'
				: '<span class="description">' . esc_html__( 'no rule', 'basic-firewall' ) . '</span>'
		);

		printf( '<td class="column-client"><code>%s</code></td>', esc_html( (string) $entry['ip'] ) );

		printf(
			'<td class="column-request"><code>%s %s</code></td>',
			esc_html( (string) $entry['method'] ),
			esc_html( $this->shorten( (string) $entry['path'], 60 ) )
		);

		printf( '<td class="column-why">%s%s</td>', esc_html( (string) $entry['message'] ), wp_kses_post( $this->render_detail( $entry ) ) );

		echo '</tr>';
	}

	/**
	 * The detail behind one entry.
	 *
	 * Folded away rather than shown, because a log is read by scanning and the
	 * detail is wanted for one row at a time. Open, six columns of agent
	 * strings push everything that identifies a row off the screen.
	 *
	 * @param array<string, mixed> $entry One entry.
	 */
	private function render_detail( array $entry ): string {
		$rows = array();

		foreach ( array(
			'user_agent' => __( 'User agent', 'basic-firewall' ),
			'host'       => __( 'Host', 'basic-firewall' ),
			'rule_type'  => __( 'Rule type', 'basic-firewall' ),
			'request_id' => __( 'Request', 'basic-firewall' ),
		) as $key => $label ) {
			$value = trim( (string) ( $entry[ $key ] ?? '' ) );

			if ( '' !== $value ) {
				$rows[ $label ] = $value;
			}
		}

		/*
		 * Whatever the rule itself recorded, minus the keys already shown as
		 * their own columns. At debug level this is where the comparison lands
		 * -- which variable was read, what it held, what it was checked against
		 * -- which is the actual answer to "why", and it was being discarded.
		 */
		$shown = array( 'name', 'plugin', 'client_ip', 'ip', 'path', 'method', 'host', 'user_agent', 'request_id', 'plugin_name', 'plugin_type', 'level' );

		foreach ( (array) ( $entry['context'] ?? array() ) as $key => $value ) {
			if ( in_array( (string) $key, $shown, true ) || is_array( $value ) ) {
				continue;
			}

			$value = trim( (string) $value );

			if ( '' !== $value ) {
				$rows[ (string) $key ] = $value;
			}
		}

		if ( array() === $rows ) {
			return '';
		}

		$detail = '';

		foreach ( $rows as $label => $value ) {
			$detail .= sprintf(
				'<div><span class="bfw-log__label">%s</span> <code>%s</code></div>',
				esc_html( (string) $label ),
				esc_html( $this->shorten( (string) $value, 200 ) )
			);
		}

		return sprintf(
			'<details class="bfw-log__detail"><summary>%s</summary>%s</details>',
			esc_html__( 'Detail', 'basic-firewall' ),
			$detail
		);
	}

	/**
	 * Cut a long value down, without pretending it was short.
	 *
	 * @param string $value  The value.
	 * @param int    $length How much to keep.
	 */
	private function shorten( string $value, int $length ): string {
		return strlen( $value ) > $length ? substr( $value, 0, $length ) . '…' : $value;
	}

	/**
	 * What the reader should be asked for.
	 *
	 * @param Log_Reader $reader The reader, for checking a rule still exists.
	 *
	 * @return array<string, mixed>
	 */
	private function filters( Log_Reader $reader ): array {
		$rule  = $this->query( 'rule' );
		$level = $this->query( 'level' );
		$since = $this->query( 'since' );

		return array(
			// Checked against what is actually in the log, so a crafted value
			// asks for nothing rather than for everything.
			'rule'  => in_array( $rule, $reader->rules(), true ) ? $rule : '',
			'level' => in_array( $level, $reader->levels(), true ) ? $level : '',
			'since' => isset( $this->windows()[ $since ] ) && '' !== $since
				? time() - (int) $this->windows()[ $since ]['seconds']
				: 0,
		);
	}

	/**
	 * The time windows offered.
	 *
	 * @return array<string, array{label: string, seconds: int}>
	 */
	private function windows(): array {
		return array(
			''      => array(
				'label'   => __( 'Any time', 'basic-firewall' ),
				'seconds' => 0,
			),
			'hour'  => array(
				'label'   => __( 'Last hour', 'basic-firewall' ),
				'seconds' => HOUR_IN_SECONDS,
			),
			'day'   => array(
				'label'   => __( 'Last 24 hours', 'basic-firewall' ),
				'seconds' => DAY_IN_SECONDS,
			),
			'week'  => array(
				'label'   => __( 'Last 7 days', 'basic-firewall' ),
				'seconds' => WEEK_IN_SECONDS,
			),
			'month' => array(
				'label'   => __( 'Last 30 days', 'basic-firewall' ),
				'seconds' => 30 * DAY_IN_SECONDS,
			),
		);
	}

	/**
	 * The filter form.
	 *
	 * A GET form, so a filtered view is a URL somebody can send to whoever
	 * asked them about it.
	 *
	 * @param Log_Reader           $reader  The reader, for the available values.
	 * @param array<string, mixed> $filters What is currently applied.
	 */
	private function render_filters( Log_Reader $reader, array $filters ): void {
		$rules  = $reader->rules();
		$levels = $reader->levels();

		if ( array() === $rules && array() === $levels ) {
			return;
		}

		printf( '<form method="get" action="%s" class="bfw-log-filters">', esc_url( admin_url( 'admin.php' ) ) );
		printf( '<input type="hidden" name="page" value="%s" />', esc_attr( $this->slug() ) );

		$options = array( '' => __( 'Any rule', 'basic-firewall' ) );

		foreach ( $rules as $rule ) {
			$options[ $rule ] = $rule;
		}

		echo wp_kses( self::select( 'rule', $options, (string) $filters['rule'] ), self::allowed_control_html() );

		$options = array( '' => __( 'Any level', 'basic-firewall' ) );

		foreach ( $levels as $level ) {
			$options[ $level ] = $level;
		}

		echo ' ' . wp_kses( self::select( 'level', $options, (string) $filters['level'] ), self::allowed_control_html() );

		$options = array();

		foreach ( $this->windows() as $key => $window ) {
			$options[ $key ] = $window['label'];
		}

		echo ' ' . wp_kses( self::select( 'since', $options, $this->query( 'since' ) ), self::allowed_control_html() );

		echo ' ';

		submit_button( __( 'Filter', 'basic-firewall' ), 'secondary', '', false );

		if ( '' !== (string) $filters['rule'] || '' !== (string) $filters['level'] || 0 !== (int) $filters['since'] ) {
			printf(
				' <a href="%s">%s</a>',
				esc_url( Admin::url( $this->slug() ) ),
				esc_html__( 'Clear', 'basic-firewall' )
			);
		}

		echo '</form>';
	}
}
