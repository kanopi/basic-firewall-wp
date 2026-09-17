<?php
/**
 * Blocked clients, and unblocking them.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Admin\Screen;

use Kanopi\BasicFirewall\Admin\Admin;
use Kanopi\BasicFirewall\Admin\Notices;
use Kanopi\BasicFirewall\Admin\Screen;
use Kanopi\BasicFirewall\Install\Capabilities;

/**
 * Who is blocked, why, and how to let them back in.
 */
final class Blocked_Screen extends Screen {

	/**
	 * {@inheritDoc}
	 */
	public function slug(): string {
		return 'basic-firewall-blocked';
	}

	/**
	 * {@inheritDoc}
	 */
	public function page_title(): string {
		return __( 'Blocked clients', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function menu_title(): string {
		return __( 'Blocked', 'basic-firewall' );
	}

	/**
	 * Support staff need to read this without being able to rewrite the rules.
	 *
	 * {@inheritDoc}
	 */
	public function capability(): string {
		return Capabilities::VIEW_REPORTS;
	}

	/**
	 * {@inheritDoc}
	 */
	public function intro(): string {
		return esc_html__( 'Everything currently blocked, permanent blocks first and then the longest remaining. Entries that have expired are filtered out — the firewall leaves them in place until it next prunes, so they would otherwise read as live blocks.', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function handle(): void {
		if ( ! $this->verify() ) {
			return;
		}

		$action = $this->posted( 'blocked_action' );

		if ( 'unblock' === $action ) {
			// A separate capability: releasing a client is not reading a report.
			if ( ! Capabilities::can_unblock() ) {
				Notices::add( __( 'You do not have permission to unblock clients.', 'basic-firewall' ), 'error' );

				$this->redirect( $this->slug() );
			}

			$ip = $this->posted( 'ip' );

			if ( $this->plugin()->blocked()->unblock( $ip ) ) {
				Notices::add(
					sprintf(
						/* translators: %s: client address. */
						__( '%s has been unblocked, and its offense history cleared — without that, escalation would put it straight back on its next request.', 'basic-firewall' ),
						esc_html( $ip )
					)
				);
			} else {
				Notices::add(
					sprintf(
						/* translators: %s: client address. */
						__( '%s could not be unblocked. It may already have expired.', 'basic-firewall' ),
						esc_html( $ip )
					),
					'error'
				);
			}

			$this->redirect( $this->slug() );
		}

		if ( 'block' === $action ) {
			$this->handle_block();
		}
	}

	/**
	 * Block an address by hand.
	 *
	 * The counterpart to unblocking, and it was missing: `wp basic-firewall
	 * block` has always existed, and the screen that lists blocked clients
	 * could only take them off the list.
	 *
	 * Gated on the same capability as unblocking. Adding an entry and removing
	 * one are the same privilege -- somebody who can release a client can
	 * already re-block it by other means -- and a separate capability would
	 * only be a way to grant half of a reversible pair.
	 */
	private function handle_block(): void {
		if ( ! Capabilities::can_unblock() ) {
			Notices::add( __( 'You do not have permission to change the block list.', 'basic-firewall' ), 'error' );

			$this->redirect( $this->slug() );
		}

		$ip = trim( $this->posted( 'ip' ) );

		if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			Notices::add(
				__( 'That is not an IP address. The block list holds single addresses — to block a range, add an IP address rule instead.', 'basic-firewall' ),
				'error'
			);

			$this->redirect( $this->slug() );
		}

		$duration = max( 0, (int) $this->posted( 'duration', '3600' ) );
		$reason   = $this->posted( 'reason' );

		if ( '' === trim( $reason ) ) {
			$reason = __( 'Added by hand', 'basic-firewall' );
		}

		if ( ! $this->plugin()->blocked()->block( $ip, $duration, $reason ) ) {
			Notices::add(
				sprintf(
					/* translators: %s: client address. */
					__( '%s could not be blocked. The storage backend refused the write — check the block list storage test on the Dashboard.', 'basic-firewall' ),
					esc_html( $ip )
				),
				'error'
			);

			$this->redirect( $this->slug() );
		}

		/*
		 * Said plainly, because a manual entry behaves unlike a rule and the
		 * difference catches people out: it expires, and it does not travel in
		 * an exported configuration.
		 */
		Notices::add(
			sprintf(
				/* translators: 1: client address, 2: how long it lasts. */
				__( '%1$s is blocked %2$s. This is a block list entry, not a rule: it expires, and it is not part of an exported configuration. To make the decision permanent and portable, add an IP address rule.', 'basic-firewall' ),
				esc_html( $ip ),
				0 === $duration
					? esc_html__( 'permanently', 'basic-firewall' )
					: sprintf(
						/* translators: %s: human-readable duration. */
						esc_html__( 'for %s', 'basic-firewall' ),
						esc_html( human_time_diff( time(), time() + $duration ) )
					)
			)
		);

		$this->redirect( $this->slug() );
	}

	/**
	 * {@inheritDoc}
	 */
	public function render(): void {
		if ( 'unblock' === $this->query( 'action' ) ) {
			$this->render_unblock_confirmation();

			return;
		}

		$this->render_lookup();
		$this->render_block_form();

		$listing = $this->plugin()->blocked()->all();

		if ( ! $listing['supported'] ) {
			printf(
				'<div class="bfw-warning"><p>%s</p></div>',
				esc_html__( 'The configured storage backend cannot list what it holds, so this page cannot show you a list. Use the lookup above to ask about one address — that works on every backend. An empty list would be a lie here, so none is shown.', 'basic-firewall' )
			);

			return;
		}

		if ( array() === $listing['clients'] ) {
			printf( '<p>%s</p>', esc_html__( 'Nothing is currently blocked.', 'basic-firewall' ) );

			return;
		}

		echo '<table class="widefat striped"><thead><tr>';

		foreach ( array(
			__( 'Address', 'basic-firewall' ),
			__( 'Blocked until', 'basic-firewall' ),
			__( 'Offenses', 'basic-firewall' ),
			__( 'Rule', 'basic-firewall' ),
			__( 'Reason', 'basic-firewall' ),
			__( 'Reference', 'basic-firewall' ),
			__( 'Actions', 'basic-firewall' ),
		) as $heading ) {
			printf( '<th>%s</th>', esc_html( $heading ) );
		}

		echo '</tr></thead><tbody>';

		foreach ( $listing['clients'] as $client ) {
			$record = (array) $client['record'];

			echo '<tr>';

			printf( '<td><code>%s</code></td>', esc_html( (string) $client['ip'] ) );

			printf(
				'<td>%s</td>',
				$client['permanent']
					? '<strong>' . esc_html__( 'Permanently', 'basic-firewall' ) . '</strong>'
					: esc_html( gmdate( 'Y-m-d H:i:s', (int) $client['expires'] ) . ' UTC' )
			);

			printf( '<td>%d</td>', (int) $client['offenses'] );
			printf( '<td>%s</td>', esc_html( (string) ( $record['plugin'] ?? '' ) ) );

			/*
			 * Shown since the block list became something a person can write
			 * to. A reason typed into the form and then never displayed is a
			 * field that asks for an explanation and files it somewhere only
			 * the CLI can read.
			 */
			printf( '<td>%s</td>', esc_html( (string) ( $record['reason'] ?? '' ) ) );

			printf( '<td><code>%s</code></td>', esc_html( (string) ( $record['event_id'] ?? '' ) ) );

			echo '<td>';

			if ( Capabilities::can_unblock() ) {
				printf(
					'<a href="%s">%s</a>',
					esc_url(
						Admin::url(
							$this->slug(),
							array(
								'action' => 'unblock',
								'ip'     => (string) $client['ip'],
							)
						)
					),
					esc_html__( 'Unblock', 'basic-firewall' )
				);
			}

			echo '</td></tr>';
		}

		echo '</tbody></table>';
	}

	/**
	 * Look one address up.
	 *
	 * Works on every backend, including the ones that cannot be enumerated,
	 * which is the only way to get an answer there.
	 */
	private function render_lookup(): void {
		$ip = $this->query( 'lookup' );

		printf( '<form method="get" action="%s" style="margin:1rem 0">', esc_url( admin_url( 'admin.php' ) ) );
		printf( '<input type="hidden" name="page" value="%s" />', esc_attr( $this->slug() ) );
		printf(
			'<label>%s <input type="text" name="lookup" value="%s" placeholder="203.0.113.10" /></label> ',
			esc_html__( 'Look up an address:', 'basic-firewall' ),
			esc_attr( $ip )
		);

		submit_button( __( 'Check', 'basic-firewall' ), 'secondary', '', false );

		echo '</form>';

		if ( '' === $ip ) {
			return;
		}

		if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			printf(
				'<div class="bfw-warning"><p>%s</p></div>',
				esc_html__( 'That is not an IP address.', 'basic-firewall' )
			);

			return;
		}

		$answer = $this->plugin()->blocked()->check( $ip );
		$record = (array) ( $answer['record'] ?? array() );

		printf(
			'<div class="%s"><p><code>%s</code> — %s</p>%s</div>',
			$answer['blocked'] ? 'bfw-danger' : 'bfw-warning',
			esc_html( $ip ),
			$answer['blocked']
				? esc_html__( 'is currently blocked', 'basic-firewall' )
				: esc_html__( 'is not blocked', 'basic-firewall' ),
			$answer['blocked']
				? sprintf(
					'<p>%s <strong>%s</strong>.%s %s <code>%s</code></p>',
					esc_html__( 'Blocked by', 'basic-firewall' ),
					esc_html( (string) ( $record['plugin'] ?? __( 'an unnamed rule', 'basic-firewall' ) ) ),
					'' !== (string) ( $record['reason'] ?? '' )
						? ' ' . esc_html( (string) $record['reason'] ) . '.'
						: '',
					esc_html__( 'Reference:', 'basic-firewall' ),
					esc_html( (string) ( $record['event_id'] ?? '' ) )
				)
				: ''
		);
	}

	/**
	 * Add an address to the block list.
	 *
	 * Folded away, because the list is mostly written by the firewall itself
	 * and read by a person. Blocking by hand is what you do with an address
	 * somebody sent you, or one you found in the log of another system.
	 */
	private function render_block_form(): void {
		if ( ! Capabilities::can_unblock() ) {
			return;
		}

		printf(
			'<details class="bfw-import"><summary>%s</summary>',
			esc_html__( 'Block an address', 'basic-firewall' )
		);

		printf(
			'<p>%s</p>',
			wp_kses_post(
				__( 'Adds one address to the list the firewall consults before it evaluates any rule. Use this for an address you already know about — from another system\'s log, or an abuse report. <strong>It expires, and it does not travel in an export.</strong> For a decision that should outlive its expiry and move with the site, add an IP address rule instead, which also takes CIDR blocks and ranges.', 'basic-firewall' )
			)
		);

		$this->open_form();

		printf( '<input type="hidden" name="blocked_action" value="block" />' );

		echo '<table class="form-table" role="presentation"><tbody>';

		$this->row(
			__( 'Address', 'basic-firewall' ),
			self::text( 'ip', '', 'text', 'placeholder="203.0.113.10"' ),
			esc_html__( 'A single IPv4 or IPv6 address. The block list holds addresses, not ranges.', 'basic-firewall' )
		);

		$this->row(
			__( 'For', 'basic-firewall' ),
			self::select(
				'duration',
				array(
					'3600'   => __( 'An hour', 'basic-firewall' ),
					'21600'  => __( 'Six hours', 'basic-firewall' ),
					'86400'  => __( 'A day', 'basic-firewall' ),
					'604800' => __( 'A week', 'basic-firewall' ),
					'0'      => __( 'Until it is removed by hand', 'basic-firewall' ),
				),
				'3600'
			),
			esc_html__( 'An entry that expires is usually the right answer: an address reassigned to somebody else should stop being blocked on its own.', 'basic-firewall' )
		);

		$this->row(
			__( 'Reason', 'basic-firewall' ),
			self::text( 'reason', '', 'text', 'class="regular-text" placeholder="' . esc_attr__( 'why, for whoever reads this next', 'basic-firewall' ) . '"' ),
			esc_html__( 'Shown in the list and in the lookup. Worth writing: the next person to see this entry may be you in three months.', 'basic-firewall' )
		);

		echo '</tbody></table>';

		$this->close_form( __( 'Block this address', 'basic-firewall' ) );

		echo '</details>';
	}

	/**
	 * Confirm an unblock, showing what the block was for.
	 */
	private function render_unblock_confirmation(): void {
		$ip     = $this->query( 'ip' );
		$answer = $this->plugin()->blocked()->check( $ip );
		$record = (array) ( $answer['record'] ?? array() );

		printf( '<h2>%s</h2>', esc_html__( 'Unblock this client?', 'basic-firewall' ) );

		printf(
			'<p><code>%s</code></p><p>%s <strong>%s</strong>%s</p>',
			esc_html( $ip ),
			esc_html__( 'Blocked by', 'basic-firewall' ),
			esc_html( (string) ( $record['plugin'] ?? __( 'an unnamed rule', 'basic-firewall' ) ) ),
			'' !== (string) ( $record['reason'] ?? '' )
				? ' — ' . esc_html( (string) $record['reason'] )
				: ''
		);

		printf(
			'<p class="description">%s</p>',
			esc_html__( 'Unblocking also clears this client\'s offense history. Without that, escalation would put a just-released address straight back on a longer ban at its next request — the block would read as lifted and would not be.', 'basic-firewall' )
		);

		$this->open_form();

		printf( '<input type="hidden" name="blocked_action" value="unblock" />' );
		printf( '<input type="hidden" name="ip" value="%s" />', esc_attr( $ip ) );

		submit_button( __( 'Unblock', 'basic-firewall' ), 'primary', 'submit', false );

		printf(
			' <a href="%s" class="button">%s</a>',
			esc_url( Admin::url( $this->slug() ) ),
			esc_html__( 'Cancel', 'basic-firewall' )
		);

		echo '</form>';
	}
}
