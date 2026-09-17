<?php
/**
 * Test a request against the live rule set.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Admin\Screen;

use Kanopi\BasicFirewall\Admin\Screen;
use Kanopi\BasicFirewall\Request_Tester;

/**
 * "Would this be blocked?", answered without waiting for it to happen.
 */
final class Test_Screen extends Screen {

	/**
	 * The last result, held between handle() and render().
	 *
	 * @var array<string, mixed>|null
	 */
	private ?array $result = null;

	/**
	 * What was submitted, so the form comes back filled in.
	 *
	 * @var array<string, string>
	 */
	private array $submitted = array();

	/**
	 * {@inheritDoc}
	 */
	public function slug(): string {
		return 'basic-firewall-test';
	}

	/**
	 * {@inheritDoc}
	 */
	public function page_title(): string {
		return __( 'Test a request', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function menu_title(): string {
		return __( 'Test', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function intro(): string {
		return wp_kses_post(
			__( 'Describe a request and see what the firewall would do with it. This evaluates the configuration the firewall is actually running, so the answer reflects the live rule set — and rules are evaluated whether or not the firewall is currently enabled, which is what makes this useful for checking a rule set <em>before</em> switching it on. Give a client address and the block list is consulted first, in the order a real request meets it. <strong>Nothing is recorded:</strong> no address is blocked, no offense is counted, no rate limit budget is spent, and nothing reaches your log.', 'basic-firewall' )
		);
	}

	/**
	 * Handled during render, because the result is shown rather than redirected to.
	 */
	public function handle(): void {}

	/**
	 * {@inheritDoc}
	 */
	public function render(): void {
		if ( $this->verify() ) {
			$this->submitted = array(
				'path'       => $this->posted( 'path', '/' ),
				'method'     => $this->posted( 'method', 'GET' ),
				'ip'         => $this->posted( 'ip' ),
				'user_agent' => $this->posted( 'user_agent' ),
				'headers'    => $this->posted_textarea( 'headers' ),
				'body'       => $this->posted_textarea( 'body' ),
			);

			$this->result = ( new Request_Tester() )->test( $this->submitted );
		}

		/*
		 * Form first, result underneath.
		 *
		 * The verdict is the answer to the question the form asks, and it reads
		 * as one when it follows it. Above the form it pushes the inputs down
		 * the page on every submission, so the thing you are about to change
		 * moves each time you change it -- and testing a rule set is an
		 * iterative business: adjust the path, submit, read, adjust again.
		 */
		$this->render_form();
		$this->render_block_list();
		$this->render_result();
		$this->render_limits();
	}

	/**
	 * Whether the address is already on the block list.
	 *
	 * Printed above the rule verdict because that is the order a real request
	 * meets them: the firewall enforces the durable block list before it
	 * evaluates the marking, recording and refusing buckets, so an address
	 * already on the list never reaches the rules at all.
	 *
	 * This used to be a line under "what this cannot tell you", which was true
	 * of the tester and wrong as advice: the block list is exactly what somebody
	 * is asking about when they test an address that is behaving oddly, the
	 * screen has access to it, and sending them to a different screen to find
	 * out meant the most common answer was the one answer this page refused to
	 * give. Reading it records nothing -- no offense, no counter, no log line --
	 * which is the property that made it safe to put here.
	 */
	private function render_block_list(): void {
		if ( null === $this->result ) {
			return;
		}

		$ip = trim( $this->submitted['ip'] ?? '' );

		if ( '' === $ip ) {
			printf(
				'<div class="bfw-warning"><p><strong>%s</strong></p><p>%s</p></div>',
				esc_html__( 'Block list: not checked', 'basic-firewall' ),
				esc_html__( 'No client address was given, so there was nothing to look up. The rule verdict below still applies.', 'basic-firewall' )
			);

			return;
		}

		$answer = $this->plugin()->blocked()->check( $ip );

		if ( ! $answer['blocked'] ) {
			printf(
				'<div class="bfw-notice"><p><strong>%s</strong></p><p>%s</p></div>',
				esc_html__( 'Block list: not listed', 'basic-firewall' ),
				sprintf(
					/* translators: 1: client address, 2: storage backend. */
					esc_html__( '%1$s is not on the block list held in %2$s storage, so this request reaches the rules.', 'basic-firewall' ),
					esc_html( $ip ),
					esc_html( (string) $answer['backend'] )
				)
			);

			return;
		}

		$record  = is_array( $answer['record'] ) ? $answer['record'] : array();
		$expires = isset( $record['expire'] ) ? (int) $record['expire'] : 0;
		$reason  = isset( $record['reason'] ) ? (string) $record['reason'] : '';
		$plugin  = isset( $record['plugin'] ) ? (string) $record['plugin'] : '';

		$detail = array();

		if ( '' !== $plugin ) {
			/* translators: %s: the rule or source that blocked the client. */
			$detail[] = sprintf( esc_html__( 'Blocked by %s.', 'basic-firewall' ), esc_html( $plugin ) );
		}

		if ( '' !== $reason ) {
			/* translators: %s: the recorded reason. */
			$detail[] = sprintf( esc_html__( 'Reason: %s', 'basic-firewall' ), esc_html( $reason ) );
		}

		$detail[] = $expires > 0
			/* translators: %s: human-readable duration. */
			? sprintf( esc_html__( 'Expires in %s.', 'basic-firewall' ), esc_html( human_time_diff( time(), $expires ) ) )
			: esc_html__( 'It does not expire.', 'basic-firewall' );

		printf(
			'<div class="bfw-danger"><p><strong>%s</strong></p><p>%s</p><p>%s</p><p>%s</p></div>',
			esc_html__( 'Block list: already blocked', 'basic-firewall' ),
			sprintf(
				/* translators: 1: client address, 2: storage backend. */
				esc_html__( '%1$s is on the block list held in %2$s storage. A real request from it is refused here, before any rule is evaluated — so the rule verdict below describes what would happen if it were released, not what happens now.', 'basic-firewall' ),
				esc_html( $ip ),
				esc_html( (string) $answer['backend'] )
			),
			wp_kses_post( implode( ' ', $detail ) ),
			sprintf(
				'<a href="%s" class="button">%s</a>',
				esc_url( admin_url( 'admin.php?page=basic-firewall-blocked' ) ),
				esc_html__( 'Release it on the Blocked clients screen', 'basic-firewall' )
			)
		);
	}

	/**
	 * Show the verdict.
	 */
	private function render_result(): void {
		if ( null === $this->result ) {
			return;
		}

		$result = $this->result;

		$class = match ( $result['verdict'] ) {
			'block'     => 'bfw-danger',
			'challenge' => 'bfw-warning',
			'error'     => 'bfw-danger',
			default     => 'bfw-warning',
		};

		$headline = match ( $result['verdict'] ) {
			'allow'     => __( 'Allowed', 'basic-firewall' ),
			'block'     => __( 'Blocked', 'basic-firewall' ),
			'challenge' => __( 'Challenged', 'basic-firewall' ),
			default     => __( 'Could not be tested', 'basic-firewall' ),
		};

		printf(
			'<div class="%s"><p><strong>%s</strong></p><p>%s</p>%s%s</div>',
			esc_attr( $class ),
			esc_html( $headline ),
			esc_html( (string) $result['message'] ),
			null !== $result['rule']
				? '<p>' . esc_html__( 'Decided by rule:', 'basic-firewall' ) . ' <code>' . esc_html( (string) $result['rule'] ) . '</code></p>'
				: '',
			null !== $result['status']
				? '<p>' . esc_html__( 'A real client would receive HTTP', 'basic-firewall' ) . ' ' . esc_html( (string) $result['status'] ) . '</p>'
				: ''
		);

		if ( array() === $result['log'] ) {
			return;
		}

		printf( '<h2>%s</h2>', esc_html__( 'What the firewall did', 'basic-firewall' ) );

		printf(
			'<p class="description">%s</p>',
			esc_html__( 'The captured log is the useful part when a verdict is surprising: it shows which variable was read, what it was compared against, and why that did or did not match.', 'basic-firewall' )
		);

		printf( '<pre class="bfw-code">%s</pre>', esc_html( implode( "\n", $result['log'] ) ) );
	}

	/**
	 * The description form.
	 */
	private function render_form(): void {
		$this->open_form();

		echo '<table class="form-table" role="presentation"><tbody>';

		$this->row(
			__( 'Path', 'basic-firewall' ),
			self::text( 'path', $this->submitted['path'] ?? '/wp-login.php' )
		);

		$this->row(
			__( 'Method', 'basic-firewall' ),
			self::select(
				'method',
				array_combine(
					array( 'GET', 'POST', 'HEAD', 'PUT', 'PATCH', 'DELETE', 'OPTIONS' ),
					array( 'GET', 'POST', 'HEAD', 'PUT', 'PATCH', 'DELETE', 'OPTIONS' )
				),
				$this->submitted['method'] ?? 'GET'
			)
		);

		$this->row(
			__( 'Client IP', 'basic-firewall' ),
			self::text( 'ip', $this->submitted['ip'] ?? '203.0.113.10' ),
			__( 'Use a documentation range (203.0.113.0/24, 198.51.100.0/24) so a test can never collide with a real client.', 'basic-firewall' )
		);

		$this->row(
			__( 'User agent', 'basic-firewall' ),
			self::text( 'user_agent', $this->submitted['user_agent'] ?? 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15' ),
			__( 'Try <code>sqlmap/1.7</code> or <code>curl/8.0</code> against a rule using <code>automated</code>, and against one using <code>bot</code> — the difference is the point.', 'basic-firewall' )
		);

		$this->row(
			__( 'Headers', 'basic-firewall' ),
			self::textarea( 'headers', $this->submitted['headers'] ?? '', 4 ),
			__( 'One per line, as <code>Name: value</code>. Only needed if a rule looks at one.', 'basic-firewall' )
		);

		$this->row(
			__( 'Request body', 'basic-firewall' ),
			self::textarea( 'body', $this->submitted['body'] ?? '', 4 ),
			__( 'Only needed if a rule inspects the body — the Core Rule Set does.', 'basic-firewall' )
		);

		echo '</tbody></table>';

		$this->close_form( __( 'Test this request', 'basic-firewall' ) );
	}

	/**
	 * What the tester cannot tell you.
	 *
	 * Stated on the screen rather than left to the readme, because this looks
	 * like the tester being wrong.
	 */
	private function render_limits(): void {
		printf( '<h2>%s</h2>', esc_html__( 'What this cannot tell you', 'basic-firewall' ) );

		echo '<ul style="list-style:disc;margin-left:2em;max-width:48rem">';

		printf(
			'<li>%s</li>',
			wp_kses_post(
				__( '<strong>Whether a rate limit would trigger.</strong> Counters start empty for the run and one request cannot exceed a limit, so a rate limit rule never fires in a test.', 'basic-firewall' )
			)
		);

		echo '</ul>';
	}
}
