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
			__( 'Describe a request and see what the firewall would do with it. This evaluates the configuration the firewall is actually running, so the answer reflects the live rule set — and rules are evaluated whether or not the firewall is currently enabled, which is what makes this useful for checking a rule set <em>before</em> switching it on. <strong>Nothing is recorded:</strong> no address is blocked, no offense is counted, no rate limit budget is spent, and nothing reaches your log.', 'basic-firewall' )
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

		$this->render_result();
		$this->render_form();
		$this->render_limits();
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
	 * Stated on the screen rather than left to the readme, because both of
	 * these look like the tester being wrong.
	 */
	private function render_limits(): void {
		printf( '<h2>%s</h2>', esc_html__( 'What this cannot tell you', 'basic-firewall' ) );

		echo '<ul style="list-style:disc;margin-left:2em;max-width:48rem">';

		printf(
			'<li>%s</li>',
			wp_kses_post(
				__( '<strong>Whether an address is currently blocked.</strong> The block list is not consulted, so this reports whether the <em>rules</em> match. Use the lookup on the Blocked clients screen, or <code>wp basic-firewall check</code>, for that.', 'basic-firewall' )
			)
		);

		printf(
			'<li>%s</li>',
			wp_kses_post(
				__( '<strong>Whether a rate limit would trigger.</strong> Counters start empty for the run and one request cannot exceed a limit, so a rate limit rule never fires in a test.', 'basic-firewall' )
			)
		);

		echo '</ul>';
	}
}
