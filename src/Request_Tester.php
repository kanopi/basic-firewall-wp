<?php
/**
 * Answers "would this request be blocked?" without blocking anything.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall;

use Kanopi\BasicFirewall\Compiler\Library_Map;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Firewall;
use Monolog\Handler\TestHandler;
use Monolog\Level;
use Symfony\Component\HttpFoundation\Request;

/**
 * Evaluates a described request against the live rule set.
 *
 * **Nothing is recorded.** That is the part worth stating explicitly, because
 * recording a block writes to storage -- it adds the client to the block list
 * and counts an offense towards escalation. A test tool that did not isolate
 * that would block whatever address somebody typed in to ask about, which is
 * the opposite of what they wanted and is discovered at the worst moment.
 *
 * So for the duration of a run, four things are overridden:
 *
 * | Changed                        | Why                                             |
 * |--------------------------------|-------------------------------------------------|
 * | Mode becomes `exception`       | Blocking mode writes a response and calls exit(), which would take the admin page down with it |
 * | Storage becomes in-memory      | Otherwise the tested address is blocked for real and gains an offense |
 * | Rate limit counters in-memory  | Otherwise a test spends a real visitor's request budget |
 * | Log handlers are replaced      | The run's records go to the screen, not into your firewall log |
 *
 * Rules are evaluated whether or not the firewall is currently enabled, which
 * is what makes this useful for checking a rule set *before* switching it on.
 */
final class Request_Tester {

	/**
	 * Evaluate a described request.
	 *
	 * @param array<string, mixed> $described Path, method, ip, user agent, headers.
	 *
	 * @return array{verdict: string, status: int|null, rule: string|null, message: string, log: list<string>, error: string|null}
	 */
	public function test( array $described ): array {
		$compiled = Plugin::instance()->paths()->compiled_file();

		if ( ! is_readable( $compiled ) ) {
			return $this->failure( __( 'There is no compiled configuration to test against. Rebuild the firewall first.', 'basic-firewall' ) );
		}

		$capture = new TestHandler( Level::Debug );

		try {
			$firewall = Firewall::create( array( $compiled ), $this->overrides( $capture ) );
		} catch ( \Throwable $e ) {
			return $this->failure(
				sprintf(
					/* translators: %s: error message. */
					__( 'The firewall could not start, so nothing could be tested: %s', 'basic-firewall' ),
					$e->getMessage()
				)
			);
		}

		$request = $this->build_request( $described );

		try {
			$allowed = $firewall->evaluate( $request );

			return array(
				'verdict' => $allowed ? 'allow' : 'block',
				'status'  => null,
				'rule'    => null,
				'message' => $allowed
					? __( 'Allowed. No rule matched this request.', 'basic-firewall' )
					: __( 'Blocked.', 'basic-firewall' ),
				'log'     => $this->format_log( $capture ),
				'error'   => null,
			);
		} catch ( FirewallBlockedException $e ) {
			return array(
				'verdict' => 'block',
				'status'  => $e->getStatusCode(),
				'rule'    => $this->rule_from_log( $capture ),
				'message' => $e->getMessage(),
				'log'     => $this->format_log( $capture ),
				'error'   => null,
			);
		} catch ( ChallengeRequiredException $e ) {
			return array(
				'verdict' => 'challenge',
				'status'  => 503,
				'rule'    => $this->rule_from_log( $capture ),
				'message' => __( 'The visitor would be challenged before being allowed through.', 'basic-firewall' ),
				'log'     => $this->format_log( $capture ),
				'error'   => null,
			);
		} catch ( \Throwable $e ) {
			return $this->failure( $e->getMessage(), $this->format_log( $capture ) );
		}
	}

	/**
	 * The overrides that make a test leave no trace.
	 *
	 * @param TestHandler $capture Collects the run's log records.
	 *
	 * @return array<string, mixed>
	 */
	private function overrides( TestHandler $capture ): array {
		return array(
			// Throw rather than respond-and-exit, which would end the admin page.
			'[global][mode]'    => 'exception',
			// Nothing the test does outlives the request.
			'[storage][type]'   => Library_Map::STORAGE['memory'],
			'[storage][config]' => array(),
			// The run's records go to the screen.
			'[logger]'          => array( array( 'class' => $capture ) ),
		);
	}

	/**
	 * Build a Symfony request from the described one.
	 *
	 * @param array<string, mixed> $described Description.
	 */
	private function build_request( array $described ): Request {
		$path   = (string) ( $described['path'] ?? '/' );
		$method = strtoupper( (string) ( $described['method'] ?? 'GET' ) );
		$body   = (string) ( $described['body'] ?? '' );

		$request = Request::create(
			'' === $path ? '/' : $path,
			$method,
			array(),
			array(),
			array(),
			array(),
			'' === $body ? null : $body
		);

		$ip = trim( (string) ( $described['ip'] ?? '' ) );

		if ( '' !== $ip ) {
			/*
			 * Set on REMOTE_ADDR rather than X-Forwarded-For. The tester asks
			 * "what would the rules do to this client?", and going through the
			 * forwarding header would make the answer depend on whether trusted
			 * proxies happen to be configured -- which is a different question,
			 * and one Site Health already answers.
			 */
			$request->server->set( 'REMOTE_ADDR', $ip );
		}

		$agent = (string) ( $described['user_agent'] ?? '' );

		if ( '' !== $agent ) {
			$request->headers->set( 'User-Agent', $agent );
		}

		foreach ( $this->parse_headers( (string) ( $described['headers'] ?? '' ) ) as $name => $value ) {
			$request->headers->set( $name, $value );
		}

		return $request;
	}

	/**
	 * Parse a "Name: value" block into headers.
	 *
	 * @param string $raw Raw textarea content.
	 *
	 * @return array<string, string>
	 */
	private function parse_headers( string $raw ): array {
		$headers = array();

		$lines = preg_split( '/\R/', $raw );

		foreach ( is_array( $lines ) ? $lines : array() as $line ) {
			$line = trim( (string) $line );

			if ( '' === $line || false === strpos( $line, ':' ) ) {
				continue;
			}

			list( $name, $value ) = explode( ':', $line, 2 );

			$name = trim( $name );

			if ( '' !== $name ) {
				$headers[ $name ] = trim( $value );
			}
		}

		return $headers;
	}

	/**
	 * Turn the captured records into readable lines.
	 *
	 * @param TestHandler $capture The capture handler.
	 *
	 * @return list<string>
	 */
	private function format_log( TestHandler $capture ): array {
		$lines = array();

		foreach ( $capture->getRecords() as $record ) {
			$context = $record['context'] ?? array();

			$lines[] = sprintf(
				'[%s] %s%s',
				$record['level_name'] ?? '',
				$record['message'] ?? '',
				array() === $context ? '' : ' ' . (string) wp_json_encode( $context )
			);
		}

		return $lines;
	}

	/**
	 * Work out which rule decided, from the captured records.
	 *
	 * @param TestHandler $capture The capture handler.
	 */
	private function rule_from_log( TestHandler $capture ): ?string {
		foreach ( array_reverse( $capture->getRecords() ) as $record ) {
			$context = $record['context'] ?? array();

			foreach ( array( 'name', 'plugin', 'rule' ) as $key ) {
				if ( isset( $context[ $key ] ) && is_string( $context[ $key ] ) && '' !== $context[ $key ] ) {
					return $context[ $key ];
				}
			}
		}

		return null;
	}

	/**
	 * Build a failure result.
	 *
	 * @param string       $message Why.
	 * @param list<string> $log     Captured log lines.
	 *
	 * @return array{verdict: string, status: int|null, rule: string|null, message: string, log: list<string>, error: string|null}
	 */
	private function failure( string $message, array $log = array() ): array {
		return array(
			'verdict' => 'error',
			'status'  => null,
			'rule'    => null,
			'message' => $message,
			'log'     => $log,
			'error'   => $message,
		);
	}
}
