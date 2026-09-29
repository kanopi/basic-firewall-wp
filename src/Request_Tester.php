<?php
/**
 * Answers "would this request be blocked?" without blocking anything.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall;

use Kanopi\BasicFirewall\Cache\Cache_Backend;
use Kanopi\BasicFirewall\Compiler\Library_Map;
use Kanopi\BasicFirewall\Logging\Log_Reader;
use Kanopi\BasicFirewall\Logging\Redaction;
use Kanopi\BasicFirewall\Runtime\Request_Factory;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Exception\FirewallRedirectException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Plugins\RateLimit;
use Kanopi\Firewall\Utility\Config;
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
 * So for the duration of a run, five things are overridden:
 *
 * | Changed                        | Why                                             |
 * |--------------------------------|-------------------------------------------------|
 * | Mode becomes `exception`       | Blocking mode writes a response and calls exit(), which would take the admin page down with it |
 * | The panic file is ignored      | It is applied over the mode above, so `block` in it would end the admin page too -- and the question here is what the rules decide, not what an incident has them doing |
 * | Storage becomes in-memory      | Otherwise the tested address is blocked for real and gains an offense |
 * | Rate limit counters in-memory  | Otherwise a test spends a real visitor's request budget, and enough tests limit them for real |
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

		// The run's log is shown on screen, which is somewhere else a session
		// token should not appear.
		Redaction::apply( (array) Plugin::instance()->settings()->get( 'logging.redact_extra', array() ) );

		try {
			$firewall = Firewall::create( array( $compiled ), $this->overrides( $capture, $compiled ) );
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

			if ( $allowed ) {
				$served = $this->served_but_noticed( $capture );

				if ( null !== $served ) {
					return $served;
				}
			}

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
		} catch ( FirewallRedirectException $e ) {
			/*
			 * Caught by name. In `exception` mode a redirect arrives as an
			 * exception like every other decision, and before this it fell
			 * through to the catch-all below -- so testing a redirect rule that
			 * worked perfectly reported that the request could not be tested.
			 */
			return array(
				'verdict' => 'redirect',
				'status'  => $e->getStatusCode(),
				'rule'    => $this->rule_from_log( $capture ),
				'message' => sprintf(
					/* translators: 1: destination, 2: HTTP status. */
					__( 'A redirect rule matched. This request would be sent to %1$s with a %2$d.', 'basic-firewall' ),
					$e->getLocation(),
					$e->getStatusCode()
				),
				'log'     => $this->format_log( $capture ),
				'error'   => null,
			);
		} catch ( \Throwable $e ) {
			return $this->failure( $e->getMessage(), $this->format_log( $capture ) );
		}
	}

	/**
	 * A served request that a record, observing or mark rule acted on, or null.
	 *
	 * All three serve the request by design, so the firewall answers "allowed"
	 * and the log line is the only evidence any of them fired. Without reading
	 * it, testing a honeypot reports "no rule matched" at the moment it has
	 * just caught the tester, and testing the rule you just set to observe
	 * reports that it does not work -- both of which read as the rule being
	 * broken.
	 *
	 * Strongest claim first. A record says the client will be refused next
	 * time, which is something happening. An observed match is next: the
	 * administrator is asking specifically what that rule would have done. A
	 * mark says only that a rule noticed.
	 *
	 * @param TestHandler $capture The capture handler.
	 *
	 * @return array{verdict: string, status: int|null, rule: string|null, message: string, log: list<string>, error: string|null}|null
	 */
	private function served_but_noticed( TestHandler $capture ): ?array {
		$recorded = null;
		$observed = null;
		$marked   = null;
		$mark     = null;

		foreach ( $capture->getRecords() as $record ) {
			$message = (string) ( $record['message'] ?? '' );
			$context = $record['context'] ?? array();
			$plugin  = is_string( $context['plugin_name'] ?? null ) ? $context['plugin_name'] : null;

			if ( null === $plugin ) {
				continue;
			}

			if ( false !== stripos( $message, 'client recorded without being refused' ) ) {
				$recorded = $plugin;
			}

			/*
			 * An observed match is treated as no match, so the request goes on
			 * to be decided by something else entirely; this line is the only
			 * trace of it.
			 */
			if ( false !== stripos( $message, Log_Reader::OBSERVED_MESSAGE ) ) {
				$observed = $plugin;
			}

			if ( false !== stripos( $message, 'request marked' ) ) {
				$marked = $plugin;
				$mark   = is_string( $context['mark'] ?? null ) ? $context['mark'] : null;
			}
		}

		if ( null !== $recorded ) {
			return array(
				'verdict' => 'record',
				'status'  => null,
				'rule'    => $recorded,
				'message' => __( 'A record rule matched. This request would be served normally — that is the point — and the client would be refused from its next one.', 'basic-firewall' ),
				'log'     => $this->format_log( $capture ),
				'error'   => null,
			);
		}

		if ( null !== $observed ) {
			return array(
				'verdict' => 'observe',
				'status'  => null,
				'rule'    => $observed,
				'message' => __( 'A rule matched while set to observe only. This request would be served — the rule acts on nothing — and the match would be logged for you to count.', 'basic-firewall' ),
				'log'     => $this->format_log( $capture ),
				'error'   => null,
			);
		}

		if ( null !== $marked ) {
			return array(
				'verdict' => 'mark',
				'status'  => null,
				'rule'    => $marked,
				'message' => null === $mark
					? __( 'A mark rule matched. This request would be served normally, with a signal left on it for this site\'s own code to read.', 'basic-firewall' )
					: sprintf(
						/* translators: %s: the mark name. */
						__( 'A mark rule matched. This request would be served normally, carrying the mark "%s" for this site\'s own code to read.', 'basic-firewall' ),
						$mark
					),
				'log'     => $this->format_log( $capture ),
				'error'   => null,
			);
		}

		return null;
	}

	/**
	 * The overrides that make a test leave no trace.
	 *
	 * @param TestHandler $capture  Collects the run's log records.
	 * @param string      $compiled The compiled file the run evaluates against.
	 *
	 * @return array<string, mixed>
	 */
	private function overrides( TestHandler $capture, string $compiled ): array {
		$overrides = array(
			// Throw rather than respond-and-exit, which would end the admin page.
			'[global][mode]'       => 'exception',
			// Or the line above is undone by whatever an armed panic file says.
			'[global][panic_file]' => '',
			// Nothing the test does outlives the request.
			'[storage][type]'      => Library_Map::STORAGE['memory'],
			'[storage][config]'    => array(),
			// The run's records go to the screen.
			'[logger]'             => array( array( 'class' => $capture ) ),
		);

		$overrides += self::rate_limit_overrides( $compiled );

		/*
		 * And the caches, aimed wherever the site chose. Without this a test
		 * falls back to the library's filesystem pool and writes a second copy
		 * of the agent corpus to disk, on a site that moved its caches off disk
		 * precisely to avoid that.
		 */
		return $overrides + Cache_Backend::overrides();
	}

	/**
	 * Point every rate limit's counters at memory for the run.
	 *
	 * A rate limit keeps its counters in its own storage, not the block list's,
	 * so overriding `[storage]` left them alone: each test of a rate-limited
	 * path spent a request of the real client's allowance, in the real file,
	 * table or Redis. Test an address a few times and it was limited for real
	 * -- exactly the side effect this class exists to rule out.
	 *
	 * The indices come from the configuration the library will actually load,
	 * presets included, because a preset's rate limit counts as much as one
	 * of ours and its plugins are appended after them. Loading it here costs a
	 * read of the parse cache the firewall is about to read anyway.
	 *
	 * Every rate limit, whatever configured it, including one with no storage
	 * of its own: the library's default for that is a file.
	 *
	 * @param string $compiled The compiled file.
	 *
	 * @return array<string, mixed>
	 */
	public static function rate_limit_overrides( string $compiled ): array {
		try {
			/*
			 * The same list Firewall::create() loads, the library's defaults
			 * first, so the indices are the ones the overrides will land on and
			 * the parse cache entry is the one it is about to use.
			 */
			$defaults = dirname( (string) ( new \ReflectionClass( Firewall::class ) )->getFileName() ) . '/../config/config.yml';
			$config   = Config::load( array( $defaults, $compiled ) );
		} catch ( \Throwable $e ) {
			// Firewall::create() will fail on the same file and say why.
			return array();
		}

		$overrides = array();

		foreach ( (array) ( $config['plugins'] ?? array() ) as $delta => $plugin ) {
			$class = is_array( $plugin ) ? ltrim( (string) ( $plugin['plugin'] ?? '' ), '\\' ) : '';

			if ( '' === $class || ! is_a( $class, RateLimit::class, true ) ) {
				continue;
			}

			$overrides[ sprintf( '[plugins][%s][metadata][storage]', $delta ) ] = array(
				'type'   => Library_Map::RATE_LIMIT_STORAGE['memory'],
				'config' => array(),
			);
		}

		return $overrides;
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

		$request = self::site_request( '' === $path ? '/' : $path, $method, '' === $body ? null : $body );

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
	 * A made-up request for a path on this site, built as a live one would be.
	 *
	 * Built as a web server would describe the same request to this site,
	 * then corrected by Request_Factory exactly as a live request is. So
	 * `/wp-login.php` is tested as the direct request for wp-login.php it
	 * would be in production, and the answer here is the answer there. Site
	 * Health builds its regression check the same way.
	 *
	 * @param string      $path   Path relative to the site, with any query.
	 * @param string      $method HTTP method.
	 * @param string|null $body   Request body.
	 */
	public static function site_request( string $path, string $method = 'GET', ?string $body = null ): Request {
		$server = Request_Factory::server_for( $path, self::site_path(), ABSPATH );

		$request = Request::create( $server['REQUEST_URI'], $method, array(), array(), array(), $server, $body );

		Request_Factory::normalise( $request );

		return $request;
	}

	/**
	 * The site's own path on its host: empty, or `/blog` for a site served there.
	 *
	 * From the WordPress address, because that is where ABSPATH is served from
	 * and so where the web server says the front controller is.
	 */
	private static function site_path(): string {
		$path = wp_parse_url( site_url( '/' ), PHP_URL_PATH );

		return is_string( $path ) ? rtrim( $path, '/' ) : '';
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
