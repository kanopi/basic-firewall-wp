<?php
/**
 * Turns a firewall verdict into what the visitor actually gets.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Runtime;

use Kanopi\BasicFirewall\Plugin;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\ChallengeSolvedException;
use Kanopi\Firewall\Exception\FirewallBlockedException;

/**
 * Sends the response for a rejected or challenged request.
 *
 * Everything here runs before WordPress has a theme, a query, or in the
 * wp-config.php case an autoloader -- so the response is assembled by hand
 * rather than through `wp_die()` or a template. That is not a limitation to work
 * around: rejecting a request has to stay cheap, and the point of evaluating
 * this early is to spend as little as possible on traffic being turned away.
 */
final class Outcome_Responder {

	/**
	 * Respond to whatever the firewall threw.
	 *
	 * Returns true when the request may continue. Anything it actually responds
	 * to, it ends -- so the return value is only reached for outcomes that are
	 * not terminal.
	 *
	 * @param \Throwable $outcome What the firewall threw.
	 */
	public function respond( \Throwable $outcome ): bool {
		if ( $outcome instanceof ChallengeSolvedException ) {
			$this->send_solved( $outcome );

			return false;
		}

		if ( $outcome instanceof ChallengeRequiredException ) {
			$this->send_challenge( $outcome );

			return false;
		}

		if ( $outcome instanceof FirewallBlockedException ) {
			$this->send_blocked( $outcome );

			return false;
		}

		/*
		 * Anything else is a failure of the firewall rather than a verdict about
		 * the request, so the request continues. Fail open, loudly.
		 */
		return true;
	}

	/**
	 * Reject the request.
	 *
	 * @param FirewallBlockedException $outcome The rejection.
	 */
	private function send_blocked( FirewallBlockedException $outcome ): void {
		$status = $outcome->getStatusCode();

		if ( $status < 100 || $status > 599 ) {
			$status = 403;
		}

		$this->send_headers( $status );

		/*
		 * The message is administrator-authored and may contain a reference
		 * token, so it is escaped rather than trusted -- an export imported from
		 * elsewhere is a path by which somebody else's text reaches this page.
		 */
		$message = $this->escape( $outcome->getMessage() );

		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo $this->document( __( 'Request blocked', 'basic-firewall' ), $message );

		$this->finish();
	}

	/**
	 * Serve the challenge interstitial.
	 *
	 * @param ChallengeRequiredException $outcome The challenge.
	 */
	private function send_challenge( ChallengeRequiredException $outcome ): void {
		/*
		 * 503 rather than 403. The visitor is not refused -- they are asked to
		 * do something and try again -- and a 403 tells a crawler the page is
		 * forbidden, which removes it from search results. 503 with Retry-After
		 * says "come back", which is what is meant.
		 */
		$this->send_headers( 503 );
		header( 'Retry-After: 60' );

		// The library composes the interstitial, including whatever widget the
		// provider needs. It is markup by contract, so it is not escaped.
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo $outcome->getMessage();

		$this->finish();
	}

	/**
	 * A challenge was solved: set the pass cookie and send the visitor on.
	 *
	 * @param ChallengeSolvedException $outcome The solved challenge.
	 */
	private function send_solved( ChallengeSolvedException $outcome ): void {
		$settings = Plugin::instance()->settings();
		$name     = (string) $settings->get( 'challenge.cookie_name', 'bfw_pass' );

		$secure = is_ssl();

		setcookie(
			$name,
			$outcome->getToken(),
			array(
				'expires'  => 0,
				'path'     => '/',
				/*
				 * HttpOnly: the token is presented by the browser on the next
				 * request and nothing on the page needs to read it, so there is
				 * no reason for script to be able to. SameSite=Lax so an
				 * ordinary top-level navigation back to the site still carries
				 * it, while a cross-site POST does not.
				 */
				'httponly' => true,
				'secure'   => $secure,
				'samesite' => 'Lax',
			)
		);

		$redirect = $outcome->getRedirect();

		/*
		 * The redirect target came back through the challenge flow, so it is
		 * treated as untrusted: only a site-relative path is followed. Without
		 * this the challenge page is an open redirect, and an open redirect on
		 * the one page every blocked visitor is sent to is worth more to an
		 * attacker than most.
		 */
		if ( '' === $redirect || 0 !== strpos( $redirect, '/' ) || 0 === strpos( $redirect, '//' ) ) {
			$redirect = '/';
		}

		header( 'Location: ' . $redirect, true, 302 );

		$this->finish();
	}

	/**
	 * Send the headers common to every firewall response.
	 *
	 * @param int $status HTTP status code.
	 */
	private function send_headers( int $status ): void {
		if ( headers_sent() ) {
			return;
		}

		$this->status_header( $status );

		header( 'Content-Type: text/html; charset=utf-8' );

		/*
		 * Never cache a firewall response. A page cache or a CDN that stored a
		 * 403 keyed only on the URL would serve it to everybody, turning one
		 * blocked client into an outage for the whole site.
		 */
		header( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' );
		header( 'Pragma: no-cache' );
		header( 'X-Content-Type-Options: nosniff' );
		header( 'X-Robots-Tag: noindex, nofollow' );
	}

	/**
	 * Send a status header with or without WordPress.
	 *
	 * The responder runs on both evaluation paths, and on the wp-config.php one
	 * `status_header()` does not exist yet.
	 *
	 * @param int $status HTTP status code.
	 */
	private function status_header( int $status ): void {
		if ( function_exists( 'status_header' ) ) {
			status_header( $status );

			return;
		}

		$protocol = isset( $_SERVER['SERVER_PROTOCOL'] ) ? (string) $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.1';

		// Only the two protocols PHP will be serving under, so a forged
		// SERVER_PROTOCOL cannot be reflected into the response line.
		if ( ! in_array( $protocol, array( 'HTTP/1.0', 'HTTP/1.1', 'HTTP/2', 'HTTP/3' ), true ) ) {
			$protocol = 'HTTP/1.1';
		}

		header( sprintf( '%s %d', $protocol, $status ), true, $status );
	}

	/**
	 * A minimal HTML document.
	 *
	 * @param string $title Page title, already escaped.
	 * @param string $body  Body text, already escaped.
	 */
	private function document( string $title, string $body ): string {
		$title = $this->escape( $title );

		return "<!doctype html>\n"
			. "<html lang=\"en\"><head><meta charset=\"utf-8\">"
			. "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
			. "<title>{$title}</title>"
			. '<style>body{font:16px/1.5 system-ui,-apple-system,sans-serif;margin:0;'
			. 'display:flex;min-height:100vh;align-items:center;justify-content:center;'
			. 'background:#f6f7f7;color:#1e1e1e}main{max-width:34rem;padding:2rem;text-align:center}'
			. 'h1{font-size:1.25rem;margin:0 0 .5rem}p{margin:0;color:#50575e}'
			. '@media(prefers-color-scheme:dark){body{background:#1e1e1e;color:#f0f0f1}p{color:#a7aaad}}'
			. "</style></head><body><main><h1>{$title}</h1><p>{$body}</p></main></body></html>\n";
	}

	/**
	 * Escape for HTML.
	 *
	 * `esc_html()` is not used: this runs on the wp-config.php path too, where
	 * WordPress does not exist yet.
	 *
	 * @param string $text Untrusted text.
	 */
	private function escape( string $text ): string {
		return htmlspecialchars( $text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8' );
	}

	/**
	 * End the request.
	 */
	private function finish(): void {
		/**
		 * Fires immediately before the firewall ends a rejected request.
		 *
		 * The last chance to observe a block on the normal path. Nothing after
		 * this runs -- not shutdown functions registered later, not WordPress.
		 */
		if ( function_exists( 'do_action' ) ) {
			do_action( 'basic_firewall_request_ended' );
		}

		exit;
	}
}

