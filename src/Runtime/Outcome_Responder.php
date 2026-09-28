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
use Kanopi\Firewall\Exception\FirewallLockdownException;
use Kanopi\Firewall\Exception\FirewallRedirectException;
use Symfony\Component\HttpFoundation\Request;

/**
 * Sends the response for a rejected or challenged request.
 *
 * Everything here runs before WordPress has a theme, a query, or in the
 * wp-config.php case an autoloader -- so the response is assembled by hand
 * rather than through `wp_die()` or a template. That is not a limitation to work
 * around: rejecting a request has to stay cheap, and the point of evaluating
 * this early is to spend as little as possible on traffic being turned away.
 *
 * **Runs without WordPress.** The wp-config.php bootstrap loads this class by
 * hand and answers `exception` mode refusals with it before WordPress exists,
 * because the alternative -- waiting for the mu-plugin -- lets a page cache in
 * advanced-cache.php serve the page first. So every WordPress function reached
 * on the way to a refusal is guarded, and the one outcome that genuinely needs
 * WordPress, a solved challenge, is left by the bootstrap for the runner. See
 * basic_firewall_answer_outcome() in bootstrap.php.
 */
final class Outcome_Responder {

	/**
	 * Respond to whatever the firewall threw.
	 *
	 * Returns true when the request may continue. Anything it actually responds
	 * to, it ends -- so the return value is only reached for outcomes that are
	 * not terminal.
	 *
	 * @param \Throwable   $outcome What the firewall threw.
	 * @param Request|null $request The request it was thrown about. A challenge
	 *                              needs it to render the interstitial, and a
	 *                              solved one to know how the page asked.
	 */
	public function respond( \Throwable $outcome, ?Request $request = null ): bool {
		if ( $outcome instanceof ChallengeSolvedException ) {
			$this->send_solved( $outcome, $request );

			return false;
		}

		if ( $outcome instanceof ChallengeRequiredException ) {
			$this->send_challenge( $outcome, $request );

			return false;
		}

		/*
		 * Before the refusal, although the two cannot be confused: a redirect
		 * extends FirewallException, not FirewallBlockedException. It is here
		 * because until it was, a redirect fell through to "anything else" below
		 * and was treated as a firewall failure -- so in `exception` mode a rule
		 * chosen to send the visitor somewhere served them the page instead, and
		 * the log recorded a broken firewall on every request it matched.
		 */
		if ( $outcome instanceof FirewallRedirectException ) {
			$this->send_redirect( $outcome );

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
		 * A lockdown refusal is temporary and says so. The library sends this
		 * header itself when it delivers the refusal; in `exception` mode it
		 * hands the refusal here instead, and dropping the header would turn a
		 * deliberate, short-lived 503 into one a CDN has no reason to retry.
		 */
		if ( $outcome instanceof FirewallLockdownException && $outcome->getRetryAfter() > 0 && ! headers_sent() ) {
			header( 'Retry-After: ' . $outcome->getRetryAfter() );
		}

		/*
		 * The message is administrator-authored and may contain a reference
		 * token, so it is escaped rather than trusted -- an export imported from
		 * elsewhere is a path by which somebody else's text reaches this page.
		 */
		$message = $this->escape( $outcome->getMessage() );

		// Translated when WordPress is there to translate it; on the
		// wp-config.php path it is not, and English is better than nothing.
		$title = function_exists( '__' ) ? __( 'Request blocked', 'basic-firewall' ) : 'Request blocked';

		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo $this->document( $title, $message );

		$this->finish();
	}

	/**
	 * Send the visitor where a redirect rule said to.
	 *
	 * Reached only in `exception` mode. In every other mode the library writes
	 * the `Location` header itself and exits, so this is the same answer given
	 * by hand -- and it should be the same answer, not a refusal: a redirect is
	 * the response somebody chose precisely because a bare 403 leaves the
	 * visitor nowhere to go.
	 *
	 * The destination is followed as the rule states it, unlike the challenge
	 * redirect below. It came from the rule's own configuration and never from
	 * the request, and the rule screen and the compiler have both already
	 * refused one that is not a site path or an http(s) URL.
	 *
	 * @param FirewallRedirectException $outcome The redirect.
	 */
	private function send_redirect( FirewallRedirectException $outcome ): void {
		$target = self::redirect_target( $outcome );

		if ( ! headers_sent() ) {
			$this->status_header( $target['status'] );

			/*
			 * `no-store` for the reason every firewall response carries it: a
			 * page cache that kept this redirect keyed on the URL would send
			 * every visitor to the notice page, not just the one the rule
			 * caught.
			 */
			header( 'Location: ' . $target['location'], true, $target['status'] );
			header( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' );
			header( 'X-Robots-Tag: noindex, nofollow' );
		}

		$this->finish();
	}

	/**
	 * Where a redirect outcome sends the visitor, and with which status.
	 *
	 * Separate from sending it so the decision can be tested; sending ends the
	 * request.
	 *
	 * A status outside the four the library honours is answered with 302, the
	 * library's own default. The library never builds one -- it reads the
	 * rule's status through the same four -- but this exception is a public
	 * class that anything can construct, and a 200 with a `Location` header is
	 * a page, not a redirect.
	 *
	 * @param FirewallRedirectException $outcome The redirect.
	 *
	 * @return array{location: string, status: int}
	 */
	public static function redirect_target( FirewallRedirectException $outcome ): array {
		$status = $outcome->getStatusCode();

		return array(
			'location' => $outcome->getLocation(),
			'status'   => in_array( $status, array( 301, 302, 307, 308 ), true ) ? $status : 302,
		);
	}

	/**
	 * Serve the challenge interstitial.
	 *
	 * Reached only on the exception path -- the request tester, and any site
	 * running in `exception` mode. In blocking mode the library composes and
	 * sends the interstitial itself and then exits, answering 200 with
	 * `Cache-Control: no-store` and a `noindex` page, so none of this runs.
	 *
	 * The page is the library's own, rendered by the exception from the
	 * context the firewall assembled -- including the signed provider token,
	 * without which a solved challenge mints a pass the rule then refuses and
	 * the visitor is served the same interstitial forever. This used to echo
	 * the exception's message, which is a sentence naming the rule, not a page:
	 * a challenged visitor in `exception` mode got that sentence and no way to
	 * answer it.
	 *
	 * 503 rather than the library's 200, because the visitor is not being
	 * served the page they asked for, and a 403 would tell a crawler the page
	 * is forbidden and remove it from search results. 503 with Retry-After says
	 * "come back", which is what is meant.
	 *
	 * @param ChallengeRequiredException $outcome The challenge.
	 * @param Request|null               $request The request being challenged.
	 */
	private function send_challenge( ChallengeRequiredException $outcome, ?Request $request ): void {
		$body = null;

		if ( null !== $request ) {
			try {
				$body = $outcome->renderInterstitial( $request );
			} catch ( \Throwable $e ) {
				// No provider was resolved, which the library reports on its
				// own. Handled below.
				$body = null;
			}
		}

		$this->send_headers( 503 );

		if ( ! headers_sent() ) {
			header( 'Retry-After: 60' );
		}

		if ( null === $body ) {
			/*
			 * A challenge that cannot be put in front of the visitor still
			 * does not serve them the page. The rule decided they must prove
			 * something first, and nothing can be proven -- so they get a
			 * temporary refusal saying so, rather than the page the rule was
			 * written to stand in front of.
			 */
			$title = function_exists( '__' ) ? __( 'Verification required', 'basic-firewall' ) : 'Verification required';
			$text  = function_exists( '__' )
				? __( 'This request needs a verification step that could not be shown. Please try again shortly.', 'basic-firewall' )
				: 'This request needs a verification step that could not be shown. Please try again shortly.';

			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo $this->document( $title, $this->escape( $text ) );

			$this->finish();

			return;
		}

		// The library composes the interstitial, including whatever widget the
		// provider needs. It is markup by contract, so it is not escaped.
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo $body;

		$this->finish();
	}

	/**
	 * A challenge was solved: set the pass cookie and send the visitor on.
	 *
	 * Needs WordPress, for the cookie name in settings and for `is_ssl()`. The
	 * wp-config.php bootstrap therefore never answers this outcome itself; it
	 * leaves it for the runner, which is safe because a solution is a POST to
	 * the challenge path and no page cache serves a POST.
	 *
	 * @param ChallengeSolvedException $outcome The solved challenge.
	 * @param Request|null             $request The submission.
	 */
	private function send_solved( ChallengeSolvedException $outcome, ?Request $request ): void {
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

		$solved = self::solved_response( $outcome, $request );

		if ( 'json' === $solved['format'] ) {
			if ( ! headers_sent() ) {
				$this->status_header( 200 );
				header( 'Content-Type: application/json; charset=utf-8' );
				header( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' );
			}

			$json = (string) wp_json_encode(
				array(
					'token'    => $outcome->getToken(),
					'redirect' => $solved['redirect'],
				),
				JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES
			);

			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- JSON, encoded with the flags that keep it inert if anything renders it as HTML.
			echo $json;

			$this->finish();

			return;
		}

		header( 'Location: ' . $solved['redirect'], true, 302 );

		$this->finish();
	}

	/**
	 * How a solved challenge is answered, and where it sends the visitor.
	 *
	 * Separate from sending it so the decision can be tested; sending ends the
	 * request.
	 *
	 * **JSON when the page asked for JSON.** The library's interstitial posts
	 * its solution with `fetch()`, asking for `application/json`, and reads the
	 * token and destination out of the reply -- which is what the library
	 * sends in blocking mode. A 302 there is followed by the browser, the
	 * script receives the destination page instead of JSON, and the visitor is
	 * told their correct answer failed. A plain form post, with no script, is
	 * still answered with the redirect.
	 *
	 * The redirect target came back through the challenge flow, so it is
	 * treated as untrusted: only a site-relative path is followed. Without
	 * this the challenge page is an open redirect, and an open redirect on
	 * the one page every blocked visitor is sent to is worth more to an
	 * attacker than most.
	 *
	 * @param ChallengeSolvedException $outcome The solved challenge.
	 * @param Request|null             $request The submission.
	 *
	 * @return array{format: string, redirect: string}
	 */
	public static function solved_response( ChallengeSolvedException $outcome, ?Request $request ): array {
		$redirect = $outcome->getRedirect();

		if ( '' === $redirect || 0 !== strpos( $redirect, '/' ) || 0 === strpos( $redirect, '//' ) || 0 === strpos( $redirect, '/\\' ) ) {
			$redirect = '/';
		}

		$wants_json = null !== $request
			&& false !== stripos( (string) $request->headers->get( 'Accept', '' ), 'application/json' );

		return array(
			'format'   => $wants_json ? 'json' : 'redirect',
			'redirect' => $redirect,
		);
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

		/*
		 * Read raw rather than through sanitize_text_field(): this branch is
		 * the one that runs without WordPress, so calling it here was a fatal
		 * error in exactly the case the branch exists for. The allowlist below
		 * is the sanitisation -- anything not on it is replaced, not cleaned.
		 */
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- compared against a fixed list below and replaced unless it matches exactly.
		$protocol = isset( $_SERVER['SERVER_PROTOCOL'] ) ? (string) $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.1';

		// Only the protocols PHP will be serving under, so a forged
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
			. '<html lang="en"><head><meta charset="utf-8">'
			. '<meta name="viewport" content="width=device-width,initial-scale=1">'
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
