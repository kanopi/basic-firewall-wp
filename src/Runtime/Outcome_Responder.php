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
use Kanopi\Firewall\Utility\NoStore;
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
	 * The cookie a solved challenge sets beside the pass, for a little while.
	 *
	 * Its only job is to let the next challenge tell "never solved" from
	 * "solved, and the pass did not come back" (see pass_went_missing()).
	 * `wp-` because that prefix is on Pantheon's pass-through list -- the host
	 * the problem was found on, and the one whose edge would otherwise strip
	 * the marker along with the pass. On Pantheon a `wp-` cookie also keeps
	 * the edge cache out of the way for the marker's short life, which is no
	 * loss straight after a challenge.
	 */
	public const SOLVED_MARKER = 'wp-bfw-solved';

	/**
	 * How long the marker lives, in seconds.
	 *
	 * Long enough to cover the redirect and a slow page, short enough that a
	 * visitor who clears their cookies later is not told a stale story.
	 */
	public const SOLVED_MARKER_TTL = 120;

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
			$this->emit( self::challenge_response( $outcome, $request ) );

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
			$this->emit( self::redirect_response( $outcome ) );

			return false;
		}

		if ( $outcome instanceof FirewallBlockedException ) {
			$this->emit( self::blocked_response( $outcome ) );

			return false;
		}

		/*
		 * A verdict this copy of the plugin cannot answer in full, because it
		 * was thrown by a library copy under the other namespace: a release
		 * build carries the library scoped and this class's imports with it,
		 * a Composer install carries neither, and a site with both can hand
		 * one's exception to the other's responder. The instanceof checks
		 * above then all miss, and this used to fall through to "anything
		 * else" and let the request continue -- serving the page to a visitor
		 * the firewall had just refused or challenged, with nothing logged.
		 * A verdict is never a reason to serve the page, so it is refused.
		 */
		$kind = self::verdict_kind( $outcome );

		if ( null !== $kind ) {
			$this->refuse( $kind, sprintf( 'the verdict is a %s, which this copy of the plugin does not answer', get_class( $outcome ) ) );

			return false;
		}

		/*
		 * Anything else is a failure of the firewall rather than a verdict about
		 * the request, so the request continues. Fail open, loudly.
		 */
		return true;
	}

	/**
	 * Refuse a request whose verdict cannot be answered properly.
	 *
	 * The last answer, for a verdict that could not be rendered or handed to
	 * the right method. Whatever the verdict was -- a challenge with no page
	 * to show, a redirect, a block -- the visitor is not served the page the
	 * rule stands in front of: they get a temporary refusal, and the reason
	 * goes to the PHP error log at warning, where somebody investigating a
	 * visitor's complaint can find it.
	 *
	 * @param string $kind `challenge`, `redirect`, `blocked` or `solved`.
	 * @param string $why  What went wrong, for the log.
	 */
	public function refuse( string $kind, string $why ): void {
		self::warn( sprintf( 'a %s verdict could not be answered (%s), so the request was refused.', $kind, $why ) );

		$this->emit( self::refusal_response() );
	}

	/**
	 * Which verdict an outcome is, in either class spelling, or null.
	 *
	 * By class name in both spellings, as basic_firewall_outcome_kind() in
	 * bootstrap.php does and for the same reason: a release build carries the
	 * library under a prefix and a Composer install does not.
	 *
	 * @param \Throwable $outcome What the firewall threw.
	 *
	 * @return string|null `solved`, `challenge`, `redirect`, `blocked`, or null.
	 */
	public static function verdict_kind( \Throwable $outcome ): ?string {
		$kinds = array(
			'ChallengeSolvedException'   => 'solved',
			'ChallengeRequiredException' => 'challenge',
			'FirewallRedirectException'  => 'redirect',

			// FirewallLockdownException extends this one.
			'FirewallBlockedException'   => 'blocked',
		);

		foreach ( $kinds as $class => $kind ) {
			foreach ( array( 'Kanopi\\Firewall\\Exception\\', 'Kanopi\\BasicFirewall\\Vendor\\Kanopi\\Firewall\\Exception\\' ) as $namespace ) {
				if ( is_a( $outcome, $namespace . $class ) ) {
					return $kind;
				}
			}
		}

		return null;
	}

	/**
	 * The response for a rejected request.
	 *
	 * Separate from sending it, as every response here is, so what a visitor
	 * receives can be tested; sending ends the request.
	 *
	 * @param FirewallBlockedException $outcome The rejection.
	 *
	 * @return array{status: int, headers: array<string, string>, body: string, warning: string|null}
	 */
	public static function blocked_response( FirewallBlockedException $outcome ): array {
		$status = $outcome->getStatusCode();

		if ( $status < 100 || $status > 599 ) {
			$status = 403;
		}

		$headers = self::page_headers();

		/*
		 * A lockdown refusal is temporary and says so. The library sends this
		 * header itself when it delivers the refusal; in `exception` mode it
		 * hands the refusal here instead, and dropping the header would turn a
		 * deliberate, short-lived 503 into one a CDN has no reason to retry.
		 */
		if ( $outcome instanceof FirewallLockdownException && $outcome->getRetryAfter() > 0 ) {
			$headers['Retry-After'] = (string) $outcome->getRetryAfter();
		}

		/*
		 * The message is administrator-authored and may contain a reference
		 * token, so it is escaped rather than trusted -- an export imported from
		 * elsewhere is a path by which somebody else's text reaches this page.
		 */
		$title = self::can_translate() ? __( 'Request blocked', 'basic-firewall' ) : 'Request blocked';

		return array(
			'status'  => $status,
			'headers' => $headers,
			'body'    => self::document( $title, self::escape( $outcome->getMessage() ) ),
			'warning' => null,
		);
	}

	/**
	 * The response that sends the visitor where a redirect rule said to.
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
	 * No-store for the reason every firewall response carries it: a page
	 * cache that kept this redirect keyed on the URL would send every visitor
	 * to the notice page, not just the one the rule caught.
	 *
	 * @param FirewallRedirectException $outcome The redirect.
	 *
	 * @return array{status: int, headers: array<string, string>, body: string, warning: string|null}
	 */
	public static function redirect_response( FirewallRedirectException $outcome ): array {
		$target = self::redirect_target( $outcome );

		return array(
			'status'  => $target['status'],
			'headers' => array( 'Location' => $target['location'] ) + self::no_store_headers() + array( 'X-Robots-Tag' => 'noindex, nofollow' ),
			'body'    => '',
			'warning' => null,
		);
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
	 * The challenge interstitial.
	 *
	 * Reached only on the exception path -- the request tester, and any site
	 * running in `exception` mode. In blocking mode the library composes and
	 * sends the interstitial itself and then exits, so none of this runs.
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
	 * A challenge that cannot be rendered -- no request to render it for, or a
	 * provider that fails -- is the refusal instead, never the page, and the
	 * reason is carried out as `warning` for the log.
	 *
	 * @param ChallengeRequiredException $outcome The challenge.
	 * @param Request|null               $request The request being challenged.
	 *
	 * @return array{status: int, headers: array<string, string>, body: string, warning: string|null}
	 */
	public static function challenge_response( ChallengeRequiredException $outcome, ?Request $request ): array {
		if ( null === $request ) {
			$response            = self::refusal_response();
			$response['warning'] = 'a challenge was reached with no request to render the interstitial for, so the request was refused.';

			return $response;
		}

		try {
			$body = $outcome->renderInterstitial( $request );
		} catch ( \Throwable $e ) {
			$response            = self::refusal_response();
			$response['warning'] = sprintf( 'the challenge interstitial could not be rendered (%s: %s), so the request was refused.', get_class( $e ), $e->getMessage() );

			return $response;
		}

		$warning = null;

		if ( self::pass_went_missing( $outcome, $request ) ) {
			$body    = self::with_missing_pass_notice( $body );
			$warning = 'a visitor who solved a challenge moments ago came back without the pass cookie, so the host or the browser is not returning it.';
		}

		// The library composes the interstitial, including whatever widget the
		// provider needs. It is markup by contract, so it is not escaped.
		return array(
			'status'  => 503,
			'headers' => self::page_headers() + array( 'Retry-After' => '60' ),
			'body'    => $body,
			'warning' => $warning,
		);
	}

	/**
	 * Is this visitor being challenged again right after solving a challenge?
	 *
	 * A solved challenge sets the pass cookie and, beside it, a short-lived
	 * marker (see solved_cookies()). A challenge that arrives carrying the
	 * marker but no pass cookie at all means the pass was issued and then did
	 * not come back: a CDN stripping it, as Pantheon's does with a name that
	 * matches none of its patterns (#35), or a browser refusing it. Left
	 * alone, that visitor solves the same challenge again and again with
	 * nothing on the page to say why.
	 *
	 * Only when the pass cookie is absent. A pass that arrived and was refused
	 * -- expired, revoked, earned against a different provider -- is a
	 * different story, and the ordinary interstitial is the right answer.
	 *
	 * The marker is not signed, and does not need to be: it only changes the
	 * wording of a page the visitor is already being refused with, and a
	 * visitor who forges it misleads nobody but themselves.
	 *
	 * @param ChallengeRequiredException $outcome The challenge.
	 * @param Request                    $request The request being challenged.
	 */
	public static function pass_went_missing( ChallengeRequiredException $outcome, Request $request ): bool {
		$marker = $request->cookies->get( self::SOLVED_MARKER );

		if ( ! is_string( $marker ) || ! ctype_digit( $marker ) ) {
			return false;
		}

		// The marker's own lifetime, checked again: a browser that ignores
		// Max-Age must not see the hint on every challenge for ever after.
		$age = time() - (int) $marker;

		if ( $age < 0 || $age > self::SOLVED_MARKER_TTL ) {
			return false;
		}

		$name = (string) ( $outcome->getRenderContext()['cookie_name'] ?? '' );

		return '' !== $name && ! $request->cookies->has( $name );
	}

	/**
	 * The interstitial, with a line explaining the missing pass.
	 *
	 * Placed just above the form, where the visitor looks first; prepended to
	 * the body if a provider's page has no form this can find. The text is
	 * fixed and escaped, and the response carries the full no-store set like
	 * every interstitial, so nothing about it can be cached for anybody else.
	 *
	 * @param string $body The rendered interstitial.
	 */
	public static function with_missing_pass_notice( string $body ): string {
		$text = self::can_translate()
			? __( 'You completed this check a moment ago, but the verification cookie did not come back with this request. Your browser may be blocking cookies for this site, or the site\'s host may not be passing the cookie on. If this keeps happening, allow cookies for this site or contact the site owner.', 'basic-firewall' )
			: 'You completed this check a moment ago, but the verification cookie did not come back with this request. Your browser may be blocking cookies for this site, or the site\'s host may not be passing the cookie on. If this keeps happening, allow cookies for this site or contact the site owner.';

		$notice = '<p class="bfw-missing-pass" role="alert" style="color:#b42318">' . self::escape( $text ) . '</p>' . "\n";
		$form   = strpos( $body, '<form' );

		if ( false !== $form ) {
			return substr( $body, 0, $form ) . $notice . substr( $body, $form );
		}

		return $notice . $body;
	}

	/**
	 * The temporary refusal given when a verdict cannot be answered properly.
	 *
	 * A challenge that cannot be put in front of the visitor still does not
	 * serve them the page. The rule decided they must prove something first,
	 * and nothing can be proven -- so they get a temporary refusal saying so,
	 * rather than the page the rule was written to stand in front of.
	 *
	 * @return array{status: int, headers: array<string, string>, body: string, warning: string|null}
	 */
	public static function refusal_response(): array {
		$title = self::can_translate() ? __( 'Verification required', 'basic-firewall' ) : 'Verification required';
		$text  = self::can_translate()
			? __( 'This request needs a verification step that could not be shown. Please try again shortly.', 'basic-firewall' )
			: 'This request needs a verification step that could not be shown. Please try again shortly.';

		return array(
			'status'  => 503,
			'headers' => self::page_headers() + array( 'Retry-After' => '60' ),
			'body'    => self::document( $title, self::escape( $text ) ),
			'warning' => null,
		);
	}

	/**
	 * A challenge was solved: set the pass cookie and send the visitor on.
	 *
	 * Needs WordPress, for the compile record that names the cookie and for
	 * `is_ssl()`. The wp-config.php bootstrap therefore never answers this
	 * outcome itself; it leaves it for the runner, which is safe because a
	 * solution is a POST to the challenge path and no page cache serves a POST.
	 *
	 * @param ChallengeSolvedException $outcome The solved challenge.
	 * @param Request|null             $request The submission.
	 */
	private function send_solved( ChallengeSolvedException $outcome, ?Request $request ): void {
		$cookies = self::solved_cookies( $outcome->getToken(), Plugin::instance()->compiled()->pass_cookie(), is_ssl() );

		foreach ( $cookies as $cookie ) {
			setcookie( $cookie['name'], $cookie['value'], $cookie['options'] );
		}

		$this->emit( self::solved_http_response( $outcome, $request ) );
	}

	/**
	 * The cookies a solved challenge sets: the pass, and a short-lived marker.
	 *
	 * The name is the one the compiled file gives the library, read from the
	 * compile record rather than from settings: the library looks for the pass
	 * under the compiled name, and a cookie set under any other -- the stored
	 * `bfw_pass` on Pantheon, say, where the compiled name is
	 * `STYXKEY_bfw_pass` -- is a pass nobody ever reads (#35).
	 *
	 * @param string $token  The pass token.
	 * @param string $name   The pass cookie's name.
	 * @param bool   $secure Whether the request arrived over HTTPS.
	 *
	 * @return list<array{name: string, value: string, options: array<string, mixed>}>
	 */
	public static function solved_cookies( string $token, string $name, bool $secure ): array {
		return array(
			array(
				'name'    => $name,
				'value'   => $token,
				'options' => array(
					'expires'  => 0,
					'path'     => '/',

					/*
					 * HttpOnly: the token is presented by the browser on the
					 * next request and nothing on the page needs to read it,
					 * so there is no reason for script to be able to.
					 * SameSite=Lax so an ordinary top-level navigation back to
					 * the site still carries it, while a cross-site POST does
					 * not.
					 */
					'httponly' => true,
					'secure'   => $secure,
					'samesite' => 'Lax',
				),
			),

			// The marker: when it was solved, so a re-challenge moments later
			// can say the pass went missing instead of silently asking again.
			array(
				'name'    => self::SOLVED_MARKER,
				'value'   => (string) time(),
				'options' => array(
					'expires'  => time() + self::SOLVED_MARKER_TTL,
					'path'     => '/',
					'httponly' => true,
					'secure'   => $secure,
					'samesite' => 'Lax',
				),
			),
		);
	}

	/**
	 * The response to a solved challenge: its JSON, or its redirect.
	 *
	 * No-store on both. The JSON carries this visitor's pass token, and a
	 * redirect cached against the challenge path would send the next solver
	 * wherever the first was going.
	 *
	 * @param ChallengeSolvedException $outcome The solved challenge.
	 * @param Request|null             $request The submission.
	 *
	 * @return array{status: int, headers: array<string, string>, body: string, warning: string|null}
	 */
	public static function solved_http_response( ChallengeSolvedException $outcome, ?Request $request ): array {
		$solved = self::solved_response( $outcome, $request );

		if ( 'json' !== $solved['format'] ) {
			return array(
				'status'  => 302,
				'headers' => array( 'Location' => $solved['redirect'] ) + self::no_store_headers(),
				'body'    => '',
				'warning' => null,
			);
		}

		$json = (string) json_encode( // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- composed without WordPress so it can be tested; the flags keep it inert if anything renders it as HTML.
			array(
				'token'    => $outcome->getToken(),
				'redirect' => $solved['redirect'],
			),
			JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES
		);

		return array(
			'status'  => 200,
			'headers' => array( 'Content-Type' => 'application/json; charset=utf-8' ) + self::no_store_headers(),
			'body'    => $json,
			'warning' => null,
		);
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
	 * treated as untrusted: only a site-relative path is followed, see
	 * safe_redirect(). Without this the challenge page is an open redirect,
	 * and an open redirect on the one page every blocked visitor is sent to
	 * is worth more to an attacker than most.
	 *
	 * @param ChallengeSolvedException $outcome The solved challenge.
	 * @param Request|null             $request The submission.
	 *
	 * @return array{format: string, redirect: string}
	 */
	public static function solved_response( ChallengeSolvedException $outcome, ?Request $request ): array {
		$redirect = self::safe_redirect( $outcome->getRedirect() );

		$wants_json = null !== $request
			&& false !== stripos( (string) $request->headers->get( 'Accept', '' ), 'application/json' );

		return array(
			'format'   => $wants_json ? 'json' : 'redirect',
			'redirect' => $redirect,
		);
	}

	/**
	 * Reduce a posted destination to a path on this site, or to `/`.
	 *
	 * Checking that the value starts with `/` and not `//` is not enough,
	 * because browsers are more forgiving than that check. They strip tabs
	 * and newlines anywhere in a URL, so `/<tab>/evil.example` is followed
	 * as `//evil.example`; they read `\` as `/`, so `/\evil.example` is
	 * too. So the value is refused outright if it holds any control
	 * character or whitespace, backslashes are treated as the slashes a
	 * browser will make of them before the `//` check, and the percent-decoded
	 * path is held to the same rules, in case anything between here and the
	 * browser decodes it. What survives is rebuilt from its path and query
	 * alone, so no scheme, host, credentials or fragment can ride along.
	 *
	 * @param string $target The destination the challenge form posted.
	 *
	 * @return string A site-relative path, with its query string if it had one.
	 */
	public static function safe_redirect( string $target ): string {
		if ( '' === $target || 1 === preg_match( '/[\x00-\x20\x7f]/', $target ) ) {
			return '/';
		}

		$normalised = str_replace( '\\', '/', $target );

		if ( '/' !== $normalised[0] || 0 === strpos( $normalised, '//' ) ) {
			return '/';
		}

		// Not wp_parse_url(): this also runs from wp-config.php, before WordPress has loaded.
		$parts = parse_url( $normalised ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url

		if ( ! is_array( $parts ) || isset( $parts['scheme'] ) || isset( $parts['host'] ) || isset( $parts['user'] ) || isset( $parts['pass'] ) || isset( $parts['port'] ) ) {
			return '/';
		}

		$path = (string) ( $parts['path'] ?? '' );
		// Decoded only to check it: the destination is sent as it arrived.
		$decoded = str_replace( '\\', '/', rawurldecode( $path ) );

		if ( '' === $path || '/' !== $path[0] || 0 === strpos( $decoded, '//' ) || 1 === preg_match( '/[\x00-\x1f\x7f]/', $decoded ) ) {
			return '/';
		}

		return isset( $parts['query'] ) && '' !== $parts['query'] ? $path . '?' . $parts['query'] : $path;
	}

	/**
	 * Whether a string can be translated without WordPress complaining.
	 *
	 * Not merely whether __() exists. On the wp-config.php path it does not;
	 * on the mu-plugin path it does, but a refusal there is answered at
	 * `muplugins_loaded`, before `init`, and translating then makes WordPress
	 * 6.7 and later report "translation loading was triggered too early" on
	 * every refused request. English is what either path had before a
	 * translation could load, so it is what they get.
	 */
	private static function can_translate(): bool {
		return function_exists( '__' ) && function_exists( 'did_action' ) && did_action( 'init' ) > 0;
	}

	/**
	 * The headers that keep a firewall response out of every cache.
	 *
	 * The library's own set (kanopi/firewall#418), so the plugin and the
	 * library cannot drift apart on what keeps a response out of a cache.
	 * `no-store` alone was not enough: Pantheon's Fastly-based edge caches a
	 * response carrying only that, and a cached challenge or refusal is
	 * served to every visitor after the first -- #34, where a page reached
	 * the edge with WordPress's `max-age=3600`.
	 *
	 * No fallback of its own: the plugin requires ^2.34.1, the release that
	 * added the class, so every copy of the library this class can be loaded
	 * beside has it. The bootstrap, which must answer even when the library
	 * is not the copy it expected, keeps one; see
	 * basic_firewall_no_store_headers().
	 *
	 * @return array<string, string>
	 */
	public static function no_store_headers(): array {
		return NoStore::HEADERS;
	}

	/**
	 * The headers common to every page the firewall answers with.
	 *
	 * Never cacheable: a page cache or a CDN that stored a 403 keyed only on
	 * the URL would serve it to everybody, turning one blocked client into an
	 * outage for the whole site -- and a stored interstitial hands every
	 * visitor the same single-use challenge.
	 *
	 * @return array<string, string>
	 */
	private static function page_headers(): array {
		return array( 'Content-Type' => 'text/html; charset=utf-8' )
			+ self::no_store_headers()
			+ array(
				'X-Content-Type-Options' => 'nosniff',
				'X-Robots-Tag'           => 'noindex, nofollow',
			);
	}

	/**
	 * Send a response and end the request.
	 *
	 * Every header replaces one of the same name already set. That matters
	 * most for `Cache-Control`: on the runner path WordPress or another plugin
	 * may have set a cacheable one before the verdict, and a cache reading the
	 * permissive one of two would store the refusal anyway.
	 *
	 * @param array{status: int, headers: array<string, string>, body: string, warning: string|null} $response The response.
	 */
	private function emit( array $response ): void {
		if ( null !== $response['warning'] ) {
			self::warn( $response['warning'] );
		}

		if ( ! headers_sent() ) {
			$this->status_header( $response['status'] );

			foreach ( $response['headers'] as $name => $value ) {
				// The status again with Location, which PHP would otherwise
				// turn into a 302 whatever the rule asked for.
				header( $name . ': ' . $value, true, 'Location' === $name ? $response['status'] : 0 );
			}
		}

		if ( '' !== $response['body'] ) {
			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- composed above: escaped documents, the library's interstitial markup, or JSON encoded to be inert as HTML.
			echo $response['body'];
		}

		$this->finish();
	}

	/**
	 * Record, at warning, why a verdict was answered with a refusal.
	 *
	 * The PHP error log, because this runs before WordPress on the
	 * wp-config.php path and the firewall's own logger is not reachable from
	 * here. A verdict answered with something other than what the rule asked
	 * for is worth finding afterwards, and it used to leave no trace at all.
	 *
	 * @param string $message What happened.
	 */
	private static function warn( string $message ): void {
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- no WordPress and no firewall logger on the early path; see above.
		error_log( 'Basic Firewall [warning]: ' . $message );
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
	private static function document( string $title, string $body ): string {
		$title = self::escape( $title );

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
	private static function escape( string $text ): string {
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
