<?php
/**
 * The request / URL rule type.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\RuleType\Types;

use Kanopi\BasicFirewall\RuleType\Condition_Rule_Type_Base;
use Kanopi\Firewall\Plugins\Url as LibraryUrl;

/**
 * Matches on the request itself: method, path, query, headers, cookies, posted fields.
 *
 * The workhorse. Most hand-written rules end up here.
 */
final class Url extends Condition_Rule_Type_Base {

	/**
	 * {@inheritDoc}
	 */
	public function id(): string {
		return 'url';
	}

	/**
	 * {@inheritDoc}
	 */
	public function label(): string {
		return __( 'Request / URL', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function description(): string {
		return __( 'Matches the method, host, path, scheme, port, query parameters, posted fields, headers or cookies. The most flexible rule type.', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function library_class(): string {
		return LibraryUrl::class;
	}

	/**
	 * {@inheritDoc}
	 */
	public function weight(): int {
		return -80;
	}

	/**
	 * {@inheritDoc}
	 *
	 * Only what the library's Url plugin resolves. It reads `method`, `host`,
	 * `path`, `query`, `scheme` and `port`, and the `query`, `post`, `header`
	 * and `cookie` families; any other name resolves to nothing, and a
	 * condition comparing against nothing never matches -- or, negated, always
	 * does, which on a block rule is every visitor.
	 */
	protected function variable_options(): array {
		return array(
			'method' => __( 'HTTP method, such as GET or POST', 'basic-firewall' ),
			'path'   => __( 'Path, without the query string', 'basic-firewall' ),
			'host'   => __( 'Host name the request asked for', 'basic-firewall' ),
			'scheme' => __( 'http or https', 'basic-firewall' ),
			'port'   => __( 'Port, compared as a number', 'basic-firewall' ),
		);
	}

	/**
	 * Old variable name to the library's.
	 *
	 * @var array<string, string>
	 */
	public const RENAMED_VARIABLES = array(
		'referer'      => 'header.referer',
		'content_type' => 'header.content-type',
	);

	/**
	 * {@inheritDoc}
	 *
	 * Both were offered as variables of their own and are headers to the
	 * library, which reads them as members of the `header` family. A rule on
	 * either resolved to nothing: "referer does not contain example.com"
	 * blocked every request on the site.
	 */
	protected function renamed_variables(): array {
		return self::RENAMED_VARIABLES;
	}

	/**
	 * {@inheritDoc}
	 *
	 * Offered, and never read by the library. None has an exact equivalent, so
	 * none is translated: a stored condition on one is kept and reported, and
	 * the explanation says what to write instead.
	 */
	protected function retired_variables(): array {
		return array(
			'uri'      => __( 'Use path for the path, and query for the query string, as two conditions.', 'basic-firewall' ),
			'body'     => __( 'Use a posted field by name, as post.fieldname; the raw body is not something the firewall can read.', 'basic-firewall' ),
			'server.*' => __( 'Server variables are not something the firewall can read. Use host, port or scheme, or a request header by name.', 'basic-firewall' ),
		);
	}

	/**
	 * {@inheritDoc}
	 */
	protected function variables_are_free_form(): bool {
		return true;
	}

	/**
	 * {@inheritDoc}
	 */
	protected function variable_prefixes(): array {
		return array( 'header', 'cookie', 'query', 'post' );
	}

	/**
	 * {@inheritDoc}
	 *
	 * The port reaches the library as the integer Symfony reads off the Host
	 * header, and `equals`, `is not equal to` and `is one of` compare strictly
	 * -- so `8443` as typed, a string like every form value, never equalled it,
	 * and "port is not equal to 443" matched every request, including the ones
	 * on 443. Compiled as a number, the way the ASN type compiles an
	 * autonomous system number.
	 *
	 * @param array<string, mixed> $condition Stored condition.
	 *
	 * @return array<string, mixed>
	 */
	protected function compile_condition( array $condition ): array {
		$compiled = parent::compile_condition( $condition );

		if ( 'port' !== $compiled['variable'] || ! in_array( $compiled['operator'], array( 'equals', 'not_equals', 'in' ), true ) ) {
			return $compiled;
		}

		$compiled['value'] = is_array( $compiled['value'] )
			? array_map( array( self::class, 'as_port' ), $compiled['value'] )
			: self::as_port( $compiled['value'] );

		return $compiled;
	}

	/**
	 * A port as the integer the request holds.
	 *
	 * Anything that is not one is left as it was, so a referenced list's
	 * `{value}` placeholder still reaches the library to be substituted.
	 *
	 * @param mixed $value Compiled value.
	 *
	 * @return mixed
	 */
	private static function as_port( $value ) {
		if ( is_string( $value ) && 1 === preg_match( '/^\s*(\d{1,5})\s*$/', $value, $matches ) ) {
			return (int) $matches[1];
		}

		return $value;
	}
}
