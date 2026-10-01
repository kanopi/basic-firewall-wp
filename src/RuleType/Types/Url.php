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
		return __( 'Matches the method, host, path, scheme, port, query parameters and how many were sent, posted fields, headers or cookies. The most flexible rule type.', 'basic-firewall' );
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
	 * `path`, `query`, `scheme`, `port` and `query_count`, and the `query`,
	 * `query_count`, `post`, `header` and `cookie` families; any other name
	 * resolves to nothing, and a condition comparing against nothing never
	 * matches -- or, negated, always does, which on a block rule is every
	 * visitor.
	 *
	 * `query_count` is offered both ways (kanopi/firewall 2.36.0): on its own
	 * it counts every parameter the client sent, and with a name alongside it
	 * counts the values of that one parameter. The rule screen shows a single
	 * entry with an optional name, because the select cannot hold the same
	 * key twice, and the description says what a blank name means.
	 */
	protected function variable_options(): array {
		return array(
			'method'      => __( 'HTTP method, such as GET or POST', 'basic-firewall' ),
			'path'        => __( 'Path, without the query string', 'basic-firewall' ),
			'host'        => __( 'Host name the request asked for', 'basic-firewall' ),
			'scheme'      => __( 'http or https', 'basic-firewall' ),
			'port'        => __( 'Port, compared as a number', 'basic-firewall' ),

			/*
			 * Counted from the raw query string, so f[0]=, f[]=, sparse or
			 * named keys, encoded brackets and a repeated f= all count the
			 * same -- which is what makes it usable against facet crawling,
			 * where `query.f` resolves to nothing once f is a list.
			 */
			'query_count' => __( 'How many values the client sent for the query parameter named alongside (f[0]=, f[]=, f=a&f=b and encoded brackets all count), or, with no name, how many parameters in all. Compared as a whole number; the name is case-sensitive.', 'basic-firewall' ),
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
		return array( 'header', 'cookie', 'query', 'query_count', 'post' );
	}

	/**
	 * {@inheritDoc}
	 *
	 * The port is the integer Symfony reads off the Host header, and a query
	 * count (kanopi/firewall 2.36.0) is an integer the library counts -- the
	 * bare `query_count` for every parameter, `query_count.<name>` for one.
	 * Everything else this type reads is text.
	 */
	protected function integer_variables(): array {
		return array( 'port', 'query_count', 'query_count.*' );
	}

	/**
	 * Operators that compare a number and never match anything else.
	 *
	 * In the screen's spelling, which is what validation sees.
	 *
	 * @var list<string>
	 */
	private const NUMERIC_OPERATORS = array( 'equals', 'not_equals', 'in', 'gt', 'gte', 'lt', 'lte' );

	/**
	 * Whether the library reads this variable as a query count.
	 *
	 * @param string $variable The library's variable name.
	 */
	private static function is_query_count( string $variable ): bool {
		return 'query_count' === $variable || 0 === strpos( $variable, 'query_count.' );
	}

	/**
	 * {@inheritDoc}
	 *
	 * A query count is a whole number, and "is equal to four" written as
	 * `four`, `4.0` or `3-5` compiles to a comparison that can never match --
	 * a rule that saves, reports itself active, and lets every crawler
	 * through. Refused here for every operator that compares the number, with
	 * each entry of "is one of" checked on its own.
	 *
	 * @param string $variable The library's variable name.
	 * @param string $operator The screen's operator.
	 * @param string $value    The value, trimmed.
	 */
	protected function value_problem( string $variable, string $operator, string $value ): ?string {
		if ( ! self::is_query_count( $variable ) || ! in_array( $operator, self::NUMERIC_OPERATORS, true ) ) {
			return null;
		}

		$entries = 'in' === $operator ? array_filter( array_map( 'trim', explode( ',', $value ) ), static fn ( string $entry ): bool => '' !== $entry ) : array( $value );

		foreach ( $entries as $entry ) {
			if ( 1 !== preg_match( '/^\d{1,9}$/', $entry ) ) {
				return sprintf(
					/* translators: 1: the variable, 2: the rejected value. */
					__( '%1$s is a count, compared as a whole number, and %2$s is not one. Write digits only, such as 3.', 'basic-firewall' ),
					$variable,
					$entry
				);
			}
		}

		return null;
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
	 * A query count is an integer too (kanopi/firewall 2.36.0), with the same
	 * strict comparison, so it is compiled the same way. For a count the
	 * greater-than and less-than operators are cast as well: the library
	 * compares those numerically and a numeric string would work, but one
	 * variable compiling to one type whatever the operator is easier to read
	 * in the compiled file and leaves nothing to PHP's comparison rules.
	 *
	 * @param array<string, mixed> $condition Stored condition.
	 *
	 * @return array<string, mixed>
	 */
	protected function compile_condition( array $condition ): array {
		$compiled = parent::compile_condition( $condition );
		$variable = (string) $compiled['variable'];

		if ( ! $this->is_integer_variable( $variable ) ) {
			return $compiled;
		}

		$numeric = self::is_query_count( $variable )
			? array( 'equals', 'not_equals', 'in', 'greater_than', 'greater_than_or_equal', 'less_than', 'less_than_or_equal' )
			: array( 'equals', 'not_equals', 'in' );

		if ( ! in_array( $compiled['operator'], $numeric, true ) ) {
			return $compiled;
		}

		$compiled['value'] = is_array( $compiled['value'] )
			? array_map( array( self::class, 'as_integer' ), $compiled['value'] )
			: self::as_integer( $compiled['value'] );

		return $compiled;
	}

	/**
	 * A port or a count as the integer the request holds.
	 *
	 * Anything that is not one is left as it was, so a referenced list's
	 * `{value}` placeholder still reaches the library to be substituted --
	 * as text, which is why an equality against a list on these variables is
	 * refused (see strict_list_comparisons()).
	 *
	 * @param mixed $value Compiled value.
	 *
	 * @return mixed
	 */
	private static function as_integer( $value ) {
		if ( is_string( $value ) && 1 === preg_match( '/^\s*(\d{1,9})\s*$/', $value, $matches ) ) {
			return (int) $matches[1];
		}

		return $value;
	}
}
