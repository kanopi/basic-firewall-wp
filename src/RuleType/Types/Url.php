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
 * Matches on the request itself: method, path, query, headers, cookies, body.
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
		return __( 'Matches the method, host, path, scheme, port, query string, POST body, headers or cookies. The most flexible rule type.', 'basic-firewall' );
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
	 */
	protected function variable_options(): array {
		return array(
			'method'       => __( 'HTTP method, such as GET or POST', 'basic-firewall' ),
			'path'         => __( 'Path, without the query string', 'basic-firewall' ),
			'uri'          => __( 'Path and query string together', 'basic-firewall' ),
			'host'         => __( 'Host name the request asked for', 'basic-firewall' ),
			'scheme'       => __( 'http or https', 'basic-firewall' ),
			'port'         => __( 'Port', 'basic-firewall' ),
			'query'        => __( 'Query string', 'basic-firewall' ),
			'body'         => __( 'Raw request body', 'basic-firewall' ),
			'content_type' => __( 'Content-Type header', 'basic-firewall' ),
			'referer'      => __( 'Referer header', 'basic-firewall' ),
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
		return array( 'header', 'cookie', 'query', 'post', 'server' );
	}
}
