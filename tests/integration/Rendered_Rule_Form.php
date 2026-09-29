<?php
/**
 * Renders the rule edit screen and posts back what it rendered.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Admin\Screen\Rule_Edit_Screen;

/**
 * The round trip a browser makes, for tests of what the rule screen stores.
 *
 * The edit screen is rendered, every control on its form is read back out of
 * the markup with the value it was rendered with, and that is what is posted
 * to the handler. So a field the screen forgets to render is a field the test
 * forgets to post, and a value the screen renders wrongly is the value that is
 * saved.
 */
trait Rendered_Rule_Form {

	/**
	 * The last page the screen rendered.
	 *
	 * @var string
	 */
	protected string $rendered_html = '';

	/**
	 * Render the edit screen and read back what its form would post.
	 *
	 * @param string $id The rule being edited.
	 *
	 * @return array<string, string> Control names to the values they were rendered with.
	 */
	protected function rendered_fields( string $id ): array {
		$this->as_administrator();

		$_GET  = array( 'rule' => $id );
		$_POST = array();

		ob_start();
		( new Rule_Edit_Screen() )->render();
		$html = (string) ob_get_clean();

		$this->rendered_html = $html;

		$document = new \DOMDocument();
		libxml_use_internal_errors( true );
		$document->loadHTML( '<?xml encoding="utf-8"?>' . $html );
		libxml_clear_errors();

		$xpath  = new \DOMXPath( $document );
		$form   = $xpath->query( '//form[.//input[@name="basic_firewall_nonce"]]' )->item( 0 );
		$fields = array();

		$this->assertNotNull( $form, 'The edit screen rendered no form.' );

		foreach ( $xpath->query( './/input[@name] | .//select[@name] | .//textarea[@name]', $form ) as $control ) {
			if ( ! $control instanceof \DOMElement ) {
				continue;
			}

			$name = $control->getAttribute( 'name' );
			$tag  = strtolower( $control->nodeName ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- a DOM property.

			if ( 'select' === $tag ) {
				$selected = $xpath->query( './/option[@selected]', $control )->item( 0 ) ?? $xpath->query( './/option', $control )->item( 0 );

				$fields[ $name ] = $selected instanceof \DOMElement ? $selected->getAttribute( 'value' ) : '';

				continue;
			}

			if ( 'textarea' === $tag ) {
				$fields[ $name ] = $control->textContent; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- a DOM property.

				continue;
			}

			$kind = strtolower( $control->getAttribute( 'type' ) );

			if ( in_array( $kind, array( 'submit', 'button' ), true ) ) {
				continue;
			}

			if ( in_array( $kind, array( 'checkbox', 'radio' ), true ) && ! $control->hasAttribute( 'checked' ) ) {
				continue;
			}

			$fields[ $name ] = $control->getAttribute( 'value' );
		}

		return $fields;
	}

	/**
	 * Post back exactly what the screen rendered.
	 *
	 * @param string                $id      The rule being edited.
	 * @param array<string, string> $changes Controls to change or add before posting, as a person would.
	 *
	 * @return bool Whether the screen saved it and redirected.
	 */
	protected function save_as_rendered( string $id, array $changes = array() ): bool {
		$fields = array_merge( $this->rendered_fields( $id ), $changes );

		// The form's own names, nested the way PHP nests a real submission.
		parse_str( http_build_query( $fields ), $posted );

		$_GET = array( 'rule' => $id );

		// Slashed, as WordPress leaves every request's $_POST.
		$_POST = wp_slash( $posted );

		add_filter(
			'wp_redirect',
			static function (): void {
				throw new \RuntimeException( 'redirected' );
			}
		);

		try {
			( new Rule_Edit_Screen() )->handle();
		} catch ( \RuntimeException $e ) {
			return 'redirected' === $e->getMessage();
		}

		return false;
	}

	/**
	 * Act as an administrator, who holds the plugin's capability.
	 */
	protected function as_administrator(): void {
		$admins = get_users(
			array(
				'role'   => 'administrator',
				'number' => 1,
				'fields' => 'ID',
			)
		);

		if ( array() === $admins ) {
			$this->markTestSkipped( 'The site has no administrator to act as.' );
		}

		wp_set_current_user( (int) $admins[0] );
	}
}
