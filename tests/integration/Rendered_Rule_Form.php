<?php
/**
 * Renders a settings screen and posts back what it rendered.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Admin\Screen;
use Kanopi\BasicFirewall\Admin\Screen\Rule_Edit_Screen;

/**
 * The round trip a browser makes, for tests of what a screen stores.
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
		return $this->rendered_screen_fields( new Rule_Edit_Screen(), array( 'rule' => $id ) );
	}

	/**
	 * Post back exactly what the edit screen rendered.
	 *
	 * @param string                $id      The rule being edited.
	 * @param array<string, string> $changes Controls to change or add before posting, as a person would.
	 *
	 * @return bool Whether the screen saved it and redirected.
	 */
	protected function save_as_rendered( string $id, array $changes = array() ): bool {
		return $this->save_screen_as_rendered( new Rule_Edit_Screen(), array( 'rule' => $id ), $changes );
	}

	/**
	 * Render any settings screen and read back what its form would post.
	 *
	 * Every screen that saves a whole section of the document needs this
	 * test, not only the rule screen: a field it does not render is a stored
	 * value its next save replaces with whatever the handler defaults to.
	 *
	 * @param Screen               $screen The screen.
	 * @param array<string, mixed> $query  The query string it is rendered with.
	 *
	 * @return array<string, string> Control names to the values they were rendered with.
	 */
	protected function rendered_screen_fields( Screen $screen, array $query = array() ): array {
		$this->as_administrator();

		$_GET  = $query;
		$_POST = array();

		ob_start();
		$screen->render();
		$html = (string) ob_get_clean();

		$this->rendered_html = $html;

		$document = new \DOMDocument();
		libxml_use_internal_errors( true );
		$document->loadHTML( '<?xml encoding="utf-8"?>' . $html );
		libxml_clear_errors();

		$xpath  = new \DOMXPath( $document );
		$form   = $xpath->query( '//form[.//input[@name="basic_firewall_nonce"]]' )->item( 0 );
		$fields = array();

		$this->assertNotNull( $form, 'The screen rendered no form.' );

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
	 * Post back exactly what a settings screen rendered.
	 *
	 * @param Screen                $screen  The screen.
	 * @param array<string, mixed>  $query   The query string it is rendered and posted with.
	 * @param array<string, string> $changes Controls to change or add before posting, as a person would.
	 *
	 * @return bool Whether the screen saved it and redirected.
	 */
	protected function save_screen_as_rendered( Screen $screen, array $query = array(), array $changes = array() ): bool {
		$fields = array_merge( $this->rendered_screen_fields( $screen, $query ), $changes );

		// The form's own names, nested the way PHP nests a real submission.
		parse_str( http_build_query( $fields ), $posted );

		$_GET = $query;

		// Slashed, as WordPress leaves every request's $_POST.
		$_POST = wp_slash( $posted );

		add_filter(
			'wp_redirect',
			static function (): void {
				throw new \RuntimeException( 'redirected' );
			}
		);

		try {
			$screen->handle();
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
