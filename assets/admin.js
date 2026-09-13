/**
 * Shows only the settings that apply to what is currently selected.
 *
 * Declarative, so no screen has to carry JavaScript of its own. Any element
 * marked up like this:
 *
 *     data-bfw-show-when="backend:database"
 *     data-bfw-show-when="connection_source:dsn|parameters"
 *
 * is shown only while the form control named by the first half currently holds
 * one of the values after the colon. It works on a table row, a section
 * wrapper, or anything else.
 *
 * Progressive on purpose: with JavaScript off, every element stays visible.
 * That is the behaviour this replaced, so nothing becomes unreachable — a
 * firewall whose storage settings cannot be configured without JavaScript would
 * be a worse problem than the one being solved.
 */
( function () {
	'use strict';

	var HIDDEN = 'bfw-hidden';

	/**
	 * Every element on the page that declares a condition.
	 *
	 * @return {Array} The conditional elements.
	 */
	function conditionals() {
		return Array.prototype.slice.call(
			document.querySelectorAll( '[data-bfw-show-when]' )
		);
	}

	/**
	 * The control a condition depends on.
	 *
	 * Scoped to the same form, so two screens sharing a field name cannot read
	 * each other's state.
	 *
	 * @param {Element} element The conditional element.
	 * @param {string}  name    The control's name attribute.
	 *
	 * @return {Element|null} The control, or null.
	 */
	function controlFor( element, name ) {
		var form = element.closest( 'form' ) || document;

		return form.querySelector( '[name="' + name + '"]' );
	}

	/**
	 * Apply one element's condition.
	 *
	 * @param {Element} element The conditional element.
	 */
	function apply( element ) {
		var condition = element.getAttribute( 'data-bfw-show-when' ) || '';
		var parts     = condition.split( ':' );

		if ( parts.length < 2 ) {
			return;
		}

		var control = controlFor( element, parts[ 0 ] );

		if ( ! control ) {
			return;
		}

		var wanted  = parts[ 1 ].split( '|' );
		var current = control.type === 'checkbox' ? ( control.checked ? '1' : '' ) : control.value;

		element.classList.toggle( HIDDEN, wanted.indexOf( current ) === -1 );
	}

	/**
	 * Re-evaluate everything.
	 *
	 * Every element, not just the ones depending on the control that changed:
	 * conditions nest, and a section becoming visible can reveal a control that
	 * another element depends on.
	 */
	function applyAll() {
		conditionals().forEach( apply );
	}

	document.addEventListener( 'DOMContentLoaded', function () {
		if ( ! conditionals().length ) {
			return;
		}

		applyAll();

		document.addEventListener( 'change', function ( event ) {
			if ( event.target && event.target.name ) {
				applyAll();
			}
		} );
	} );
}() );
