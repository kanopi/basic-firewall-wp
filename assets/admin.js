/**
 * Shows only the settings that apply to what is currently selected.
 *
 * Declarative, so no screen has to carry JavaScript of its own. Any element
 * marked up like this:
 *
 *     data-bfw-show-when="backend:database"
 *     data-bfw-show-when="connection_source:dsn|parameters"
 *     data-bfw-show-when="operator:!regex"
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

		/*
		 * A leading `!` inverts the test, so an element can be shown for every
		 * value *except* the ones listed. Added for the case-sensitivity box on
		 * a condition row, which applies to every operator but `regex` -- and
		 * listing the other twelve to say "not that one" is a list that goes
		 * stale the moment an operator is added.
		 */
		var values  = parts[ 1 ];
		var invert  = 0 === values.indexOf( '!' );
		var wanted  = ( invert ? values.slice( 1 ) : values ).split( '|' );
		var current = control.type === 'checkbox' ? ( control.checked ? '1' : '' ) : control.value;
		var matched = -1 !== wanted.indexOf( current );

		element.classList.toggle( HIDDEN, invert ? matched : ! matched );
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

/**
 * "Add" and "Remove", for any repeatable block of fields.
 *
 * Generic on purpose. Two screens grew the same need -- referenced lists on a
 * rule, log handlers on the logging screen -- and the second one was about to
 * be a copy of the first with different selectors.
 *
 * A container declares its field name:
 *
 *     <div data-bfw-repeatable="handlers"> … </div>
 *     <button data-bfw-add="handlers">
 *
 * and each repeated block inside it is marked `data-bfw-item`. Field names are
 * renumbered on clone, which is what keeps `handlers[0][type]` from posting
 * over `handlers[1][type]`.
 *
 * Progressive in the same way the rest of this file is. With JavaScript off
 * every screen still renders one blank block, so a thing can still be added --
 * one per save rather than several at once, which is slower and not broken.
 *
 * Removal empties the block rather than deleting it, because an emptied block
 * is already what every validator here treats as "gone". The markup and the
 * saved state therefore agree without the two having to be kept in step.
 */
( function () {
	'use strict';

	/**
	 * Point every indexed reference in a block at a new position.
	 *
	 * Handles both shapes in use: a nested `settings[sources][0][url]` and a
	 * top-level `handlers[0][type]`.
	 *
	 * @param {Element} item  The cloned block.
	 * @param {string}  name  The repeatable's field name.
	 * @param {number}  index Its new position.
	 */
	function renumber( item, name, index ) {
		var pattern = new RegExp( '(^|\\[)' + name + '(\\]?)\\[\\d+\\]' );
		var replace = '$1' + name + '$2[' + index + ']';

		Array.prototype.forEach.call(
			item.querySelectorAll( '[name]' ),
			function ( field ) {
				field.name = field.name.replace( pattern, replace );
			}
		);

		/*
		 * The conditions too. A row shown only while this block's own select
		 * holds a given value names that select by its indexed field name, so a
		 * clone that kept the original index would follow the block it was
		 * cloned from rather than itself.
		 */
		Array.prototype.forEach.call(
			item.querySelectorAll( '[data-bfw-show-when]' ),
			function ( element ) {
				element.setAttribute(
					'data-bfw-show-when',
					element.getAttribute( 'data-bfw-show-when' ).replace( pattern, replace )
				);
			}
		);
	}

	/**
	 * Empty every field in a block.
	 *
	 * @param {Element} item The block.
	 */
	function clear( item ) {
		Array.prototype.forEach.call(
			item.querySelectorAll( 'input, textarea, select' ),
			function ( field ) {
				if ( 'checkbox' === field.type || 'radio' === field.type ) {
					field.checked = false;
					return;
				}

				if ( 'SELECT' === field.tagName ) {
					field.selectedIndex = 0;
					return;
				}

				field.value = '';
			}
		);
	}

	document.addEventListener( 'click', function ( event ) {
		var button = event.target.closest( '[data-bfw-add], [data-bfw-remove]' );

		if ( ! button ) {
			return;
		}

		event.preventDefault();

		if ( button.hasAttribute( 'data-bfw-remove' ) ) {
			var item = button.closest( '[data-bfw-item]' );

			if ( item ) {
				clear( item );
				item.hidden = true;
			}

			return;
		}

		var name = button.getAttribute( 'data-bfw-add' );
		var container = document.querySelector( '[data-bfw-repeatable="' + name + '"]' );

		if ( ! container ) {
			return;
		}

		var items = container.querySelectorAll( '[data-bfw-item]' );
		var last = items[ items.length - 1 ];

		if ( ! last ) {
			return;
		}

		var fresh = last.cloneNode( true );

		/*
		 * Before clearing: a cloned block may carry an initialised editor, which
		 * is two elements rather than one and would otherwise show the text of
		 * the block it was copied from while posting nothing.
		 */
		if ( window.basicFirewallEditors ) {
			window.basicFirewallEditors.reset( fresh );
		}

		clear( fresh );
		renumber( fresh, name, items.length );
		fresh.hidden = false;
		container.appendChild( fresh );

		// After it is in the document: CodeMirror measures on initialise and
		// gets it wrong for an element that is not laid out yet.
		if ( window.basicFirewallEditors ) {
			window.basicFirewallEditors.attach( fresh );
		}

		// The conditions in the clone have to be evaluated before it is shown,
		// or it appears with every type's fields at once.
		document.dispatchEvent( new Event( 'change', { bubbles: true } ) );

		var first = fresh.querySelector( 'select, input[type="text"]' );

		if ( first ) {
			first.focus();
		}
	} );
}() );

/**
 * Turns the YAML fields into CodeMirror, using the copy WordPress already ships.
 *
 * `wp_enqueue_code_editor()` has loaded the library and handed its settings over
 * in `window.basicFirewallEditor`; when the administrator has syntax
 * highlighting switched off in their profile, nothing is handed over and every
 * field stays the plain textarea they asked for. That is the whole fallback, and
 * it is the same one WordPress uses for its own file editors.
 */
( function () {
	'use strict';

	/**
	 * Whether the editor is available at all.
	 *
	 * @return {boolean} True when CodeMirror and its settings are both present.
	 */
	function available() {
		return !! ( window.wp && window.wp.codeEditor && window.basicFirewallEditor );
	}

	/**
	 * Attach the editor to one textarea, once.
	 *
	 * @param {Element} field The textarea.
	 */
	function attach( field ) {
		if ( field.dataset.bfwYamlReady ) {
			return;
		}

		field.dataset.bfwYamlReady = '1';

		var editor = window.wp.codeEditor.initialize( field, window.basicFirewallEditor );

		/*
		 * CodeMirror keeps its content in its own document and only writes it
		 * back to the textarea when told to. Without this the form posts
		 * whatever the textarea held when the page loaded, so every edit made
		 * in the editor is discarded on save -- which for the advanced
		 * configuration field means the change looks accepted while the
		 * firewall goes on running the old one.
		 */
		if ( editor && editor.codemirror ) {
			editor.codemirror.on( 'change', function ( instance ) {
				instance.save();
			} );
		}
	}

	/**
	 * Attach to every marked field that has not got one yet.
	 *
	 * Exposed because the repeatable blocks need to call it after adding a
	 * card, and because a card's editor has to be discarded and rebuilt when
	 * the card was cloned from one that already had it.
	 *
	 * @param {Element} [scope] Restrict to this subtree.
	 */
	function attachAll( scope ) {
		if ( ! available() ) {
			return;
		}

		var root = scope || document;

		Array.prototype.forEach.call(
			root.querySelectorAll( 'textarea[data-bfw-yaml]' ),
			attach
		);
	}

	/**
	 * Strip a cloned editor, leaving a plain textarea to be initialised.
	 *
	 * A clone carries both halves of an initialised field: the rendered
	 * CodeMirror element, and the textarea it hid. Only removing the first and
	 * clearing the flag makes the clone initialisable as itself -- otherwise
	 * the new card shows the text of the one it was copied from and posts
	 * nothing.
	 *
	 * @param {Element} scope The cloned block.
	 */
	function reset( scope ) {
		Array.prototype.forEach.call( scope.querySelectorAll( '.CodeMirror' ), function ( element ) {
			element.parentNode.removeChild( element );
		} );

		Array.prototype.forEach.call( scope.querySelectorAll( 'textarea[data-bfw-yaml]' ), function ( field ) {
			delete field.dataset.bfwYamlReady;
			field.style.display = '';
			field.value = '';
		} );
	}

	window.basicFirewallEditors = {
		attach: attachAll,
		reset: reset,
	};

	document.addEventListener( 'DOMContentLoaded', function () {
		attachAll();
	} );
}() );
