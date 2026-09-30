<?php
/**
 * A verdict under the other library namespace, for EarlyPathExceptionModeTest.
 *
 * @package Kanopi\BasicFirewall
 */

// phpcs:disable WordPress.NamingConventions -- the library's class name, under the release build's prefix.

namespace Kanopi\BasicFirewall\Vendor\Kanopi\Firewall\Exception;

/**
 * A challenge as a release build's scoped library spells it, in a working
 * copy whose responder imports the unscoped name. A site running both copies
 * can hand one's exception to the other's responder, whose instanceof checks
 * then all miss -- the responder took it for a firewall failure and let the
 * request continue.
 */
class ChallengeRequiredException extends \RuntimeException {
}
