<?php
/**
 * Pinned versions of the vendored library.
 *
 * Generated from composer.lock by build/build-zip.sh, and committed on purpose.
 *
 * This is the only way a scoped release build can report its own library version.
 * PHP-Scoper leaves Composer's classmap key for InstalledVersions unscoped while
 * rewriting the file it points at to declare the prefixed class, so in a scoped
 * build neither name resolves and Composer's runtime API answers nothing.
 *
 * Committed rather than generated-only so a checkout is analysable and the pinned
 * version is visible in git beside composer.lock. The build overwrites it.
 *
 * @package Kanopi\BasicFirewall
 */

return array(
	'kanopi/crs-engine' => '1.0.0',
	'kanopi/firewall'   => 'v2.26.0',
);
