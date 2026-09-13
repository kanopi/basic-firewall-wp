#!/usr/bin/env bash
#
# Builds the release zip.
#
# The zip is the artefact that has to work on a host with no Composer, no shell
# and no build step, so everything Composer would have done happens here and the
# result is checked rather than assumed:
#
#   1. assemble the plugin and a production dependency tree in a scratch copy
#   2. scope BOTH the vendor tree and the plugin's own source
#   3. prove the scoped build actually resolves its classes
#   4. zip
#
# Step 3 is not optional. See DECISIONS.md section 0: an unscoped class name in a
# scoped build does not throw -- the library skips the plugin and carries on, so
# the firewall reports success and enforces nothing.
#
#   BFW_SKIP_SCOPING=1   build unscoped, for local testing only.

set -euo pipefail

PLUGIN_SLUG="basic-firewall"
PREFIX="Kanopi\\BasicFirewall\\Vendor"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="${ROOT}/build"
SCRATCH="${BUILD}/scratch"
SCOPED="${BUILD}/scoped"
STAGE="${BUILD}/stage/${PLUGIN_SLUG}"
DIST="${BUILD}/dist"

VERSION="$(grep -m1 '^ \* Version:' "${ROOT}/${PLUGIN_SLUG}.php" | awk '{print $3}')"

# Everything that goes in the zip. PHP here is scoped; the rest is copied as-is.
# Scoped: references the vendor tree, so its `use` statements must be rewritten.
SOURCE_SCOPED=( src )
# Copied verbatim: references no vendored class, and scoping bootstrap.php would
# move basic_firewall_evaluate() out of the global namespace, which is the
# function every wp-config.php calls by name.
SOURCE_VERBATIM=( basic-firewall.php loader.php bootstrap.php uninstall.php )
SOURCE_DATA=( assets languages mu-plugin LICENSE README.md readme.txt DECISIONS.md )

echo "==> Building ${PLUGIN_SLUG} ${VERSION}"

rm -rf "${SCRATCH}" "${SCOPED}" "${BUILD}/stage" "${DIST}"
mkdir -p "${SCRATCH}" "${STAGE}" "${DIST}"

# ---------------------------------------------------------------------------
# 1. Assemble a scratch copy of the plugin with a production dependency tree.
#
# In a scratch directory rather than in place, because php-scoper is a dev
# dependency and `composer install --no-dev` in the working directory would
# delete the very tool the next step needs. It also means a build never leaves
# the working copy without its dev dependencies.
# ---------------------------------------------------------------------------
echo "==> Assembling a production tree"

cp "${ROOT}/composer.json" "${ROOT}/composer.lock" "${SCRATCH}/"

for path in "${SOURCE_SCOPED[@]}" "${SOURCE_VERBATIM[@]}"; do
  cp -R "${ROOT}/${path}" "${SCRATCH}/"
done

composer install \
  --no-dev \
  --optimize-autoloader \
  --classmap-authoritative \
  --no-interaction \
  --no-progress \
  --working-dir="${SCRATCH}"

echo "==> Recording the pinned library version"
php -r '
$lock = json_decode(file_get_contents($argv[1] . "/composer.lock"), true);
$pinned = [];
foreach ($lock["packages"] as $package) {
    if (in_array($package["name"], ["kanopi/firewall", "kanopi/crs-engine"], true)) {
        $pinned[$package["name"]] = $package["version"];
    }
}
if (!isset($pinned["kanopi/firewall"])) {
    fwrite(STDERR, "kanopi/firewall is not in composer.lock\n");
    exit(1);
}
// Aligned to the longest key, which is what the coding standard wants -- the
// file is committed, so it has to pass the same linter as everything else.
$width = 0;
foreach (array_keys($pinned) as $name) {
    $width = max($width, strlen($name) + 2);
}
$lines = "";
foreach ($pinned as $name => $version) {
    $lines .= sprintf("\t%-" . $width . "s => %s,\n", "\x27" . $name . "\x27", "\x27" . $version . "\x27");
}
file_put_contents(
    $argv[2] . "/vendor-version.php",
    "<?php\n/**\n * Pinned versions of the vendored library.\n *\n * Generated from composer.lock by build/build-zip.sh, and committed on purpose.\n *\n * This is the only way a scoped release build can report its own library version.\n * PHP-Scoper leaves Composer\x27s classmap key for InstalledVersions unscoped while\n * rewriting the file it points at to declare the prefixed class, so in a scoped\n * build neither name resolves and Composer\x27s runtime API answers nothing.\n *\n * Committed rather than generated-only so a checkout is analysable and the pinned\n * version is visible in git beside composer.lock. The build overwrites it.\n *\n * @package Kanopi\\BasicFirewall\n */\n\nreturn array(\n" . $lines . ");\n"
);
printf("    kanopi/firewall %s\n", $pinned["kanopi/firewall"]);
' "${ROOT}" "${BUILD}"

# Refresh the committed copy at the plugin root as well, so that a checkout
# always carries the version the lock file pins. It is read by Library_Loader in
# a scoped build, where Composer's runtime API cannot answer.
cp "${BUILD}/vendor-version.php" "${ROOT}/vendor-version.php"

# ---------------------------------------------------------------------------
# 2. Scope.
# ---------------------------------------------------------------------------
if [ "${BFW_SKIP_SCOPING:-0}" = "1" ]; then
  echo "==> SKIPPING scoping (BFW_SKIP_SCOPING=1)"
  echo "    This build is NOT collision-safe. For local testing only."

  cp -R "${SCRATCH}/vendor" "${STAGE}/vendor"

  for path in "${SOURCE_SCOPED[@]}" "${SOURCE_VERBATIM[@]}"; do
    cp -R "${ROOT}/${path}" "${STAGE}/"
  done
else
  echo "==> Checking the scoper patcher"
  php "${BUILD}/patcher-test.php"

  echo "==> Scoping under ${PREFIX}"

  test -x "${ROOT}/vendor/bin/php-scoper" || {
    echo "php-scoper is not installed. Run 'composer install' first." >&2
    exit 1
  }

  # Scoping parses the whole tree into an AST at once, which exceeds a default
  # 128M limit partway through and fails with a stack trace rather than a
  # useful message.
  php -d memory_limit=-1 "${ROOT}/vendor/bin/php-scoper" add-prefix \
    --config="${ROOT}/scoper.inc.php" \
    --output-dir="${SCOPED}" \
    --force \
    --no-interaction \
    --working-dir="${SCRATCH}"

  cp -R "${SCOPED}/vendor" "${STAGE}/vendor"

  # The plugin's own source, as rewritten by the scoper: its namespace is
  # unchanged, but every reference into the vendor tree now points at the
  # prefixed name.
  for path in "${SOURCE_SCOPED[@]}"; do
    cp -R "${SCOPED}/${path}" "${STAGE}/"
  done

  for path in "${SOURCE_VERBATIM[@]}"; do
    cp -R "${ROOT}/${path}" "${STAGE}/"
  done

  # composer/installers is an install-time Composer plugin. It does nothing at
  # runtime, and leaving it in breaks the dump below: Composer finds a scoped
  # Composer\Plugin\PluginInterface and refuses to start.
  rm -rf "${STAGE}/vendor/composer/installers"

  echo "==> Re-dumping the scoped autoloader"
  cp "${SCOPED}/composer.json" "${STAGE}/composer.json"

  # --no-plugins and --no-scripts because every plugin in this tree has just
  # been renamed out from under Composer.
  composer dump-autoload \
    --classmap-authoritative \
    --no-dev \
    --no-plugins \
    --no-scripts \
    --no-interaction \
    --working-dir="${STAGE}"
fi

# ---------------------------------------------------------------------------
# 3. Stage everything else, and verify.
# ---------------------------------------------------------------------------
echo "==> Staging the rest"

cp "${BUILD}/vendor-version.php" "${STAGE}/vendor-version.php"
cp "${ROOT}/composer.json" "${STAGE}/composer.json"

for path in "${SOURCE_DATA[@]}"; do
  if [ -e "${ROOT}/${path}" ]; then
    cp -R "${ROOT}/${path}" "${STAGE}/"
  fi
done

# Never ship development tooling or tests.
rm -rf "${STAGE}/vendor/bin" \
       "${STAGE}/tests" \
       "${STAGE}/.github" \
       "${STAGE}/phpcs.xml.dist" \
       "${STAGE}/phpstan.neon.dist" \
       "${STAGE}/phpunit.xml.dist"

if [ "${BFW_SKIP_SCOPING:-0}" != "1" ]; then
  echo "==> Verifying the scoped build actually works"
  php "${BUILD}/verify-scope.php" "${STAGE}" "${PREFIX}"
fi

echo "==> Sanity-checking the staged plugin"
php -l "${STAGE}/${PLUGIN_SLUG}.php" > /dev/null
test -f "${STAGE}/vendor/autoload.php" || { echo "No vendor/autoload.php in the zip." >&2; exit 1; }
test -f "${STAGE}/vendor-version.php"  || { echo "No vendor-version.php in the zip." >&2; exit 1; }

# The library itself has to be in there. A zip that installs and then reports
# "the firewall library is not installed" is the failure this checks for.
test -d "${STAGE}/vendor/kanopi/firewall" \
  || { echo "kanopi/firewall is missing from the zip." >&2; exit 1; }

ZIP="${DIST}/${PLUGIN_SLUG}-${VERSION}.zip"

echo "==> Writing ${ZIP}"
( cd "${BUILD}/stage" && zip -rq "${ZIP}" "${PLUGIN_SLUG}" -x '*.DS_Store' )

echo "==> Done"
ls -lh "${ZIP}"
