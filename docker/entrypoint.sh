#!/bin/sh

set -e

echo "start app"
node -p 'let pkg = require("./package.json");`${pkg.name} - ${pkg.version}`'
yarn run start