#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
printf '%s\n' 'Encrypto verified frontend v2.1.1'
if ! command -v node >/dev/null 2>&1; then
  echo 'ERROR: Node.js 22 or newer is required.' >&2
  exit 1
fi
if [ ! -f server/node_modules/express/package.json ]; then
  echo 'Installing backend dependencies (first run)...'
  npm run setup
fi
echo 'Open http://localhost:3000. If that port is occupied, stop the OLD server first.'
npm start
