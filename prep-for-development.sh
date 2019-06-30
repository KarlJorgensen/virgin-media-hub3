#!/bin/sh
#
# Set up a few things for developers
#
set -e
mydir=$(dirname $0)

repodir=$(dirname $(git rev-parse --git-dir))

cd $repodir

git config core.hooksPath ./githooks
