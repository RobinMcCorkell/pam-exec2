#!/bin/bash

# Create ChangeLog from git
if which git > /dev/null && git rev-parse; then
	[[ -e ChangeLog ]] && rm -f ChangeLog
	git log --pretty=medium --abbrev-commit > ChangeLog
else
	touch ChangeLog #suppress errors with a missing ChangeLog
fi

# Prepare the source files for packaging
autoreconf --force --install
