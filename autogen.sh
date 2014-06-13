#!/bin/bash

# Create ChangeLog from git
if [[ -d .git ]] && which git > /dev/null; then
	[[ -e ChangeLog ]] && rm -f ChangeLog
	git log --pretty=medium --abbrev-commit > ChangeLog
else
	touch Changelog #suppress errors with a missing ChangeLog
fi

# Prepare the source files for packaging
autoreconf --force --install
