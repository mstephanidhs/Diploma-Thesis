#!/bin/bash

# Generated at Mon Mar 27 14:41:43 2023 - Do not edit!
# template: /home/sysop/seiscomp/share/templates/slarchive/purge_datafiles.tpl

# specify the paths to configuration files and the archive 
# directory respectively
CFGDIR="/home/sysop/seiscomp/var/lib/slarchive"
ARCHIVE="/home/sysop/seiscomp/var/lib/archive"

# iterate over files in GFGDIR that match the pattern  "rc_*"
# assign each found file's path to the variable $rc
for rc in `find $CFGDIR -name "rc_*"`; do
    # extracts the part of the file name after the last underscore
    # and assigns it to the variable 'station'
    station=${rc##*_}
    # executes the content of the current configuration file denotes by '$rc'.
    source $rc
    # searches for files in the '$archive' directory that match the 
    # specific pattern/criteria and then deletes them
    find "$ARCHIVE"/*/"$NET/$STATION" -type f -follow -mtime +$ARCH_KEEP -exec rm -f '{}' \;
done
