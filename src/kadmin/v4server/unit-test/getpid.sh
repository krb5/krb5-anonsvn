#!/bin/sh

# tcl sucks big fat hairy rocks

$PS_ALL | awk "/$1/"' && !/awk/ && !/getpid/ { print $2 }'
