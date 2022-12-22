#!/bin/bash
#
#

##
# Helper script to launch Ghidra coverage analysis with given kAFL traces and target ELF.
#
# Usage: ghidra_run.sh [-h | --help] WORKDIR SCRIPT [TARGET [ADDRESS]]
#
# Options:
#   -h, --help    Display this help text
#   WORKDIR       kAFL workdir with traces/ folder
#   SCRIPT        ghidra script to run for this analysis
#   TARGET        target binary
#   ADDRESS       target image base address in hexadecimal
##
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: MIT
##


# print script usage information given above in comments
function usage()
{
    # find usage line
    usage_start=$(grep -n "^# Usage" "$0" | awk -F ":" '{print $1}')
    # print only usage part
    tail -n +"$usage_start" "$0" | sed -ne '/^#/!q;/^##/q;s/.\{1,2\}//;p'
    exit
}

# print help text given above in comments
function help()
{
    # find usage line
    help_start="`grep -n "^##" "$0" | head -n 1 | awk -F ":" '{print $1}'`"
    # print only usage part
    tail -n +"$help_start" "$0" | sed -ne '/^#/!q;s/.\{1,2\}//;1d;p'
    exit
}

# exit with errorcode 1 & print usage
function fatal()
{
    [[ -n "$1" ]] && echo "Error: $1"; echo
    usage >&2
    exit 1
}

# create project and import binary - slow but only required once per binary
function import_target()
{
    test -f $PROJDIR/$PROJ.gpr && return

    if [[ $TARGET == *.debug ]]
    then
        test -z "$BASEADDR" && BASEADDR="0x00"
        $BIN $PROJDIR $PROJ -import $TARGET -overwrite -loader ElfLoader -loader-imagebase $BASEADDR
    else
    $BIN $PROJDIR $PROJ -import $TARGET -overwrite
    fi
}


### Main() ###
set -e

# assert kAFL environment
test -z ${GHIDRA_ROOT-} && fatal "Could not find \$GHIDRA_ROOT. Missing 'make env'?"
test -z ${KAFL_ROOT-} && fatal "Could not find \$KAFL_ROOT. Missing 'make env'?"

# command line argument parsing
[[ $# -eq 1 && ("$1" == "-h" || "$1" == "--help") ]] && help
[[ $# -lt 2 || $# -gt 4 ]] && fatal "Invalid number of arguments."
WORKDIR="$(realpath $1)"
SCRIPT="$(realpath $2)"
[[ -n "$3" ]] && TARGET="$(realpath $3)"
BASEADDR="$4"

BIN=$GHIDRA_ROOT/support/analyzeHeadless
PROJDIR=$WORKDIR/traces/ghidra
PROJ=cov_analysis

test -d $PROJDIR   || mkdir $PROJDIR || fatal "Could not create target folder $PROJDIR"
test -f "$BIN"     || fatal "Could not find $BIN. Check ghidra install."
test -f "$SCRIPT"  || fatal "Could not find coverage analysis script at $SCRIPT"
[[ -n $TARGET ]] && (test -f "$TARGET"  || fatal "Could not find target binary at $TARGET")
re_addr="^(0x)?[0-9a-fA-F]{1,16}$"
[[ -n $BASEADDR ]] && ([[ $BASEADDR =~ $re_addr ]] || fatal "bad address format \"$BASEADDR\"")

# Check if traces have been generated and optionally create unique edges file
test -d "$WORKDIR/traces/" || fatal "Could not find traces/ folder in workdir."
test -f "$WORKDIR/traces/edges_uniq.lst" || $KAFL_ROOT/tools/unique_edges.sh $WORKDIR

# TODO: how can we hand the file argument directly to ghidra script?
ln -sf "$WORKDIR/traces/edges_uniq.lst" /tmp/edges_uniq.lst

# import target if given as command line argument
[[ -n $TARGET ]] && import_target

# analyse coverage
$BIN $PROJDIR $PROJ -noanalysis -process $(basename $TARGET) -prescript GetAndSetAnalysisOptionsScript.java -scriptPath "$(dirname $SCRIPT)" -postscript "$(basename $SCRIPT)"
