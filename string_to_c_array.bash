#!/bin/bash

if [ "$#" -ne 2 ]; then
	echo "$0 STRING WIDE?"
	echo "Note: question mark arguments must be yes or no."
	exit 1
fi

STRING="$1"
WIDE="$2"

C_ARRAY=$(echo -n "$STRING" | while read -n1 c;
do
	if [ "$WIDE" == "yes" ]; then
		echo -n "L'${c}',"
	else
		echo -n "'${c}',"
	fi
done);

C_ARRAY="${C_ARRAY}0"

VAR=$(echo "$STRING" | sed -r 's/[.]+/_/g')

if [ "$WIDE" == "yes" ]; then
	echo "wchar_t data_${VAR}[] = {${C_ARRAY}};"
else
	echo "char data_${VAR}[] = {${C_ARRAY}};"
fi
