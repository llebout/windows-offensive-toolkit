#!/bin/bash

PATH="${PATH}:$(pwd)"

echo "Please paste the dll_imports struct then press CTRL-D, or pipe/redirect it to the script."

COUNTER=0
grep -Po "[a-zA-Z_][a-zA-Z0-9_]{0,31}(?=\s*;)" | while IFS= read -r var; do

	if [ "$COUNTER" == "0" ]; then
		echo "int"
		echo "resolve_dll_imports(struct dll_imports* imports)"
		echo "{"
		echo "/*"
		echo "  HACK:"
		echo "  We use unsigned char arrays to force the compiler to include"
    		echo "  the data in the code section (.text) and not .data or .rdata."
		echo "*/"
		string_to_c_array.bash "ntdll.dll" yes
		string_to_c_array.bash "kernel32.dll" yes
	fi

	let COUNTER++

	EXPORT_NAME_C_ARRAY=$(string_to_c_array.bash "$var" no)
	echo "$EXPORT_NAME_C_ARRAY"

	if [[ $var == Nt* ]] || [[ $var == Zw* ]] || [[ $var == Rtl* ]]; then
		echo "imports->${var} = (PVOID)get_export_address(get_module_base((PWSTR)data_ntdll_dll), (PSTR)data_${var});"
	else
		echo "imports->${var} = (PVOID)get_export_address(get_module_base((PWSTR)data_kernel32_dll), (PSTR)data_${var});"
	fi

	echo "if (imports->${var} == NULL) {"
	echo "return -${COUNTER};"
	echo "}"
done

echo "  return 0;"
echo "}"
