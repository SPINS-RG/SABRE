#!/bin/bash
# SABRE UNIFIED TEST RUNNER
# Usage: ./run.sh <ARCH> <APP> <ovf|uaf>
#   ARCH       : msp430 | arm
#   APP        : aha-compress | cover | crc_32 | fibcall | jfdctint | lcdnum | libbs
#   attack_type: ovf | uaf  (bench set is derived: ovf->beebs, uaf->beebs-uaf)

case "$3" in
	ovf) attack_type=OVF ;;
	uaf) attack_type=UAF ;;
	*)   echo "arg 3 must be 'ovf' or 'uaf'"; exit ;;
esac

if [[ $1 == "msp430" ]]; then

	app=$2
	if [[ $attack_type == "OVF" ]]; then
		bench_set=beebs
	else
		bench_set=beebs-uaf
	fi
	path="../ACFA/"${bench_set}"/"${app}"/"

	# handle attack/ subdir layout (beebs) vs flat layout (beebs-uaf)
	if [ -d ${path}"attack" ]; then
		path=${path}"attack/"
	fi

	if [ -f ${path}"combined.cflog" ]; then
		cflog_file=${path}"combined.cflog"
	else
		cflog_file=${path}"1.cflog"
	fi
	echo RUNNING ${path}

	case "${attack_type}" in
	    OVF)
	        # OVF-style patch addresses
	        case "$2" in
	            jfdctint)
	                patchaddr=0xed00
	                ;;
	            crc_32)
	                patchaddr=0xe500
	                ;;
	            cover)
	                patchaddr=0xea00
	                ;;
	            aha-compress)
	                patchaddr=0xe800
	                ;;
	            *)
	                patchaddr=0xe300
	                ;;
	        esac
	        ;;
	    UAF)
	        # UAF-style patch addresses
	        case "$2" in
	            jfdctint)
	                patchaddr=0xee00
	                ;;
	            crc_32)
	                patchaddr=0xe600
	                ;;
	            cover)
	                patchaddr=0xeb00
	                ;;
	            aha-compress)
	                patchaddr=0xe800
	                ;;
	            libbs)
	                patchaddr=0xe400
	                ;;
	            lcdnum)
	                patchaddr=0xe500
	                ;;
	            *)
	                patchaddr=0xe300
	                ;;
	        esac
	        ;;
	    *)
	        patchaddr=0xe300
	        ;;
	esac

	input_file=${path}"tcb.lst"
	input_elf=${path}"tcb.elf"
	arch_type="elf32-msp430"
	funcname="main"
	OBJDUMP=msp430-objdump
	stack="__stack"

	sed -i 's/Disassembly of section .empty://g' ${input_file}

elif [[ $1 == "arm" ]]; then

	app=$2
	if [[ $attack_type == "OVF" ]]; then
		bench_set=beebs
	else
		bench_set=beebs-uaf
	fi
	path="../TRACES/"${bench_set}"/"${app}"/"

	input_file=${path}"TRACES_NonSecure.list"
	cflog_file=${path}"0.cflog"
	input_elf=${path}"TRACES_NonSecure.elf"

	patchaddr=0x8060000

	arch_type="armv8-m33"
	funcname="application"
	OBJDUMP=arm-none-eabi-objdump
	stack="_estack"

	# get data from pmem
	grep "word" ${input_file} > .words.tmp
	awk {'print $1, $2'} .words.tmp > .words.tmp2
	sed 's/:/,/g' .words.tmp2 > ./objs/.words
	rm .words.tmp .words.tmp2
	sed -i '/.word/d' ./objs/.words #remove any mess caused by listing file
	arm-none-eabi-objdump -d ${input_elf} > ${path}beebs.lst
else
	echo "Use argument 'msp430' or 'arm'"
	exit
fi
echo "Path: " ${path}
echo "Input file: " ${input_file}
echo "Input ELF: " ${input_elf}
echo "Patch address: " ${patchaddr}

# try to get init stack pointer val
${OBJDUMP} -dt ${input_elf} | grep ${stack} | awk '{print $1}' > ./objs/.sp

# try to get initial values for data
${OBJDUMP} -t ${input_elf} | grep "O \.data" | sort -k1,1 | awk '{print $1, $5}' > ./objs/.data.objs
${OBJDUMP} -t ${input_elf} | grep "O \.bss" | sort -k1,1 | awk '{print $1, $5}' > ./objs/.bss.objs
${OBJDUMP} -s -j .data ${input_elf} | tail -n +5 | awk '{print $2$3$4$5}' > ./objs/.data
${OBJDUMP} -s -j .rodata ${input_elf} | tail -n +5 | awk '{print $1}' > ./objs/.rodata.start
${OBJDUMP} -s -j .rodata ${input_elf} | tail -n +5 | awk '{print $2$3$4$5}' > ./objs/.rodata

touch ./logs/timingdata.log

echo "Building app CFG..."
echo python3 generate_cfg.py --asmfile ${input_file} --arch ${arch_type} --cfgfile ./objs/cfg.bin
python3 generate_cfg.py --asmfile ${input_file} --arch ${arch_type} --cfgfile ./objs/cfg.bin
echo "Done"

echo "Running SABRE..."
echo  ${input_elf} patched.elf
cp  ${input_elf} patched.elf
python3 sabre.py --cfgfile ./objs/cfg.bin --cflog ${cflog_file} --funcname ${funcname} --patchaddr ${patchaddr}
echo "Done"

cp ./patched.elf ${path}patched.elf
cp ./patched.lst ${path}patched.lst
cp ./translated.cflog ${path}translated.cflog