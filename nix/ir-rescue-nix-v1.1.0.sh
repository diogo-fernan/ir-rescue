#!/bin/bash
# Bash v4+

# http://mywiki.wooledge.org/

# https://d0hnuts.com/2016/12/21/basics-of-making-a-rootkit-from-syscall-to-hook/

# https://countuponsecurity.com/2017/04/12/intro-to-linux-forensics/

main () {
	set +vx
	if [ "$#" -eq 0 ]; then
		# if [ $(id -u) -eq 0 ]; then
		if [ "$EUID" -eq 0 ]; then

			# $(awk '/MemTotal/{print $2}' /proc/meminfo) # KB
			# df -k . # B
			# echo $(($(stat -f --format="%a*%S" .))) # KB

			init
			test "$?" -eq 0 && { run; end; exit 0; } || exit 1
		else
			echo -e "\n ERROR: ${0##*/} is running without root privileges."
		fi
	else
		echo -e "\n ERROR: too many arguments."
	fi
	help
}

run () {
	if [ "$RUN" -eq 1 ]; then
		clear
		msg "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/${0##*/}"
		cmdl "$LOG" "cat $CONF"
		echo >> "$LOG"
		msg " $HOSTNAME $FQDN `who | awk '{print $1}'` ${SUDO_USER:-$USER}"
		timestamp
		echo >> "$LOG"
		echo
	fi
	activ
	memory
	log
	system
	network
	filesystem
	malware
	activ-contd
	web

	clam
	return 0
}

memory () {
	test "${cfg[mem]}" = true && test "$RUN" -eq 0 && mkd "$MEM"

	if [ "${cfg[mem-dump]}" == true ]; then
		if [ "$RUN" -eq 1 ]; then
			cmd "$MEM/log" "$AVML $MEM/mem.lime"
		else it=$((it+1)); fi
	fi
	return 0
}
log () {
	test "${cfg[log]}" = true && test "$RUN" -eq 0 && mkd "$LOGS"

	if [ "${cfg[log-var]}" == true ]; then
		if [ "$RUN" -eq 1 ]; then
			cpy "$LOGS/log" $LOGS/var "/var/log/" # *.log*
			# "/var/spool/abrt" # program crash debug data
			# "/var/log/kern.log"
			# "/var/log/iptables.log"
			# "/var/www"
			# "/var/mail"
		else it=$((it+1)); fi
	fi
	if [ "${cfg[log-profile]}" == true ]; then
		if [ "$RUN" -eq 1 ]; then
			cmdn "$LOG/log" "cat ~/.*"
			for i in ~/.*; do
				test -f "$i" && cmdl "$LOG/log" "cat $i"
			done
			cmdl "$LOG/log" "cat ~/.ssh/authorized_keys"
			cmdl "$LOG/log" "cat ~/.ssh/known_hosts"
		else it=$((it+1)); fi
	fi
        if [ "${cfg[log-journal]}" == true ]; then
	        if [ "$RUN" -eq 1 ]; then
                        cmd "$LOGS/journal-exp" "journalctl -o export"
                        cmd "$LOGS/journal" "journalctl"
                else it=$((it+1)); fi
        fi
	return 0
}
system () {
	test "${cfg[sys]}" = true && test "$RUN" -eq 0 && mkd "$SYS"

	if [ "${cfg[sys-distro]}" == true ]; then
		if [ "$RUN" -eq 1 ]; then
			cmd "$SYS/distro" "hostname"
			cmd "$SYS/distro" "echo -e \"$DKERN\n$DDIST\""
			cmd "$SYS/distro" "uname"
			cmd "$SYS/distro" "uname -a"
			cmd "$SYS/distro" "lsb_release -a"
			cmd "$SYS/distro" "echo ${DFILES[@]}"
			cmd "$SYS/distro" "cat ${DFILES[@]}"
		else it=$((it+7)); fi
	fi
	if [ "${cfg[sys-info]}" == true ]; then
		if [ "$RUN" -eq 1 ]; then
			cmd "$SYS/sys" "date"
			cmd "$SYS/sys" "ntpq -np"
			cmd "$SYS/sys" "uptime"
			cmd "$SYS/sys" "cat /proc/cpuinfo" # "lscpu"
			cmd "$SYS/sys" "cat /proc/meminfo"
			cmd "$SYS/sys" "vmstat"
			cmd "$SYS/sys" "free -mt"
			cmd "$SYS/sys" "cat /proc/pci" # "lspci"
			cmd "$SYS/sys" "lsusb"
			cmd "$SYS/lshw" "lshw -short"
			cmd "$SYS/lshw" "lshw"
		else it=$((it+10)); fi
	fi
	if [ "${cfg[sys-acc]}" == true ]; then
		if [ "$RUN" -eq 1 ]; then
			cmd "$SYS/acc" "who"
			cmd "$SYS/acc" "whoami"
			cmd "$SYS/acc" "id"
			cmd "$SYS/acc" "sudo -l"
			cmd "$SYS/acc" "last -dFwx" # "/var/log/wtmp"
			# "/var/log/auth*"
			cmd "$SYS/acc" "zcat -f /var/log/auth*"
			# "cat /etc/passwd /etc/shadow"
			cmd "$SYS/acc" "getent passwd"
			cmd "$SYS/acc" "getent shadow"
			cmd "$SYS/acc" "cat /etc/sudoers"
			cmd "$SYS/acc" "cat /etc/group"
			cmd "$SYS/acc" "compgen -u | sort -u" # user alias names
			cmd "$SYS/acc" "compgen -g | sort -u" # groups
		else it=$((it+12)); fi
	fi
	if [ "${cfg[sys-sec]}" == true ]; then
		if [ "$RUN" -eq 1 ]; then
			# "iptables -S"; "iptables -nvL --line-numbers -t [filter, nat, mangle, raw, security]"
			cmd "$SYS/firewall" "iptables-save"
		else it=$((it+1)); fi
	fi
	return 0
}
network () {
	test "${cfg[net]}" = true && test "$RUN" -eq 0 && mkd "$NET"

	if [ "${cfg[net-info]}" == true ]; then
		if [ "$RUN" -eq 1 ]; then
			cmd "$NET/ip" "cat /etc/network/interfaces"
			cmd "$NET/ip" "ifconfig -a" # "ip addr"
			cmd "$NET/ip" "ip link"
			cmd "$NET/conn" "netstat -lnput"
			cmd "$NET/conn" "lsof -i -n -P"
			cmd "$NET/conn" "ss -ap"
			cmd "$NET/tables" "route -n" # "netstat -nr"; "ip route"
			cmd "$NET/tables" "ip neigh"
			cpy "$NET/log" "$NET" "/etc/hosts /etc/hosts.allow /etc/hosts.deny"
			# "smbtree", "smbstatus", "smbclient"
		else it=$((it+9)); fi
	fi
	return 0
}
filesystem () {
	test "${cfg[fs]}" = true && test "$RUN" -eq 0 && mkd "$FS"

	if [ "${cfg[fs-info]}" == true ]; then
		if [ "$RUN" -eq 1 ]; then
			cmd "$FS/lsblk" "lsblk"
			cmd "$FS/lsblk" "fdisk -l"
			cmd "$FS/disk" "cat /proc/partitions"
			cmd "$FS/disk" "df -h"
			cmd "$FS/disk" "du -ch -d 1 /"
			cmd "$FS/mount" "mount -l" # "cat /proc/mounts"
			cmd "$FS/mount" "findmnt -aA"
			cmd "$FS/grub" "cat /boot/grub/grub.cfg"
		else it=$((it+7)); fi
	fi
	if [ "${cfg[fs-stat]}" == true ]; then
		if [ "$RUN" -eq 1 ]; then
			cmd "$FS/stat" "find -P $(echo $(<"$TEMPIR/nonrecursive.txt")) -maxdepth 1 -exec $STATC {} \;"
			cmd "$FS/stat" "find -P $(echo $(<"$TEMPIR/recursive.txt")) -exec $STATC {} \;"
		else it=$((it+2)); fi
	fi
	if [ "${cfg[fs-md5]}" == true ]; then
		if [ "$RUN" -eq 1 ]; then
			cmd "$FS/md5" "find -P $(echo $(<"$TEMPIR/nonrecursive-md5sum.txt")) -maxdepth 1 -type f -exec md5sum {} \;"
			cmd "$FS/md5" "find -P $(echo $(<"$TEMPIR/recursive-md5sum.txt")) -type f -exec md5sum {} \;"
		else it=$((it+2)); fi
	fi
	return 0
}
malware () {
	test "${cfg[mal]}" = true && test "$RUN" -eq 0 && mkd "$MAL"

	if [ "${cfg[mal-proc]}" == true ]; then
		if [ "$RUN" -eq 1 ]; then
			cmd "$MAL/proc" "ps -p $$"
			cmd "$MAL/proc" "pstree -aAhglpSu"
			cmd "$MAL/proc" "ps afux" # pgrep
			cmd "$MAL/proc" "top -n 1 -b"
			# processes accessing files that have been unlinked (link count is zero)
			cmd "$MAL/proc" "lsof +L1"
			cmd "$MAL/proc" "lsof"
		else it=$((it+6)); fi
	fi
	if [ "${cfg[mal-kern]}" == true ]; then
		if [ "$RUN" -eq 1 ]; then
			cmd "$MAL/kernel" "/sbin/sysctl -a"
			cmd "$MAL/kernel" "lsmod" # "cat /proc/modules"
		else it=$((it+2)); fi
	fi
	if [ "${cfg[mal-svcs]}" == true ]; then
		if [ "$RUN" -eq 1 ]; then
			cmd "$MAL/svcs" "compgen -s | sort -u"
			cmd "$MAL/svcs" "service --status-all"
			cmd "$MAL/svcs" "chkconfig --list" # if exists
		else it=$((it+3)); fi
	fi
	if [ "${cfg[mal-tasks]}" == true ]; then
		if [ "$RUN" -eq 1 ]; then
			cmd "$MAL/tasks/tasks" "compgen -j | sort -u"
			# http://stackoverflow.com/questions/134906/how-do-i-list-all-cron-jobs-for-all-users
			cmdn "$MAL/tasks/task"s "crontab -l -u <user>"
			for i in "${UNAME[@]}"; do
				cmdl "$MAL/tasks/tasks.txt" "crontab -l -u $i"
			done
			cmdn "$MAL/tasks/tasks" "cat $(echo ${CRONF[@]})"
			for i in "${CRONF[@]}"; do
				cmdl "$MAL/tasks/tasks.txt" "cat $i"
			done
			cmdn "$MAL/tasks/tasks" "cp -prv $(echo ${CROND[@]})"
			for i in "${CROND[@]}"; do
				cpy "$MAL/tasks/tasks.txt" "$MAL/tasks/$(echo $i | cut -c 2-4)" "$i"
			done
		else mkd "$MAL/tasks"; it=$((it+4)); fi
	fi
	if [ "${cfg[mal-pkg]}" == true ]; then
		if [ "$RUN" -eq 1 ]; then
			cmd "$MAL/pkg" "rpm -alqv" # query
			cmd "$MAL/pkg" "rpm -avV" # verify
			# "rpm –Va -–root=/ | grep SM5"; different filesize (S), mode (M), and MD5 (5)
			# http://searchsecurity.techtarget.com/feature/Malware-Forensics-Field-Guide-for-Linux-Systems

			cmd "$MAL/pkg" "yum list all"
			cmd "$MAL/pkg" "yum history list"

			cmd "$MAL/pkg" "apt list"

			cmd "$MAL/pkg" "dpkg -l"
			cmd "$MAL/pkg" "zcat -f /var/log/apt/history.log*; zcat -f /var/log/dpkg.log*"
		else it=$((it+7)); fi
	fi
	if [ "${cfg[mal-exec]}" == true ]; then
		if [ "$RUN" -eq 1 ]; then
			# find -L / -type f \( -perm -u=x -or -perm -g=x -or -perm -o=x \) -exec echo {} \;
			# find / -type f [(-perm (/111|-111|+x)|-executable] -exec echo {} \;
			cmdn "$MAL/exec" "find -L $(echo $(<"$TEMPIR/recursive-exec.txt")) | file -b | egrep -qw \"(ELF|executable|PE32|shared object|script)\" | $STATC"
			find -L $(echo $(<"$TEMPIR/recursive-exec.txt")) -type f -print0 2>"$NUL" | \
			while read -d $'\0' -r i; do
				file -b "$i" | egrep -qw "ELF|executable|PE32|shared object|script" && echo "$i";
			done | sort | xargs -r stat -c "$STATF" >> "$MAL/exec.txt" 2>&1
		else it=$((it+1)); fi
	fi
	if [ "${cfg[mal-hid]}" == true ]; then
		if [ "$RUN" -eq 1 ]; then
			cmd "$MAL/hid" "find -P $(echo $(<"$TEMPIR/nonrecursive-hidden.txt")) -maxdepth 1 -iname \".*\" -exec $STATC {} \;"
			cmd "$MAL/hid" "find -P $(echo $(<"$TEMPIR/recursive-hidden.txt")) -iname \".*\" -exec $STATC {} \;"
			cmd "$MAL/hid-char" "find -P / -regextype egrep -regex \".*/[^a-zA-Z]+.*\" -exec $STATC {} \;"
			cmd "$MAL/hid-space" "find -P / -regextype egrep -regex \".*/(\.+?)(\s+.*)\" -exec $STATC {} \;"
			cmd "$MAL/orph" "find -P / -nouser -exec $STATC {} \;"
		else it=$((it+5)); fi
	fi
	if [ "${cfg[mal-dev]}" == true ]; then
		if [ "$RUN" -eq 1 ]; then
			cmd "$MAL/dev" "find -P /dev ! \( -type b -or -type c -or -type d \) -exec $STATC {} \;"
		else it=$((it+1)); fi
	fi
	if [ "${cfg[mal-bits]}" == true ]; then
		if [ "$RUN" -eq 1 ]; then
			cmd "$MAL/bits" "find -P / \( -perm -1000 -o -perm -2000 -o -perm 4000 \) -exec $STATC {} \;"
		else it=$((it+1)); fi
	fi

	# persistence mechanisms
	# "/sbin/hwclock"
	return 0
}
activ () {
	test "${cfg[activ]}" = true && test "$RUN" -eq 0 && mkd "$ACTIV"
	if [ "${cfg[activ-cmd]}" == true ]; then
		if [ "$RUN" -eq 1 ]; then
			HISTFILE=~/.bash_history
			set -o history > "$NUL" 2>&1
			cmd "$ACTIV/cmd" "history"
			cmd "$ACTIV/cmd" "cat -b $HISTFILE"
			cmdn "$ACTIV/cmd-files" "cat $(echo ${FPATH[@]})"
			for i in "${FPATH[@]}"; do
				cmdl "$ACTIV/cmd-files.txt" "cat $i"
			done
		else it=$((it+3)); fi
	fi
	return 0
}
activ-contd () {
	if [ "${cfg[activ-env]}" == true ]; then
		if [ "$RUN" -eq 1 ]; then
			cmd "$ACTIV/env" "shopt"
			cmd "$ACTIV/env" "compgen -v | sort -u" # shell variables
			cmd "$ACTIV/env" "env" # "printenv", "compgen -e | sort -u"
			cmd "$ACTIV/env" "compgen -k | sort -u" # Bash reserved words
			cmd "$ACTIV/env" "locale"
			cmd "$ACTIV/env" "compgen -a | sort -u" # commands that can be run
			cmd "$ACTIV/env" "alias" # "compgen -a | sort -u"
			cmd "$ACTIV/env" "umask"
			cmd "$ACTIV/env" "echo $-"
		else it=$((it+9)); fi
	fi
	return 0
}
web () {
	test "${cfg[web]}" = true && test "$RUN" -eq 0 && mkd "$WEB"

	if [ "${cfg[web-browsers]}" == true ]; then
		if [ "$RUN" -eq 1 ]; then
			cmd "$WEB/browsers" "mozilla --version"
			cmd "$WEB/browsers" "firefox --version"
			cmdn "$WEB/log" "cp -v [$(echo ${UPROF[@]})]/*/*.sqlite $WEB/firefox/*"
			for i in "${!UPROF[@]}"; do
				mkd "$WEB/firefox/${UNPRO[$i]}"
				cmdl "$WEB/log.txt" "find ${UPROF[$i]}/.mozilla/ -iname \"*.sqlite\" | xargs cp -v -t $WEB/firefox/${UNPRO[$i]}/"
			done
		else mkd "$WEB/firefox"; it=$((it+2)); fi
	fi
	return 0
}

clam () {
	# "rkhunter --check -r / -l /rkhunter.log"
	test "${cfg[clamscan]}" = true && test "$RUN" -eq 0 && mkd "$MAL/clamscan"

	if [ "${cfg[clamscan-fc]}" == true ]; then
		if [ "$RUN" -eq 1 ]; then
			cmd "$MAL/clamscan/log" "freshclam"
		else it=$((it+1)); fi
	fi
	if [ "${cfg[clamscan]}" == true ]; then
		if [ "$RUN" -eq 1 ]; then
			cmd "$MAL/clamscan/log" "clamscan -r --move=$MAL/clamscan /"
		else it=$((it+1)); fi
	fi
	return 0
}

cmd () {
	cmdn "$@"
	eval "$2" >> "$1.txt" 2>&1 # evil
	return 0
}
cmdn () {
	dateupd
	((in++))
	echo " $YYYYMMDD $TIME running $in out of $it: \"$2\"" | tee -a "$LOG"
	echo -e "\n$NAME-$VER $YYYYMMDD $TIME ($TZ): \"$2\"\n" >> "$1.txt"
	return 0
}
cmdl () {
	dateupd
	echo -e "\n$NAME-$VER $YYYYMMDD $TIME ($TZ): \"$2\"\n" >> "$1"
	eval "$2" >> "$1" 2>&1 # evil
	return 0
}

cpy () {
	test -d "$2" || mkd "$2" && cmdl "$1.txt" "cp -prv $3 $2"
}
dateupd () {
	YYYYMMDD=$(date +%Y%m%d)
	TIME=$(date +%H:%M:%S)
}

timestamp () {
	msg "$NAME-$VER $YYYYMMDD $TIME ($TZ)"
}

msg () {
	echo -e "\n$1" | tee -a "$LOG"
}

init () {
	# prone to symlinks
	cd $(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
	dateupd

	NAME=ir-rescue-nix
	VER=beta
	TOOLS=tools-nix
	SYSTEM="$HOSTNAME-$YYYYMMDD"

	FQDN=$(host -TtA $(hostname -s) | grep "has address" | awk '{print $1}')
	test -z "$FQDN" && FQDN=$(hostname -s)

	DATA="./data"
	ROOT="$DATA/$SYSTEM"
	META="$ROOT/$NAME"
	CFG="$TOOLS/cfg"
	MEM="$ROOT/mem"
	LOGS="$ROOT/log"
	SYS="$ROOT/sys"
	NET="$ROOT/net"
	FS="$ROOT/fs"
	MAL="$ROOT/mal"
	ACTIV="$ROOT/activ"
	WEB="$ROOT/web"

	TEMPIR="/tmp/$NAME"
	LOG="$META/$NAME.log"
	CONF="$CFG/$NAME.conf"
	NUL="/dev/null"

	# BSD stat format is different
	# differentiate GNU find from BSD find
	STATF="%8i %A (%4a) %m %N %b (%B) %s '%F' '%y' '%x' '%z' '%w' %U (%u) %G (%g)"
	STATC="stat -c \"$STATF\""
	AVML="$TOOLS/mem/avml-0.21"
	declare -a -g RECUF=(
		"nonrecursive.txt" "recursive.txt"
		"recursive-exec.txt"
		"nonrecursive-hidden.txt" "recursive-hidden.txt"
		"nonrecursive-md5sum.txt" "recursive-md5sum.txt"
	)

	TZ="$(date +%Z), UTC$(date +%:z)"
	clear
	echo -e "\n   initializing..."
	local f=0

	test ! -e "$AVML" && echo -e "\n ERROR: $AVML not found" && f=1
	for i in "${RECUF[@]}"; do
		test ! -e "$CFG/$i" && echo -e "\n ERROR: $CFG/$i not found" && f=1
	done

	if [ "$f" -eq 0 ]; then
		local txt=("$TOOLS"/ascii/*.txt)
		ASCII="${txt[RANDOM % ${#txt[@]}]}"
		# type -A cfg # cfg=()
		declare -A -g cfg

		rconf killself ckillself
		rconf shred cshred
		rconf zip czip
		rconf zpassword czpassword
		rconf ascii cascii

		rconf memory mem
		rconf memory-all mem-all
		test "${cfg[mem]}" = false && cfg[mem-all]=false
		rconf memory-dump mem-dump "${cfg[mem-all]}" "${cfg[mem]}"

		rconf log log
		rconf log-all log-all
		test "${cfg[log]}" = false && cfg[log-all]=false
		rconf log-var log-var "${cfg[log-all]}" "${cfg[log]}"
                rconf log-journal log-journal "${cfg[log-all]}" "${cfg[log]}"

		rconf system sys
		rconf system-all sys-all
		test "${cfg[sys]}" = false && cfg[sys-all]=false
		rconf system-distribution sys-distro "${cfg[sys-all]}" "${cfg[sys]}"
		rconf system-info sys-info "${cfg[sys-all]}" "${cfg[sys]}"
		rconf system-account sys-acc "${cfg[sys-all]}" "${cfg[sys]}"

		rconf network net
		rconf network-all net-all
		test "${cfg[net]}" = false && cfg[net-all]=false
		rconf network-info net-info "${cfg[net-all]}" "${cfg[net]}"

		rconf filesystem fs
		rconf filesystem-all fs-all
		test "${cfg[fs]}" = false && cfg[fs-all]=false
		rconf filesystem-info fs-info "${cfg[fs-all]}" "${cfg[fs]}"
		rconf filesystem-stat fs-stat "${cfg[fs-all]}" "${cfg[fs]}"
		rconf filesystem-md5sum fs-md5 "${cfg[fs-all]}" "${cfg[fs]}"

		rconf malware mal
		rconf malware-all mal-all
		test "${cfg[mal]}" = false && cfg[mal-all]=false
		rconf malware-processes mal-proc "${cfg[mal-all]}" "${cfg[mal]}"
		rconf malware-kernel mal-kern "${cfg[mal-all]}" "${cfg[mal]}"
		rconf malware-services mal-svcs "${cfg[mal-all]}" "${cfg[mal]}"
		rconf malware-tasks mal-tasks "${cfg[mal-all]}" "${cfg[mal]}"
		rconf malware-packages mal-pkg "${cfg[mal-all]}" "${cfg[mal]}"
		rconf malware-executables mal-exec "${cfg[mal-all]}" "${cfg[mal]}"
		rconf malware-hidden mal-hid "${cfg[mal-all]}" "${cfg[mal]}"
		rconf malware-dev mal-dev "${cfg[mal-all]}" "${cfg[mal]}"
		rconf malware-bits mal-bits "${cfg[mal-all]}" "${cfg[mal]}"

		rconf activity activ
		rconf activity-all activ-all
		test "${cfg[activ]}" = false && cfg[activ-all]=false
		rconf activity-command-line activ-cmd "${cfg[activ-all]}" "${cfg[activ]}"
		rconf activity-environment activ-env "${cfg[activ-all]}" "${cfg[activ]}"

		rconf web web
		rconf web-all web-all
		test "${cfg[web]}" = false && cfg[web-all]=false
		rconf web-browsers web-browsers "${cfg[web-all]}" "${cfg[web]}"

		rconf clamscan clam
		rconf clamscan-freshclam clam-fc false "${cfg[clam]}"

		cleann "$DATA" "$TEMPIR"
		cleann "./$SYSTEM.zip"

		in=0
		it=0

		declare -a -g DFILES=(
			"/etc/*-release" "/etc/*_version" "/etc/issue"
			"/proc/*release*" "/proc/*version*"
		)
		declare -a -g DISTRO=(
			"/etc/fedora-release" "/etc/arch-release"
			"/etc/redhat-release" "/etc/SuSE-release" "/etc/gentoo-release"
		)
		declare -a -g USERS=( )
		readarray USERS < <(getent passwd)
		# declare -a -g USERS=( $(getent passwd) )
		declare -a -g UNAME=( $(getent passwd | cut -d : -f 1) )
		declare -a -g UNPRO=( )
		declare -a -g UPROF=( )
		declare -a -g FBASH=( ".profile" ".bashrc" ".bash_logout" )
		declare -a -g FHIST=( ".bash_history" ".history" )
		declare -a -g FILES=( "${FBASH[@]}" "${FHIST[@]}" )
		declare -a -g FPATH=( "/etc/profile" /etc/profile.d/* )
		declare -a -g CRONF=( "/etc/crontab" "/etc/anacrontab" )
		declare -a -g CROND=(
			"/etc/cron.d"
			"/var/spool/cron" "/var/spool/anacron"
			"/etc/cron.hourly" "/etc/cron.daily"
			"/etc/cron.weekly" "/etc/cron.monthly"
		)

		DKERNEL=$(uname -s)
		DKERN="$(uname -s) ($(uname -o) $(uname -r) ($(uname -v)) $(uname -n) $(uname -m) $(uname -p)"
		DDIST=""

		# shopt -s nullglob dotglob     # To include hidden files
		# http://linuxmafia.com/faq/Admin/release-files.html
		# http://unix.stackexchange.com/questions/6345/how-can-i-get-distribution-name-and-version-number-in-a-simple-shell-script

		declare -a tmp=( "${DISTRO[@]}" "${DFILES[@]}" )
		if [ "$DKERNEL" == "Linux" ]; then
			if [ -f "/etc/lsb-release" ] || [ -f "/etc/lsb_release" ]; then
				. /etc/lsb-release 2>"$NUL" || . /etc/lsb_release
				DDIST="$DISTRIB_ID $DISTRIB_RELEASE ($DISTRIB_CODENAME): $DISTRIB_DESCRIPTION"
			else
				for i in "${tmp[@]}"; do
					test -e "$i" && { DDIST=`cat $i`; break; }
				done
			fi
		elif [ "$DKERNEL" == "AIX" ]; then
			DDIST="`oslevel` `oslevel -r`"
		elif [ "$DKERNEL" == "SunOS" ]; then
			:
		else
			:
		fi

		unset tmp
		for i in "${!USERS[@]}"; do
			tmp="$(echo "${USERS[$i]}" | cut -d : -f 6)"
			for j in "${FILES[@]}"; do
				test -e "$tmp/$j" && {
					UNPRO+=("${UNAME[$i]}"); UPROF+=("$tmp"); break 1;
				}
			done
		done
		unset tmp

		for i in "${UPROF[@]}"; do
			for j in "${FILES[@]}"; do
				test -e "$i/$j" && FPATH+=( "$i/$j" )
			done
		done

		mkdir "./$DATA" "./$ROOT" "./$META" "$TEMPIR" > "$NUL" 2>&1

		for i in "${RECUF[@]}"; do
			while read -r j; do
				for k in "$j"; do
					test -e "$k" && echo "$k" >> "$TEMPIR/$i"
				done
			done < "$CFG/$i"
		done

		RUN=0
		run
		RUN=1

		# for i in "${!cfg[@]}"; do
		# 	echo "$i" "${cfg[$i]}"
		# done | sort -k 2n
		# pause
	fi
	return "$f"
}
end () {
	timestamp
	msg " compressing data and cleaning up..."

	packf "$MEM/mem.lime"
	# packd $MEM

	clean "$MEM/mem.lime"

	timestamp
	ascii
	msg "  finishing..."

	cmdl "./$META/$SYSTEM.md5" "find -P . -type f -exec md5sum {} \;"
	cd "$DATA"; zip -b "$TEMPIR" -r "../$SYSTEM.zip" "$SYSTEM" > "$NUL" 2>&1; cd ..
	clean "$TEMPIR"
	# cleann "$DATA"

	echo -e "\nterminus / end / fin / fim / fine / einde / koniec"
	pause
	return 0
}

ascii () {
	(echo && cat "$ASCII" && echo) | tee -a "$LOG"
	return 0
}

mkd () {
	mkdir -p "$1" > "$NUL" 2>&1
}
packf () {
	for i in "$@"; do
		test -e "./$i" && cmdl "$LOG" "zip -b $TEMPIR -j $i.zip $i"
	done
	return 0
}
packd () {
	for i in "$@"; do
		if [ -e "./$i" ]; then
			test -n "$2" && tmp="$1" || tmp="$2"
			cmdl "$LOG" "zip -b $TEMPIR -r $tmp $1"
			pushd "$1/.." > "$NUL" 2>&1
			zip -b "$TEMPIR" -r "$tmp" "$1" > "$TEMPIR/tmp"
			popd > "$NUL" 2>&1
			cat "$TEMPIR/tmp" >> "$LOG" 2>&1
		fi
	done
	return 0
}
packdd () {
	test -z "$2" && tmp="$1" || tmp="$2"
	cmdl "$LOG" "zip -b $TEMPIR -r $tmp $1"
	return 0
}
cleann () {
	cleanr "$NUL" "$@"
	return 0
}
clean () {
	cleanr "$LOG" "$@"
	return 0
}
cleanr () {
	if [ "${cfg[cshred]}" == true ]; then
		# "wipe", "srm"; "shred" is not effective in all filesystems
		# "smem", "sfill", "sswap"
		cmdl "$1" 'find '"${@:2}"' -type f -exec shred -uvn 1 {} '\\\;''
	fi
	cmdl "$1" "rm -rf -- ${@:2}"
	# cmdl "$1" "rm -rf ${@:2}"
	return 0
}

rconf () {
	tmp="$(grep -E "^$1=([a-Z]+)$" $CONF | cut -d = -f 2)"
	test ! "$tmp" = true -o "$tmp" = false && tmp=false
	[ -n "$3" ] && [ "$3" == true ] && tmp=true
	[ -n "$4" ] && [ "$4" == false ] && tmp=false
	cfg+=(["$2"]="$tmp")
	return 0
}

pause () {
	read -p "$*"
	return 0
}

help () {
	echo "
 Usage: sudo ./${0##*/}

 Output: text files per each command executed organized according to data type.

 ${0##*/}  is a Bash shell script for collecting incident response
 data on Unix systems.  It uses  third-party  utilities kept in a folder called
 'tools' under 'ir-rescue/tools-nix/'.

 Needs root privileges to run.
"
	pause
	exit 1
}

# remove trailing forward slashes from paths
main "${@%/}"
