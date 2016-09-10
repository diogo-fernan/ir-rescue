@echo off

:: author:	Diogo A. B. Fernandes
:: contact:	diogoabfernandes@gmail.com
:: license:	see LICENSE

:main
	:: start local variable environment
	setlocal ENABLEDELAYEDEXPANSION

	:: check for arguments
	set /A args=0
	for %%a in (%*) do set /A args+=1
	if not %args% equ 0 (
		echo.&echo  ERROR: too many arguments
		call:help
		exit /B 1
	) 
	:: check for elevated (administrator) permissions
	fsutil dirty query %SystemDrive% > NUL 2>&1
	if not %errorLevel% equ 0 (
		echo.&echo  ERROR: %~nx0 is running without administrator rights.
		call:help
		exit /B 1
	)
	:: check for free disk space
	:: batch "set /A" does not handle signed numbers larger than 32-bit in precision
	:: several workarounds, too complicated

	:: "set" before everything else
	del /A:H /F /Q set.txt.tmp > NUL 2>&1
	set > set.txt.tmp 2>&1
	attrib +H set.txt.tmp > NUL 2>&1

	call:init
	if not %errorLevel% equ 0 (
		attrib -H set.txt.tmp > NUL 2>&1
		del /Q /S .\set.txt.tmp >> NUL 2>&1
		call:help
		exit /B 1
	)

:run
	cls
	:: The command line window character set enconding is based on MS-DOS, which
	:: is independent of the enconding used by Windows subsystems.  The codepage
	:: thus needs to be changed to UTF-8.
	chcp 65001 > NUL 2>&1

	call:msg "%~pdnx0"
	echo. >> %LOG%
	type %CONF% >> %LOG%
	echo. >> %LOG%
	call:msg " %LOGONSERVER%  %COMPUTERNAME%  %USERDOMAIN%\%USERNAME%"
	call:timestamp
	echo.

	if %cmem% equ true (
		call:cmd %MEM%	winpmem	"%PMEM% %MEM%\raw.mem"
	)

	if %cmal% equ true (
		call:cmd %MAL%	log ^
			"xcopy %SystemRoot%\Prefetch\*.pf %MAL%\Prefetch\ /C /I /F /H /Y"
		call:ncmd %MAL%	log		"%WPV% /prefetchfile %SystemRoot%\Prefetch\*.pf /sort ~7 /scomma %MAL%\Prefetch\*.csv"
		for /F "tokens=*" %%p in ('dir /B /S %SystemRoot%\Prefetch\*.pf') do (
			%WPV% /prefetchfile %%p /sort ~7 /scomma %MAL%\Prefetch\%%~np.csv
		)
	)

	if %creg% equ true			call:registry

	if %cmisc% equ true (
		call:cmd %MISC%	log		"%LAV% /scomma %MISC%\last-activity.csv"
	)

	if %cevt% equ true			call:events
	if %csys% equ true			call:system
	if %cnet% equ true			call:network
	if %csys% equ true			call:system-contd
	if %cfs% equ true			call:filesystem
	if %cmal% equ true			call:malware
	if %cweb% equ true			call:web
	if %cmisc% equ true			call:misc

	if %csigcheck% equ true		call:sigcheck
	if %cdensity% equ true		call:density
	if %ciconext% equ true		call:iconext
	if %cyara% equ true			call:yara

	call:end
	:: end local variable environment
	endlocal
	:: exit and delete self
	:: if %ckillself% equ true		goto 2>NUL & del /F /Q %~f0
	exit /B 0

:registry
	:: SAM is empty
	:: call:cmd %REG% reg					"reg export HKLM\SAM\ %REG%\hives\SAM.txt"
	call:cmd %REG% log			"reg export HKLM\SOFTWARE\ %REG%\hives\SOFTWARE.txt"
	call:cmd %REG% log			"reg export HKLM\SYSTEM\ %REG%\hives\SYSTEM.txt"
	for /F "tokens=*" %%p in ('reg query HKU') do (
		set key=%%p
		set key=!key:\=-!.txt
		call:cmd %REG% log		"reg export %%p %REG%\hives\!key!"
	)
	goto:eof

:events
	:: call:cmd %EVT%	log ^
	::	"xcopy %SystemRoot%\system32\winevt\logs\Security.evtx %EVT%\ /C /I /F /H /Y"
	call:cmd %EVT%	log			"%PLL% -accepteula -g %EVT%\evtx\Security.evtx Security"
	call:cmd %EVT%	log			"%PLL% -accepteula -g %EVT%\evtx\System.evtx System"
	call:cmd %EVT%	log			"%PLL% -accepteula -g %EVT%\evtx\Application.evtx Application"
	call:cmd %EVT%	log			"%PLL% -accepteula -g %EVT%\evtx\Setup.evtx Setup"
	call:cmd %EVT%	Security	"%PLL% -accepteula Security"
	call:cmd %EVT%	System		"%PLL% -accepteula System"
	call:cmd %EVT%	Application	"%PLL% -accepteula Application"
	call:cmd %EVT%	Setup		"%PLL% -accepteula Setup"
	goto:eof

:system
	call:cmd %SYS%	sys			"hostname"
	call:cmd %SYS%	sys			"ver"
	call:cmd %SYS%	sys			"type set.txt.tmp"
	:: setx /?
	call:cmd %SYS%	sys			"systeminfo"
	call:cmd %SYS%	sys			"%PSI% -accepteula -h -s -d"
	call:cmd %SYS%	acc			"%PSLO% -accepteula"
	call:cmd %SYS%	acc			"%PSL% -accepteula -c -p"
	goto:eof

:system-contd
	call:cmd %SYS%	acc			"net accounts"
	call:cmd %SYS%	acc			"net localgroup"
	call:cmd %SYS%	acc			"net localgroup Administrators"
	call:cmd %SYS%	acc			"net localgroup Users"
	call:cmd %SYS%	acc			"net localgroup HomeUsers"
	call:cmd %SYS%	acc			"net localgroup Guests"
	call:cmd %SYS%	sid			"%PSG% -accepteula \\%COMPUTERNAME%"
	for /L %%u in (1,1,%c%) do (
		net user !users[%%u]! /domain %USERDOMAIN% > NUL 2>&1
		:: if ERRORLEVEL 2
		if not !errorLevel! equ 0 (
			call:cmd %SYS%	acc	"net user !users[%%u]!"
		) else (
			call:cmd %SYS%	acc	"net user !users[%%u]! /domain %USERDOMAIN%"
		)
		call:cmd %SYS%	sid		"%PSG% -accepteula !users[%%u]!"
	)
	:: "icacls C:\Users\* /C"
	call:cmd %SYS%	acl			"%AC% -accepteula -l C:\Users"
	call:cmd %SYS%	acl			"%AC% -accepteula -d -l C:\Users"
	call:cmd %SYS%	acl			"%AC% -accepteula -l D:\Users"
	call:cmd %SYS%	acl			"%AC% -accepteula -d l D:\Users"
	call:cmd %SYS%	acl			"%AC% -accepteula -d -l %SystemRoot%"
	call:cmd %SYS%	acl			"%AC% -accepteula -d -l %SystemRoot%\system32"
	call:cmd %SYS%	acl			"%AC% -accepteula -d -l %SystemRoot%\syswow64"
	goto:eof

:network
	call:cmd %NET%	ip			"ipconfig /all"
	call:cmd %NET%	ip			"ipconfig /displaydns"
	call:cmd %NET%	conn		"netstat -abno"
	call:cmd %NET%	conn		"%TCPV% -accepteula -a -n -c"
	call:cmd %NET%	conn		"ping -a -n 1 www.google.com"
	:: nmap -sn --traceroute www.google.com
	:: no portable version
	call:cmd %NET%	conn		"tracert -h 16 -w 256 www.google.com"
	call:cmd %NET%	netbios		"nbtstat -c"
	call:cmd %NET%	netbios		"nbtstat -n"
	call:cmd %NET%	netbios		"nbtstat -S"
	call:cmd %NET%	tables		"route print"
	call:cmd %NET%	tables		"arp -a"
	call:cmd %NET%	net			"net use"
	call:cmd %NET%	net			"net view"
	call:cmd %NET%	net			"net sessions"
	call:cmd %NET%	shares		"openfiles"
	call:cmd %NET%	shares		"%PSF% -accepteula"
	call:cmd %NET%	log ^
		"xcopy %SystemRoot%\system32\drivers\etc\hosts %NET%\ /C /I /F /H /Y"
	goto:eof

:filesystem
	call:cmd %FS%	ntfs		"fsutil fsinfo drives"
	call:cmd %FS%	ntfs		"fsutil fsinfo ntfsinfo C:\"
	call:cmd %FS%	ntfs		"fsutil fsinfo ntfsinfo D:\"
	call:cmd %FS%	ntfs		"%NTFS% -accepteula C:\"
	call:cmd %FS%	ntfs		"%NTFS% -accepteula D:\"
	call:cmd %FS%	vss			"vssadmin list volumes"
	call:cmd %FS%	vss			"vssadmin list shadows"
	call:cmd %FS%	vss			"vssadmin list shadowstorage"
	for /L %%u in (1,1,%e%) do (
		call:cmd %FS%	dir-!driveslc[%%u]!-m	"dir /A /O:D /Q /T:W /S !drivesuc[%%u]!:\"
	)
	if %cfs-simple% equ true (
		for /L %%u in (1,1,%e%) do (
			call:cmd %FS%	dir-!driveslc[%%u]!	"dir /A /B /S !drivesuc[%%u]!:\"
		)
	) else (
		call:cmd %FS%	fls-c	"%FLS% -p -l -r \\?\GLOBALROOT\Device\HarddiskVolume2"
		call:cmd %FS%	fls-d	"%FLS% -p -l -r \\?\GLOBALROOT\Device\HarddiskVolume3"
		call:cmd %FS%	md5-c	"%MD5% -f %CFG%\c.txt -r -s -t -z"
		call:cmd %FS%	md5-sys	"%MD5% -f %CFG%\sys.txt -s -t -z"
		call:cmd %FS%	md5-d	"%MD5% -r -s -t -z D:\"
		call:cmd %FS%	ads ^
			"%ADS% /FolderPath C:\ /ScanSubfolders 1 /SubFolderDept 0 /ShowZeroLengthStreams 1 /scomma %FS%\ads-c.csv"
		call:cmd %FS%	ads ^
			"%ADS% /FolderPath D:\ /ScanSubfolders 1 /SubFolderDept 0 /ShowZeroLengthStreams 1 /scomma %FS%\ads-d.csv"
	)
	goto:eof

:malware
	call:cmd %MAL%	svcs 		"tasklist /svc"
	call:cmd %MAL%	svcs 		"sc queryex"
	call:cmd %MAL%	svcs 		"%PSS% -accepteula"
	call:cmd %MAL%	tasks		"schtasks /query /FO csv /V"
	call:cmd %MAL%	proc		"%PSP% -accepteula"
	call:cmd %MAL%	proc		"%PSP% -accepteula -t"
	call:cmd %MAL%	drivers		"%DV% /sort ~12 /scomma %MAL%\drivers.csv"
	call:cmd %MAL%	drivers		"driverquery /FO csv /V"
	call:cmd %MAL%	dlls-unsign	"%PSD% -accepteula -r -v"
	call:cmd %MAL%	handles		"%PSH% -accepteula -a -u"
	call:cmd %MAL%	autoruns	"%AR% -accepteula -a * -c -h -s -t * | %TR% -dc '[:print:]\n'"
	call:cmd %MAL%	log ^
		"xcopy %SystemRoot%\Tasks %MAL%\Tasks /E /C /I /F /H /Y"
	call:cmd %MAL%	log ^
		"xcopy %SystemRoot%\system32\Tasks %MAL%\Tasks32 /E /C /I /F /H /Y"
	call:cmd %MAL%	log ^
		"xcopy %SystemRoot%\syswow64\Tasks %MAL%\Tasks64 /E /C /I /F /H /Y"
	for /L %%p in (1,1,%d%) do (
		for /F "tokens=3 delims=\" %%u in ("!profiles[%%p]!") do (
			call:ncmd	%MAL%	log	"xcopy Startup-%%u %MAL%\Startup-%%u /E /C /I /F /H /Y"
			xcopy "!profiles[%%p]!\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" %MAL%\Startup-%%u /C /I /F /H /Y >> %MAL%\log.txt 2>&1
			set "startup[%%p]=%MAL%\Startup-%%u"
		)
	)
	:: browser stuff
	:: reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /S
	:: reg query "HKLM\Software\Microsoft\Internet Explorer\Extensions" /S
	:: reg query "HKLM\Software\Microsoft\Internet Explorer\Toolbar" /S
	:: reg query "HKLM\Software\Wow6432Node\Google\Chrome" /S
	:: reg query "HKLM\Software\Wow6432Node\Google\Chrome\Extensions" /S
	:: reg query "HKLM\Software\Wow6432Node\Google\Mozilla" /S
	call:ncmd %MAL%	autorun 	"type *:\autorun.inf"
	for /F "delims=: tokens=1,*" %%a in ('fsutil fsinfo drives') do (
		for %%c in (%%b) do (
			type %%~dc\autorun.inf >> %MAL%\autorun.txt 2>&1
		)
	)
	goto:eof

:web
	call:cmd %WEB% web ^
		"%BHV% /HistorySource 1 /VisitTimeFilterType 1 /LoadIE 1 /LoadFirefox 1 /LoadChrome 1 /LoadSafari 0 /sort ~2 /scomma %WEB%\browsing-history.csv"
	call:cmd %WEB% web			"%IECV% /scomma %WEB%\cache-ie.csv"
	call:cmd %WEB% web			"%CCV% /scomma %WEB%\cache-chrome.csv"
	call:cmd %WEB% web			"%MCV% /scomma %WEB%\cache-mozilla.csv"
	call:cmd %WEB% web ^
		"%IECV% /copycache "" "" /CopyFilesFolder "%WEB%\cache-ie" /UseWebSiteDirStructure 0"
	call:cmd %WEB% web ^
		"%CCV% /copycache "" "" /CopyFilesFolder "%WEB%\cache-chrome" /UseWebSiteDirStructure 0"
	call:cmd %WEB% web ^
		"%MCV% /copycache "" "" /CopyFilesFolder "%WEB%\cache-mozilla" /UseWebSiteDirStructure 0"
	goto:eof

:misc
	call:cmd %MISC%	log			"%OI% /stext %MISC%\office-addins.txt"
	call:cmd %MISC%	log ^
		"%USB% /DisplayDisconnected 1 /DisplayNoPortSerial 1 /DisplayNoDriver 1 /RetrieveUSBPower /MarkConnectedDevices 1 /AddExportHeaderLine 1 /sort ~10 /scomma %MISC%\usb.csv"
	goto:eof

:sigcheck
	call:cmd %MAL%	sig-users ^
		"%SIG% -accepteula -nobanner -a -c -e -h -s C:\Users"
	call:cmd %MAL%	sig-prgdata ^
		"%SIG% -accepteula -nobanner -a -c -e -h -s %ProgramData%"
	call:cmd %MAL%	sig-temp ^
		"%SIG% -accepteula -nobanner -a -c -e -h -s %SystemRoot%\Temp"
	call:cmd %MAL%	sig-system32 ^
		"%SIG% -accepteula -nobanner -a -c -e -h %SystemRoot%\system32"
	call:cmd %MAL%	sig-system64 ^
		"%SIG% -accepteula -nobanner -a -c -e -h %SystemRoot%\syswow64"
	call:cmd %MAL%	sig-drivers32 ^
		"%SIG% -accepteula -nobanner -a -c -e -h %SystemRoot%\system32\drivers"
	call:cmd %MAL%	sig-drivers64 ^
		"%SIG% -accepteula -nobanner -a -c -e -h %SystemRoot%\syswow64\drivers"
	call:cmd %MAL%	sig-d ^
		"%SIG% -accepteula -nobanner -a -c -e -h -s D:\"
	goto:eof

:density
	call:cmd %MAL%	density-c ^
		"%DS% C:\Users -o %MAL%\density-users.txt | %TR% -dc '[:print:]\n'"
	call:cmd %MAL%	density-c ^
		"%DS% %ProgramData% -o %MAL%\density-prgdata.txt | %TR% -dc '[:print:]\n'"
	call:cmd %MAL%	density-c ^
		"%DS% %SystemRoot%\system32\ -o %MAL%\density-system32.txt | %TR% -dc '[:print:]\n'"
	call:cmd %MAL%	density-c ^
		"%DS% %SystemRoot%\syswow64\ -o %MAL%\density-syswow64.txt | %TR% -dc '[:print:]\n'"
	call:cmd %MAL%	density-c ^
		"%DS% %SystemRoot%\system32\drivers -o %MAL%\density-drivers32.txt | %TR% -dc '[:print:]\n'"
	call:cmd %MAL%	density-c ^
		"%DS% -r %SystemRoot%\syswow64\drivers -o %MAL%\density-drivers64.txt | %TR% -dc '[:print:]\n'"
	call:cmd %MAL%	density-d ^
		"%DS% -r D:\ -o %MAL%\density-d.txt | %TR% -dc '[:print:]\n'"
	goto:eof

:iconext
	call:ncmd %MAL%	icons ^
		"%IE% /save C:\Users\*.exe %MAL%\icons\users\exe\* -icons"
	for /F "tokens=*" %%p in ('dir /B /S C:\Users ^| findstr /I "^.*\.exe$"') do (
		%IE% /save %%p %MAL%\icons\users\exe\%%~np -icons >> %MAL%\icons.txt 2>&1
	)
	call:ncmd %MAL%	icons ^
		"%IE% /save C:\Users\*.dll %MAL%\icons\users\dll\* -icons"
	for /F "tokens=*" %%p in ('dir /B /S C:\Users ^| findstr /I "^.*\.dll$"') do (
		%IE% /save %%p %MAL%\icons\users\dll\%%~np -icons >> %MAL%\icons.txt 2>&1
	)
	call:ncmd %MAL%	icons ^
		"%IE% /save %ProgramData%\*.exe %MAL%\icons\prgdata\exe\* -icons"
	for /F "tokens=*" %%p in ('dir /B /S %ProgramData% ^| findstr /I "^.*\.exe$"') do (
		%IE% /save %%p %MAL%\icons\prgdata\exe\%%~np -icons >> %MAL%\icons.txt 2>&1
	)
	call:ncmd %MAL%	icons ^
		"%IE% /save %ProgramData%\*.dll %MAL%\icons\prgdata\dll\* -icons"
	for /F "tokens=*" %%p in ('dir /B /S %ProgramData% ^| findstr /I "^.*\.dll$"') do (
		%IE% /save %%p %MAL%\icons\prgdata\dll\%%~np -icons >> %MAL%\icons.txt 2>&1
	)
	call:ncmd %MAL%	icons ^
		"%IE% /save %SystemRoot%\Temp\*.exe %MAL%\icons\temp\exe\* -icons"
	for /F "tokens=*" %%p in ('dir /B /S %SystemRoot%\Temp ^| findstr /I "^.*\.exe$"') do (
		%IE% /save %%p %MAL%\icons\temp\exe\%%~np -icons >> %MAL%\icons.txt 2>&1
	)
	call:ncmd %MAL%	icons ^
		"%IE% /save %SystemRoot%\Temp\*.dll %MAL%\icons\temp\dll\* -icons"
	for /F "tokens=*" %%p in ('dir /B /S %SystemRoot%\Temp ^| findstr /I "^.*\.dll$"') do (
		%IE% /save %%p %MAL%\icons\temp\dll\%%~np -icons >> %MAL%\icons.txt 2>&1
	)
	call:ncmd %MAL%	icons ^
		"%IE% /save %SystemRoot%\system32\*.exe %MAL%\icons\system32\exe\* -icons"
	for /F "tokens=*" %%p in ('dir /B %SystemRoot%\system32 ^| findstr /I "^.*\.exe$"') do (
		%IE% /save %%p %MAL%\icons\system32\exe\%%~np -icons >> %MAL%\icons.txt 2>&1
	)
	call:ncmd %MAL%	icons ^
		"%IE% /save %SystemRoot%\system32\*.dll %MAL%\icons\system32\dll\* -icons"
	for /F "tokens=*" %%p in ('dir /B %SystemRoot%\system32 ^| findstr /I "^.*\.dll$" ^| findstr /V "imageres\.dll shell32\.dll"') do (
		%IE% /save %%p %MAL%\icons\system32\dll\%%~np -icons >> %MAL%\icons.txt 2>&1
	)
	call:ncmd %MAL%	icons ^
		"%IE% /save %SystemRoot%\syswow64\*.exe %MAL%\icons\syswow64\exe\* -icons"
	for /F "tokens=*" %%p in ('dir /B %SystemRoot%\syswow64 ^| findstr /I "^.*\.exe$"') do (
		%IE% /save %%p %MAL%\icons\syswow64\exe\%%~np -icons >> %MAL%\icons.txt 2>&1
	)
	call:ncmd %MAL%	icons ^
		"%IE% /save %SystemRoot%\syswow64\*.dll %MAL%\icons\syswow64\dll\* -icons"
	for /F "tokens=*" %%p in ('dir /B %SystemRoot%\syswow64 ^| findstr /I "^.*\.dll$" ^| findstr /V "imageres\.dll shell32\.dll"') do (
		%IE% /save %%p %MAL%\icons\syswow64\dll\%%~np -icons >> %MAL%\icons.txt 2>&1
	)
	goto:eof

:yara
	call:ncmd %MAL%	yara		"%YAR% -m ruleset.yar %SystemRoot%\system32\"
	call:ncmd %MAL%	yara		"%YAR% -m ruleset.yar %ProgramData%"
	call:ncmd %MAL%	yara		"%YAR% -m ruleset.yar C:\Users\"
	call:ncmd %MAL%	yara		"%YAR% -m ruleset.yar D:\"
	for /F "tokens=*" %%p in ('dir /B /S %TOOLS%\yara\rules\*.yar') do (
		%YAR% -m %%p %SystemRoot%\system32\ >> %MAL%\yara.txt 2>>%MAL%\yara.err
		%YAR% -m -r %%p %ProgramData% >> %MAL%\yara.txt 2>>%MAL%\yara.err
		%YAR% -m -r %%p C:\Users\ >> %MAL%\yara.txt 2>>%MAL%\yara.err
		%YAR% -m -r %%p D:\ >> %MAL%\yara.txt 2>>%MAL%\yara.err
	)
	goto:eof

:cmd
	call:date
	call:ncmd %1 %2 %3
	%~3 >> %~1\%~2.txt 2>&1
	goto:eof

:ncmd
	set /A n+=1
	echo  %datetime% running %n% out of %t%: %3
	echo  %datetime% running %n% out of %t%: %3 >> %LOG%
	echo. >> %~1\%~2.txt 
	echo %NAME%-%VER% %datetime% (%TZ%): %3 >> %~1\%~2.txt 
	echo. >> %~1\%~2.txt 
	goto:eof

:date
	if "%date%A" LSS "A" (set toks=1-3) else (set toks=2-4)
	for /f "tokens=2-4 delims=(-)" %%a in ('echo:^|date') do (
		for /f "tokens=%toks% delims=.-/ " %%i in ('date/t') do (
			set '%%a'=%%i
			set '%%b'=%%j
			set '%%c'=%%k
		)
	)
	if %'yy'% LSS 100 set 'yy'=20%'yy'%
	:: regional independent date
	set yyyymmdd=%'yy'%%'mm'%%'dd'%
	set datetime=%yyyymmdd% %TIME%
	goto:eof

:timestamp
	call:msg "%NAME%-%VER% %yyyymmdd% %TIME% (%TZ%)"
	goto:eof

:msg
	echo.&echo %~1
	echo. >> %LOG%
	echo %~1 >> %LOG%
	goto:eof

:ascii
	echo.&type %ASCII%
	echo. >> %LOG%
	type %ASCII% >> %LOG%
	echo. >> %LOG%
	goto:eof

:init
	echo.
	cd /d %~dp0

	:: variables
	call:date

	set NAME=ir-rescue
	set VER=v1.1
	set TOOLS=tools
	set SYSTEM=%COMPUTERNAME%-%yyyymmdd%

	set DATA=data
	set ROOT=%DATA%\%SYSTEM%
	set CFG=%TOOLS%\cfg
	set MEM=%ROOT%\mem
	set REG=%ROOT%\reg
	set EVT=%ROOT%\evt
	set SYS=%ROOT%\sys
	set NET=%ROOT%\net
	set FS=%ROOT%\fs
	set MAL=%ROOT%\mal
	set WEB=%ROOT%\web
	set MISC=%ROOT%\misc

	set LOG=%ROOT%\%NAME%.log

	set CONF=%CFG%\%NAME%.conf
	set TR=%TOOLS%\cygwin\tr.exe
	set SDEL=%TOOLS%\sdelete.exe
	set ZIP=%TOOLS%\7za.exe
	set /A c=0
	for %%f in (%TOOLS%\ascii\*.txt) do (
		set /A c+=1
		set "asciiart[!c!]=%%f"
	)
	set /A "rand=(%c%*%random%)/32768+1"
	set ASCII=!asciiart[%rand%]!
	if "%ASCII%" equ "" set ASCII=""

	set PMEM=%TOOLS%\mem\winpmem_1.6.2.exe
	set PLL=%TOOLS%\evt\psloglist.exe
	set PSI=%TOOLS%\sys\Psinfo.exe
	set PSLO=%TOOLS%\sys\psloggedon.exe
	set PSL=%TOOLS%\sys\logonsessions.exe
	set PSG=%TOOLS%\sys\PsGetsid.exe
	set AC=%TOOLS%\sys\accesschk.exe
	set TCPV=%TOOLS%\net\tcpvcon.exe
	set PSF=%TOOLS%\net\psfile.exe
	set NTFS=%TOOLS%\fs\ntfsinfo.exe
	set FLS=%TOOLS%\fs\tsk\fls.exe
	set ADS=%TOOLS%\fs\AlternateStreamView.exe
	set MD5=%TOOLS%\fs\md5deep.exe
	set PSP=%TOOLS%\mal\pslist.exe
	set PSS=%TOOLS%\mal\PsService.exe
	set DV=%TOOLS%\mal\DriverView.exe
	set PSD=%TOOLS%\mal\Listdlls.exe
	set PSH=%TOOLS%\mal\handle.exe
	set AR=%TOOLS%\mal\autorunsc.exe
	set WPV=%TOOLS%\mal\WinPrefetchView.exe
	set SIG=%TOOLS%\mal\sigcheck.exe
	set DS=%TOOLS%\mal\densityscout.exe
	set IE=%TOOLS%\mal\iconsext.exe
	set BHV=%TOOLS%\web\BrowsingHistoryView.exe
	set IECV=%TOOLS%\web\IECacheView.exe
	set CCV=%TOOLS%\web\ChromeCacheView.exe
	set MCV=%TOOLS%\web\MozillaCacheView.exe
	set LAV=%TOOLS%\misc\LastActivityView.exe
	set OI=%TOOLS%\misc\OfficeIns.exe
	set USB=%TOOLS%\misc\USBDeview.exe
	set YAR=%TOOLS%\yara\yara32.exe
	if exist "%PROGRAMFILES(X86)%" (
		set SDEL=%TOOLS%\sdelete64.exe
		set PSI=%TOOLS%\sys\PsInfo64.exe
		set PSLO=%TOOLS%\sys\PsLoggedon64.exe
		set PSL=%TOOLS%\sys\logonsessions64.exe
		set PSG=%TOOLS%\sys\PsGetsid64.exe
		set AC=%TOOLS%\sys\accesschk64.exe
		set PSF=%TOOLS%\net\psfile64.exe
		set NTFS=%TOOLS%\fs\ntfsinfo64.exe
		set ADS=%TOOLS%\fs\AlternateStreamView64.exe
		set MD5=%TOOLS%\fs\md5deep64.exe
		set PSD=%TOOLS%\mal\Listdlls64.exe
		set PSP=%TOOLS%\mal\pslist64.exe
		set PSS=%TOOLS%\mal\PsService64.exe
		set DV=%TOOLS%\mal\DriverView64.exe
		set PSH=%TOOLS%\mal\handle64.exe
		set AR=%TOOLS%\mal\autorunsc64.exe
		set WPV=%TOOLS%\mal\WinPrefetchView64.exe
		set SIG=%TOOLS%\mal\sigcheck64.exe
		set DS=%TOOLS%\mal\densityscout64.exe
		set BHV=%TOOLS%\web\BrowsingHistoryView64.exe
		set OI=%TOOLS%\misc\OfficeIns64.exe
		set USB=%TOOLS%\misc\USBDeview64.exe
		set YAR=%TOOLS%\yara\yara64.exe
	)

	:: timezone
	for /f "usebackq tokens=*" %%a in (`tzutil /g`) do set TZ=%%a

	cls
	echo.&echo   initializing...
	set /A f=0

	:: check tools
	if not exist %CONF%	 (echo.&echo  ERROR: %CONF% not found. & set /A f=1)
	if not exist %TR%	 (echo.&echo  ERROR: %TR% not found. & set /A f=1)
	if not exist %SDEL%	 (echo.&echo  ERROR: %SDEL% not found. & set /A f=1)
	if not exist %ZIP%	 (echo.&echo  ERROR: %ZIP% not found. & set /A f=1)
	if not exist %ASCII% (echo.&echo  ERROR: %ASCII% not found. & set /A f=1)

	if not exist %PMEM%	 (echo.&echo  ERROR: %PMEM% not found. & set /A f=1)
	if not exist %PLL%	 (echo.&echo  ERROR: %PLL% not found. & set /A f=1)
	if not exist %PSI%	 (echo.&echo  ERROR: %PSI% not found. & set /A f=1)
	if not exist %PSLO%	 (echo.&echo  ERROR: %PSLO% not found. & set /A f=1)
	if not exist %PSL%	 (echo.&echo  ERROR: %PSL% not found. & set /A f=1)
	if not exist %PSG%	 (echo.&echo  ERROR: %PSG% not found. & set /A f=1)
	if not exist %AC%	 (echo.&echo  ERROR: %AC% not found. & set /A f=1)
	if not exist %TCPV%	 (echo.&echo  ERROR: %TCPV% not found. & set /A f=1)
	if not exist %PSF%	 (echo.&echo  ERROR: %PSF% not found. & set /A f=1)
	if not exist %NTFS%	 (echo.&echo  ERROR: %NTFS% not found. & set /A f=1)
	if not exist %FLS%	 (echo.&echo  ERROR: %FLS% not found. & set /A f=1)
	if not exist %ADS%	 (echo.&echo  ERROR: %ADS% not found. & set /A f=1)
	if not exist %MD5%	 (echo.&echo  ERROR: %MD5% not found. & set /A f=1)
	if not exist %PSP%	 (echo.&echo  ERROR: %PSP% not found. & set /A f=1)
	if not exist %PSS%	 (echo.&echo  ERROR: %PSS% not found. & set /A f=1)
	if not exist %DV%	 (echo.&echo  ERROR: %DV% not found. & set /A f=1)
	if not exist %PSD%	 (echo.&echo  ERROR: %PSD% not found. & set /A f=1)
	if not exist %PSH%	 (echo.&echo  ERROR: %PSH% not found. & set /A f=1)
	if not exist %AR%	 (echo.&echo  ERROR: %AR% not found. & set /A f=1)
	if not exist %WPV%	 (echo.&echo  ERROR: %WPV% not found. & set /A f=1)
	if not exist %SIG%	 (echo.&echo  ERROR: %SIG% not found. & set /A f=1)
	if not exist %DS%	 (echo.&echo  ERROR: %DS% not found. & set /A f=1)
	if not exist %IE%	 (echo.&echo  ERROR: %IE% not found. & set /A f=1)
	if not exist %BHV%	 (echo.&echo  ERROR: %BHV% not found. & set /A f=1)
	if not exist %IECV%	 (echo.&echo  ERROR: %IECV% not found. & set /A f=1)
	if not exist %CCV%	 (echo.&echo  ERROR: %CCV% not found. & set /A f=1)
	if not exist %MCV%	 (echo.&echo  ERROR: %MCV% not found. & set /A f=1)
	if not exist %LAV%	 (echo.&echo  ERROR: %LAV% not found. & set /A f=1)
	if not exist %OI%	 (echo.&echo  ERROR: %OI% not found. & set /A f=1) 
	if not exist %USB%	 (echo.&echo  ERROR: %USB% not found. & set /A f=1)
	if not exist %YAR%	 (echo.&echo  ERROR: %YAR% not found. & set /A f=1)

	if %f% equ 0 (
		icacls . /grant Everyone:"(OI)(CI)F" /T > NUL 2>&1

		call:rconf %conf% killself ckillself
		call:rconf %conf% sdelete csdel
		call:rconf %conf% zip czip
		call:rconf %conf% ascii cascii
		call:rconf %conf% memory cmem
		call:rconf %conf% registry creg
		call:rconf %conf% events cevt
		call:rconf %conf% system csys
		call:rconf %conf% network cnet
		call:rconf %conf% filesystem cfs
		call:rconf %conf% malware cmal
		call:rconf %conf% web cweb
		call:rconf %conf% misc cmisc
		call:rconf %conf% filesystem-simple cfs-simple
		call:rconf %conf% sigcheck csigcheck
		call:rconf %conf% density cdensity
		call:rconf %conf% iconext ciconext
		call:rconf %conf% yara cyara

		call:clean "%DATA%" "rmdir" "NUL"
		call:clean "%SYSTEM%.7z" "rmdir" "NUL"

		set /A n=0
		set /A t=0

		set /A c=3
		set /A d=0
		set /A e=0

		set "users[1]=Administrator"
		set "users[2]=Guest"
		set "users[3]=HomeGroupUser$"
		for /F "tokens=3,*" %%p in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" /S /V ProfileImagePath ^| findstr "ProfileImagePath" ^| findstr /v "ServiceProfiles" ^| findstr /v "system32"') do (
			set /A c+=1
			set /A d+=1
			set "profiles[!d!]=%%p"
			for /F "tokens=3 delims=\" %%u in ("%%p") do (
				set "users[!c!]=%%u"
			)
		)

		mkdir %DATA% %ROOT%

		if !cascii! equ false	set ASCII=%TOOLS%\ascii\cyb.txt
		if !cmem! equ true		mkdir %MEM% & set /A t+=1
		if !creg! equ true (
			mkdir %REG% %REG%\hives
			set /A t+=2
			for /F "tokens=*" %%p in ('reg query HKU') do (
				set /A t+=1
			)
		)
		if !cevt! equ true		mkdir %EVT% %EVT%\evtx & set /A t+=8
		if !csys! equ true		mkdir %SYS% & set /A t+=21+!c!+!c!
		if !cnet! equ true		mkdir %NET% & set /A t+=17
		if !cfs! equ true (
			mkdir %FS%
			for %%f in (c d e f g h i j k l m n o p q r s t u v w x y z) DO (
				if exist %%f: (
					set /A e+=1
					set "driveslc[!e!]=%%f"
				)
			)
			set /A e=0
			for %%f in (C D E F G H I J K L M N O P Q R S T U V W X Y Z) DO (
				if exist %%f: (
					set /A e+=1
					set "drivesuc[!e!]=%%f"
				)
			)
			set /A t+=8+!e!+7
			if !cfs-simple! equ true set /A t=t+!e!-7
		)
		if !cmal! equ true (
			mkdir %MAL% %MAL%\Prefetch %MAL%\icons
			set /A t+=2+15+!d!
		)
		if !cweb! equ true (
			mkdir %WEB% %WEB%\cache-chrome %WEB%\cache-ie %WEB%\cache-mozilla
			set /A t+=7
		)
		if !cmisc! equ true 	mkdir %MISC% & set /A t+=1+2
		if !csigcheck! equ true (
			mkdir %MAL% > NUL 2>&1
			set /A t+=8
		)
		if !cdensity! equ true (
			mkdir %MAL% > NUL 2>&1
			set /A t+=7
		)
		if !ciconext! equ true (
			mkdir %MAL% %MAL%\icons > NUL 2>&1
			set /A t+=10
		)
		if !cyara! equ true (
			mkdir %MAL% > NUL 2>&1
			set /A t+=4
		)
	)
	exit /B %f%

:end
	call:timestamp
	call:msg "  compressing data and cleaning up..."

	:: delete Sysinternals registry keys?
	:: delete prefetch files?
	:: what other evidence pollutes the system?

	icacls . /grant Everyone:"(OI)(CI)F" /T >> %LOG% 2>&1
	attrib -H set.txt.tmp >> %LOG% 2>&1

	:: delete empty icon folders before compressing
	if %cmal% equ true (
		for /f %%d in ('dir /A:D /B /S .\%MAL%\icons ^| sort /R') do (
			call:clean "%%d" "rmdir"
		)
	)

	if %cmem% equ true		%ZIP% a -tzip %MEM%\raw.mem.zip .\%MEM%\raw.mem >> %LOG% 2>&1
	if %creg% equ true		%ZIP% a -tzip -xr"^!.*" %REG%\hives.zip .\%REG%\hives >> %LOG% 2>&1
	if %cevt% equ true (
		%ZIP% a -tzip -xr"^!.*" %EVT%\evtx.zip .\%EVT%\evtx >> %LOG% 2>&1
		%ZIP% a -tzip -xr"^!evt.txt" %EVT%\txt.zip .\%EVT%\*.txt >> %LOG% 2>&1
	)
	if %cmal% equ true (
		%ZIP% a -tzip -xr"^!.*" %MAL%\Prefetch.zip .\%MAL%\Prefetch >> %LOG% 2>&1
		%ZIP% a -tzip -xr"^!.*" %MAL%\Tasks.zip .\%MAL%\Tasks >> %LOG% 2>&1
		%ZIP% a -tzip -xr"^!.*" %MAL%\Tasks.zip .\%MAL%\Tasks32 >> %LOG% 2>&1
		if exist %MAL%\Tasks64 (
			%ZIP% a -tzip -xr"^!.*" %MAL%\Tasks.zip .\%MAL%\Tasks64 >> %LOG% 2>&1
		)
		for /L %%p in (1,1,%d%) do (
			%ZIP% a -t7z -xr"^!.*" -pinfected %MAL%\Startup.7z .\!startup[%%p]! >> %LOG% 2>&1
		)
		if %ciconext% equ true (
			%ZIP% a -tzip -xr"^!.*" %MAL%\icons.zip .\%MAL%\icons >> %LOG% 2>&1
		)
	)
	if %cweb% equ true (
		%ZIP% a -t7z -xr"^!.*" -pinfected %WEB%\cache-chrome.7z .\%WEB%\cache-chrome >> %LOG% 2>&1
		%ZIP% a -t7z -xr"^!.*" -pinfected %WEB%\cache-ie.7z .\%WEB%\cache-ie >> %LOG% 2>&1
		%ZIP% a -t7z -xr"^!.*" -pinfected %WEB%\cache-mozilla.7z .\%WEB%\cache-mozilla >> %LOG% 2>&1
	)

	icacls . /grant Everyone:"(OI)(CI)F" /T >> %LOG% 2>&1

	call:clean "set.txt.tmp" "del"
	if %cmem% equ true		call:clean "%MEM%\raw.mem" "del"
	if %creg% equ true		call:clean "%REG%\hives" "rmdir"
	if %cevt% equ true (
		call:clean "%EVT%\evtx" "rmdir"
		call:clean "%EVT%\Application.txt" "del"
		call:clean "%EVT%\Security.txt" "del"
		call:clean "%EVT%\Setup.txt" "del"
		call:clean "%EVT%\System.txt" "del"
	)
	if %cmal% equ true (
		call:clean "%MAL%\Prefetch" "rmdir"
		call:clean "%MAL%\Tasks" "rmdir"
		call:clean "%MAL%\Tasks32" "rmdir"
		call:clean "%MAL%\Tasks64" "rmdir"
		for /L %%p in (1,1,%d%) do (
			call:clean "!startup[%%p]!" "rmdir"
		)
		call:clean "%MAL%\icons" "rmdir"
	)
	if %cweb% equ true (
		call:clean "%WEB%\cache-chrome" "rmdir"
		call:clean "%WEB%\cache-ie" "rmdir"
		call:clean "%WEB%\cache-mozilla" "rmdir"
	)

	icacls . /grant Everyone:"(OI)(CI)F" /T >> %LOG% 2>&1

	call:timestamp
	call:msg "  finishing..."
	call:ascii

	if %czip% equ true (
		%ZIP% a -t7z -xr"^!.*" -pinfected -mhe %SYSTEM%.7z .\%ROOT% > NUL 2>&1
	)
	if %ckillself% equ true (
		call:clean "%DATA%" "rmdir" "NUL"
		call:clean "%TOOLS%" "rmdir" "NUL"
		if %csdel% equ true (
			rmdir /Q /S .\%TOOLS% >> NUL 2>&1
		)
	)
	echo.&echo.&echo.&echo terminus / end / fin / fim / fine / einde / koniec
	chcp 437 > NUL 2>&1
	set /P null=
	goto:eof

:clean
	set out=%LOG%
	if not "%~3" equ "" set out=NUL
	if %csdel% equ true (
		%SDEL% -accepteula -s .\%~1 >> %out% 2>&1
	) else (
		%~2 /Q /S .\%~1 >> %out% 2>&1
	)
	goto:eof

:rconf
	for /F "eol=# tokens=1,2* delims==" %%i in ('findstr /B /I /L "%~2=" %1') DO (
		set %~3=%%~j
	)
	if %~3 equ "" set %~3=false
	goto:eof

:help
	echo.&echo Usage: %~nx0
	echo.
	echo Output: text  files  per each  command executed  organized according to
	echo data type.
	echo.
	echo ir-rescue  is a batch script for collecting  incident  response data on
	echo Windows systems.  It uses third-party utilities kept in a folder called
	echo 'tools' under '%NAME%\tools\'.
	echo.
	echo Needs administrator rights to run.
	set /P null=
	goto:eof

:: Windows Scripting
:: PowerShell and WMI

:: TZWorks pescan
:: TZWorks ntfswalk, ntfscopy
:: TZWorks LNK Parsing
:: Copy C:\$MFT, all registry files (including NTUSER.dat and UsrClass.dat)
:: Redline comprehensive collector

:; RegRipper

:: *.lnk
:: Sysinternals junctions

:: BHO, browser addons
:: copy from paths

:: ShimCache in memory?
:: What other registry is loaded only in memory?

:: timestomping