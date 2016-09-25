@echo off

:: author:	Diogo A. B. Fernandes
:: contact:	diogoabfernandes@gmail.com
:: license:	see LICENSE

:main
	:: start local variable environment
	setlocal ENABLEDELAYEDEXPANSION

	:: check for arguments
	set /A iargs=0
	for %%i in (%*) do set /A iargs+=1
	if not %iargs% equ 0 (
		echo.&echo  ERROR: too many arguments [%iargs%].
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
	:: "set /A" does not handle signed numbers larger than 32-bit in precision
	:: several workarounds, too complicated

	:: "set" before everything else
	del /A:H /F /Q .\set.txt.tmp > NUL 2>&1
	set > set.txt.tmp 2>&1
	attrib +H set.txt.tmp > NUL 2>&1

	call:init
	if not %errorLevel% equ 0 (
		attrib -H set.txt.tmp > NUL 2>&1
		del /Q .\set.txt.tmp > NUL 2>&1
		call:help
		exit /B 1
	)

:run
	cls
	:: The command line window character set enconding is based on MS-DOS, which
	:: is independent of the enconding used by Windows subsystems.  The codepage
	:: thus needs to be changed to UTF-8 in order to account for file names in
	:: multiple languages.
	chcp 65001 > NUL 2>&1

	call:msg "%~pdnx0"
	call:cmdln	"%LOG%" "type %CONF%"
	call:msg " %LOGONSERVER%  %COMPUTERNAME%  %USERDOMAIN%\%USERNAME%"
	call:timestamp
	echo.

	call:screenshot

	if %cmem% equ true			call:memory

	if %cmal% equ true (
		if !cmal-pf! equ true (
			call:cmd %MAL%	log ^
				"xcopy %SystemRoot%\Prefetch\*.pf %MAL%\Prefetch\ /C /I /F /H /Y"
			call:cmdn %MAL%	log ^
				"%WPV% /prefetchfile %SystemRoot%\Prefetch\*.pf /sort ~7 /scomma %MAL%\Prefetch\*.csv"
			for /F "tokens=*" %%i in ('dir /B /S %SystemRoot%\Prefetch\*.pf') do (
				%WPV% /prefetchfile %%i /sort ~7 /scomma %MAL%\Prefetch\%%~ni.csv >> %MAL%\log.txt 2>&1
			)
		)
	)

	if %creg% equ true			call:registry

	if %cmisc% equ true (
		if !cmisc-mtl! equ true (
			call:cmd %MISC%	log		"%LAV% /scomma %MISC%\last-activity.csv"
		)
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
	if %ciconsext% equ true		call:iconsext
	if %cyara% equ true			call:yara

	call:end
	:: end local variable environment
	endlocal
	:: exit and delete self
	:: if %ckillself% equ true		goto 2>NUL & del /F /Q %~f0
	exit /B 0

:memory
	if %cmem-dump% equ true (
		call:cmd %MEM%	log		"%PMEM% -d %TEMP%\pmem.tmp %MEM%\raw.mem"
	)
	:: "dir /A /B /S %SystemDrive%\ | findstr /L pagefile.sys"
	if %cmem-pf% equ true (
		call:cmd %MEM%	log ^
			"%RCP% /FileNamePath:%SystemDrive%\pagefile.sys /OutputPath:%MEM%"
	)
	if %cmem-md% equ true (
		call:cmd %MEM%	log ^
			"xcopy %SystemRoot%\Minidump %MEM%\Minidump /C /I /F /H /S /Y"
	)
	:: `%SystemRoot%\MEMORY.DMP`
	goto:eof

:registry
	if %creg-sys% equ true (
		call:cmd %REG%	log ^
			"%RCP% /FileNamePath:%SystemRoot%\System32\config\SAM /OutputPath:%REG%\sys"
		call:cmd %REG%	log ^
			"%RCP% /FileNamePath:%SystemRoot%\System32\config\SECURITY /OutputPath:%REG%\sys"
		call:cmd %REG%	log ^
			"%RCP% /FileNamePath:%SystemRoot%\System32\config\SOFTWARE /OutputPath:%REG%\sys"
		call:cmd %REG%	log ^
			"%RCP% /FileNamePath:%SystemRoot%\System32\config\SYSTEM /OutputPath:%REG%\sys"
	)
	if %creg-user% equ true (
		for /L %%i in (1,1,%ip%) do (
			call:cmd %REG%	log ^
				"%RCP% /FileNamePath:!profiles[%%i]!\NTUSER.dat /OutputPath:%REG%\user\"
			call:cmd %REG%	log ^
				"%RCP% /FileNamePath:!profiles[%%i]!\AppData\Local\Microsoft\Windows\UsrClass.dat /OutputPath:%REG%\user\"
			ren "%REG%\user\NTUSER.dat" NTUSER-!usersp[%%i]!.dat
			ren "%REG%\user\UsrClass.dat" UsrClass-!usersp[%%i]!.dat
		)
	)
	:: for /F "tokens=*" %%p in ('reg query HKU') do (
	::	set key=%%p
	::	set key=!key:\=-!.txt
	::	call:cmd %REG% log		"reg export %%p %REG%\hives\!key!"
	:: )
	goto:eof

:events
	:: call:cmd %EVT%	log ^
	::	"xcopy %SystemRoot%\System32\winevt\logs\Security.evtx %EVT%\ /C /I /F /H /Y"
	if %cevt-evtx% equ true (
		call:cmd %EVT%	log		"%PLL% -accepteula -g %EVT%\evtx\Security.evtx Security"
		call:cmd %EVT%	log		"%PLL% -accepteula -g %EVT%\evtx\System.evtx System"
		call:cmd %EVT%	log		"%PLL% -accepteula -g %EVT%\evtx\Application.evtx Application"
		call:cmd %EVT%	log		"%PLL% -accepteula -g %EVT%\evtx\Setup.evtx Setup"
	)
	if %cevt-txt% equ true (
		call:cmd %EVT%	txt\Security	"%PLL% -accepteula -s -x Security"
		call:cmd %EVT%	txt\System		"%PLL% -accepteula -s -x System"
		call:cmd %EVT%	txt\Application	"%PLL% -accepteula -s -x Application"
		call:cmd %EVT%	txt\Setup		"%PLL% -accepteula -s -x Setup"
	)
	goto:eof

:system
	:: "setx /?"
	if %csys-info% equ true (
		call:cmd %SYS%	sys		"hostname"
		call:cmd %SYS%	sys		"ver"
		call:cmd %SYS%	sys		"type set.txt.tmp"
		call:cmd %SYS%	sys		"systeminfo"
		call:cmd %SYS%	sys		"%PSI% -accepteula -h -s -d"
	)
	goto:eof

:system-contd
	if %csys-acc% equ true (
		call:cmd %SYS%	acc		"%PSLO% -accepteula"
		call:cmd %SYS%	acc		"%PSL% -accepteula -c -p"
		call:cmd %SYS%	acc		"whoami"
		call:cmd %SYS%	acc		"net accounts"
		call:cmd %SYS%	acc		"net localgroup"
		call:cmd %SYS%	acc		"net localgroup Administrators"
		call:cmd %SYS%	acc		"net localgroup Users"
		call:cmd %SYS%	acc		"net localgroup HomeUsers"
		call:cmd %SYS%	acc		"net localgroup Guests"
		call:cmd %SYS%	sid		"%PSG% -accepteula \\%COMPUTERNAME%"
		for /L %%i in (1,1,%iu%) do (
			net user !users[%%i]! /domain %USERDOMAIN% > NUL 2>&1
			:: if ERRORLEVEL 2
			if not !errorLevel! equ 0 (
				call:cmd %SYS%	acc	"net user !users[%%i]!"
			) else (
				call:cmd %SYS%	acc	"net user !users[%%i]! /domain %USERDOMAIN%"
			)
			call:cmd %SYS%	sid		"%PSG% -accepteula !users[%%i]!"
		)
	)
	:: "icacls %SystemDrive%\Users\* /C"
	if %csys-acl% equ true (
		call:cmdn %SYS%	acl			"%AC% -accepteula -d -l %CFG%\nonrecursive-acl"
		for /F %%i in (%CFG%\nonrecursive-accesschk.txt) do (
			call:cmdr %SYS%	acl		"%AC% -accepteula -d -l %%i"
		)
		call:cmdn %SYS%	acl			"%AC% -accepteula -l %CFG%\recursive-acl"
		for /F %%i in (%CFG%\recursive-accesschk.txt) do (
			call:cmdr %SYS%	acl		"%AC% -accepteula -l %%i"
		)
	)
	goto:eof

:network
	call:cmd %NET%	ip			"ipconfig /all"
	call:cmd %NET%	ip			"ipconfig /displaydns"
	call:cmd %NET%	conn		"netstat -abno"
	:: NirSoft CurrPorts "cports.exe"
	call:cmd %NET%	conn		"%TCPV% -accepteula -a -n -c"
	:: "nmap -sn --traceroute www.google.com"
	:: nping, ncat
	:: no portable versions
	call:cmd %NET%	conn		"ping -a -n 1 www.google.com"
	call:cmd %NET%	conn		"tracert -h 16 -w 256 www.google.com"
	call:cmd %NET%	netbios		"nbtstat -c"
	call:cmd %NET%	netbios		"nbtstat -n"
	call:cmd %NET%	netbios		"nbtstat -S"
	:: "netstat -nr"
	call:cmd %NET%	tables		"route print"
	call:cmd %NET%	tables		"arp -a"
	call:cmd %NET%	net			"net use"
	call:cmd %NET%	net			"net view"
	call:cmd %NET%	net			"net sessions"
	call:cmd %NET%	shares		"net files"
	call:cmd %NET%	shares		"openfiles"
	call:cmd %NET%	shares		"%PSF% -accepteula"
	call:cmd %NET%	log ^
		"xcopy %SystemRoot%\System32\drivers\etc\hosts %NET%\ /C /I /F /H /Y"
	call:cmd %NET%	log ^
		"xcopy %SystemRoot%\System32\drivers\etc\lmhosts.sam %NET%\ /C /I /F /H /Y"
	goto:eof

:filesystem
	if %cfs-ntfs% equ true (
		call:cmd %FS%	ntfs	"reg query HKLM\SYSTEM\CurrentControlSet\Control\FileSystem /S"
		call:cmd %FS%	ntfs	"fsutil fsinfo drives"
		for /L %%i in (1,1,%id%) do (
			call:cmd %FS%	ntfs	"fsutil fsinfo ntfsinfo !drivesuc[%%i]!:\"
			call:cmd %FS%	ntfs	"%NTFS% -accepteula !drivesuc[%%i]!:\"
		)
	)
	:: "reg query HKLM\System\CurrentControlSet\Services\VSS"
	if %cfs-vss% equ true (
		call:cmd %FS%	vss		"vssadmin list volumes"
		call:cmd %FS%	vss		"vssadmin list shadows"
		call:cmd %FS%	vss		"vssadmin list shadowstorage"
	)
	if %cfs-dfull% equ true (
		for /L %%i in (1,1,%id%) do (
			call:cmd %FS%	dir-!driveslc[%%i]!-m	"dir /A /O:D /Q /T:W /R /S !drivesuc[%%i]!:\"
		)
	)
	if %cfs-dplain% equ true (
		for /L %%i in (1,1,%id%) do (
			call:cmd %FS%	dir-!driveslc[%%i]!	"dir /A /B /S !drivesuc[%%i]!:\"
		)
	)
	:: Win32 device namespace (`NamedPipe`)
	if %cfs-fls% equ true (
		for /L %%i in (1,1,%id%) do (
			call:cmd %FS%	fls-!driveslc[%%i]!	"%FLS% -l -p -r \\.\!drivesuc[%%i]!:"
		)
		call:cmd %FS%	bin		"type %FS%\fls-c.txt | findstr $Recycle.Bin"
	)
	if %cfs-md5% equ true (
		call:cmd %FS%	md5-nr	"%MD5% -f %CFG%\nonrecursive-md5deep.txt -s -t -z | sort /+67"
		call:cmd %FS%	md5-r	"%MD5% -f %CFG%\recursive-md5deep.txt -r -s -t -z | sort /+67"
	)
	if %cfs-ads% equ true (
		call:cmd %FS%	log ^
			"%ADS% /FolderPath %SystemDrive% /ScanSubfolders 1 /SubFolderDept 0 /ShowZeroLengthStreams 1 /scomma %FS%\ads-c.csv"
		call:cmd %FS%	log ^
			"%ADS% /FolderPath D:\ /ScanSubfolders 1 /SubFolderDept 0 /ShowZeroLengthStreams 1 /scomma %FS%\ads-d.csv"
	)
	if %cfs-mft% equ true (
		call:cmd %FS%	log		"%RCP% /FileNamePath:C:0 /OutputPath:%FS%"
	)
	if %cfs-log% equ true (
		call:cmd %FS%	log		"%RCP% /FileNamePath:C:2 /OutputPath:%FS%"
	)
	if %cfs-jrnl% equ true (
		call:cmd %FS%	log		"%EUJ% /DevicePath:C: /OutputPath:%~dp0\%FS%"
	)
	:: Sysinternals junctions
	:: Sysinternals streams64.exe -s %SystemDrive% | findstr /C:"Error opening" /V | findstr /C:"The system cannot find the path specified." /V | findstr /R /V "^$"
	goto:eof

:malware
	:: "findstr /C:DisplayName /C:ImagePath /C:ServiceDll /L | findstr /V ServiceDllUnloadOnStop"
	if %cmal-proc% equ true (
		call:cmd %MAL%	proc		"%PSP% -accepteula"
		call:cmd %MAL%	proc		"%PSP% -accepteula -t"
		call:cmd %MAL%	proc		"tasklist /V"
		call:cmd %MAL%	proc		"tasklist /M"
		call:cmd %MAL%	handles		"%PSH% -accepteula -a -u"
	)
	if %cmal-drvs% equ true (
		call:cmd %MAL%	drivers		"%DV% /sort ~12 /scomma %MAL%\drivers.csv"
		call:cmd %MAL%	drivers		"driverquery /FO csv /V"
	)
	if %cmal-dlls% equ true (
		call:cmdn %MAL%	dlls-known	"reg query HKLM\System\CurrentControlSet\Control\Session Manager\KnownDLLs /S"
		reg query "HKLM\System\CurrentControlSet\Control\Session Manager\KnownDLLs" /S >> %MAL%\dlls-known.txt 2>&1
		call:cmd %MAL%	dlls-unsign	"%PSD% -accepteula -r -v"
	)
	if %cmal-svcs% equ true (
		call:cmdn %MAL%	svcs	"reg query HKLM\System\CurrentControlSet\Services /S | %GREP% -E 'DisplayName|ImagePath|ServiceDll'"
		reg query HKLM\System\CurrentControlSet\Services\ /S | %GREP% -E "HKEY_LOCAL_MACHINE\\\\System\\\\CurrentControlSet\\\\Services\\\\|DisplayName|ImagePath|ServiceDll" | %GREP% -F -v "ServiceDllUnloadOnStop" >> %MAL%\svcs.txt 2>&1
		call:cmd %MAL%	svcs	"tasklist /svc"
		call:cmd %MAL%	svcs	"sc queryex"
		call:cmd %MAL%	svcs	"%PSS% -accepteula"
	)
	if %cmal-tasks% equ true (
		call:cmd %MAL%	tasks	"schtasks /query /FO csv /V"
		call:cmd %MAL%	log ^
			"xcopy %SystemRoot%\Tasks %MAL%\Tasks /E /C /I /F /H /Y"
		call:cmd %MAL%	log ^
			"xcopy %SystemRoot%\System32\Tasks %MAL%\Tasks32 /E /C /I /F /H /Y"
		if exist "%PROGRAMFILES(X86)%" (
			call:cmd %MAL%	log ^
				"xcopy %SystemRoot%\SysWOW64\Tasks %MAL%\Tasks64 /E /C /I /F /H /Y"
		)
	)
	if %cmal-ar% equ true (
		call:cmd %MAL%	autoruns	"%AR% -accepteula -a %MAL%\autoruns\autoruns.arn"
		call:cmd %MAL%	autoruns\autoruns	"%ARC% -accepteula -a * -c -h -s -t * | %TR% -dc '[:print:]\n'"
		call:cmdn %MAL%	autorun.inf	"type *:\autorun.inf"
		for /F "delims=: tokens=1,*" %%i in ('fsutil fsinfo drives') do (
			for %%a in (%%j) do (
				call:cmdln "%MAL%\autoruns\autorun.inf.txt"	"type %%~da\autorun.inf"
			)
		)
	)
	:: "findstr /C:'    H' /C:'   S' /C:'   SH' /C:'A   H' /C:'A  S' /C:'A  SH'"
	if %cmal-hid% equ true (
		call:cmdn %MAL%\hidden	dir-hidden		"dir /A:HS /O:D /Q [/S] /T:W *"
		call:cmdn %MAL%\hidden	attrib-hidden	"attrib /L [/D /S] *"
		for /F %%i in (%CFG%\nonrecursive.txt) do (
			call:cmdr %MAL%\hidden	dir-hidden		"dir /A:HS /O:D /Q /T:W %%i"
			call:cmdr %MAL%\hidden	attrib-hidden	"attrib %%i\* /L | %GREP% -E '^A?\s{2,4}[SH]{1,2}.+$'"
		)
		for /F %%i in (%CFG%\recursive.txt) do (
			call:cmdr %MAL%\hidden	dir-hidden		"dir /A:HS /O:D /Q /S /T:W %%i"
			call:cmdr %MAL%\hidden	attrib-hidden	"attrib %%i\* /D /L /S | %GREP% -E '^A?\s{2,4}[SH]{1,2}.+$'"
		)
	)
	if %cmal-startup% equ true (
		call:cmdn %MAL%	log ^
			"xcopy *\Startup %MAL%\Startup-* /E /C /I /F /H /Y"
		for /L %%i in (1,1,%ip%) do (
			xcopy "!startup[%%i]!" %MAL%\Startup-!usersp[%%i]! /C /I /F /H /Y >> %MAL%\log.txt 2>&1
			set "startupx[%%i]=%MAL%\Startup-!usersp[%%i]!" > NUL 2>&1
		)
	)
	if %cmal-cache% equ true (
		call:cmd %MAL%	log ^
			"xcopy %SystemRoot%\AppCompat\Programs\RecentFileCache.bcf %MAL%\cache /C /I /F /H /Y"
		call:cmd %MAL%	log ^
			"%RCP% /FileNamePath:%SystemRoot%\AppCompat\Programs\Amcache.hve /OutputPath:%MAL%\cache"
	)
	:: browser stuff
	:: "reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /S"
	:: "reg query "HKLM\Software\Microsoft\Internet Explorer\Extensions" /S"
	:: "reg query "HKLM\Software\Microsoft\Internet Explorer\Toolbar" /S"
	:: "reg query "HKLM\Software\Wow6432Node\Google\Chrome" /S"
	:: "reg query "HKLM\Software\Wow6432Node\Google\Chrome\Extensions" /S"
	:: "reg query "HKLM\Software\Wow6432Node\Google\Mozilla" /S"
	goto:eof

:web
	if %cweb-hist% equ true (
		call:cmd %WEB% log ^
			"%BHV% /HistorySource 1 /VisitTimeFilterType 1 /LoadIE 1 /LoadFirefox 1 /LoadChrome 1 /LoadSafari 0 /sort ~2 /scomma %WEB%\browsing-history.csv"
	)
	if %cweb-chrome% equ true (
		call:cmd %WEB% log		"%CCV% /scomma %WEB%\cache-chrome.csv"
		call:cmdn %WEB% log		"%CCV% /copycache /CopyFilesFolder %WEB%\cache-chrome /UseWebSiteDirStructure 0"
		%CCV% /copycache "" "" /CopyFilesFolder "%WEB%\cache-chrome" /UseWebSiteDirStructure 0 >> %WEB%\log.txt 2>&1
	)
	if %cweb-ie% equ true (
		call:cmd %WEB% log		"%IECV% /scomma %WEB%\cache-ie.csv"
		call:cmdn %WEB% log		"%IECV% /copycache /CopyFilesFolder %WEB%\cache-ie /UseWebSiteDirStructure 0"
		%IECV% /copycache "" "" /CopyFilesFolder "%WEB%\cache-ie" /UseWebSiteDirStructure 0 >> %WEB%\log.txt 2>&1
	)
	if %cweb-moz% equ true (
		call:cmd %WEB% log		"%MCV% /scomma %WEB%\cache-mozilla.csv"
		call:cmdn %WEB% log		"%MCV% /copycache /CopyFilesFolder %WEB%\cache-mozilla /UseWebSiteDirStructure 0"
		%MCV% /copycache "" "" /CopyFilesFolder "%WEB%\cache-mozilla" /UseWebSiteDirStructure 0 >> %WEB%\log.txt 2>&1
	)
	goto:eof

:misc
	if %cmisc-office% equ true (
		call:cmd %MISC%	log			"%OI% /stext %MISC%\office-addins.txt"
	)
	if %cmisc-usb% equ true (
		call:cmd %MISC%	log ^
			"%USB% /DisplayDisconnected 1 /DisplayNoPortSerial 1 /DisplayNoDriver 1 /RetrieveUSBPower /MarkConnectedDevices 1 /AddExportHeaderLine 1 /sort ~10 /scomma %MISC%\usb.csv"
	)
	goto:eof

:sigcheck
	call:cmdn %MAL%	sig			"%SIG% -accepteula -nobanner -a -c -e -h %CFG%\nonrecursive.txt"
	for /F %%i in (%CFG%\nonrecursive.txt) do (
		call:cmdr %MAL%	sig		"%SIG% -accepteula -nobanner -a -c -e -h %%i"
	)
	call:cmdn %MAL%	sig			"%SIG% -accepteula -nobanner -a -c -e -h -s %CFG%\recursive.txt"
	for /F %%i in (%CFG%\recursive.txt) do (
		call:cmdr %MAL%	sig		"%SIG% -accepteula -nobanner -a -c -e -h -s %%i"
	)
	goto:eof

:density
	call:cmdn %MAL%	density		"%DS% %CFG%\nonrecursive.txt -o %MAL%\density\*.txt"
	for /F %%i in (%CFG%\nonrecursive.txt) do (
		set str=%%i
		set str=!str:\=-!
		set str=!str::=!
		call:cmdr %MAL%	density	"%DS% %%i -o %MAL%\density\!str!.txt | %TR% -dc '[:print:]\n'"
	)
	call:cmdn %MAL%	density		"%DS% -r %CFG%\recursive.txt -o %MAL%\density\*.txt"
	for /F %%i in (%CFG%\recursive.txt) do (
		set str=%%i
		set str=!str:\=-!
		set str=!str::=!
		call:cmdr %MAL%	density	"%DS% -r %%i -o %MAL%\density\!str!.txt | %TR% -dc '[:print:]\n'"
	)
	goto:eof

:iconsext
	call:cmdn %MAL%	icons		"%IE% /save %CFG%\nonrecursive-iconsext.txt %MAL%\icons\* -icons"
	for /F %%i in (%CFG%\nonrecursive-iconsext.txt) do (
		set str=%%i
		set str=!str:\=-!
		set str=!str::=!
		for /F "tokens=*" %%j in ('dir /A /B %%i\*.exe') do (
			call:cmdr %MAL%	icons	"%IE% /save %%j %MAL%\icons\!str!\exe\%%~nj -icons"
		)
		for /F "tokens=*" %%j in ('dir /A /B %%i\*.dll ^| findstr /V "imageres\.dll shell32\.dll netshell\.dll"') do (
			call:cmdr %MAL%	icons	"%IE% /save %%j %MAL%\icons\!str!\dll\%%~nj -icons"
		)
	)
	call:cmdn %MAL%	icons		"%IE% /save %CFG%\recursive-iconsext.txt %MAL%\icons\* -icons"
	for /F %%i in (%CFG%\recursive-iconsext.txt) do (
		set str=%%i
		set str=!str:\=-!
		set str=!str::=!
		for /F "tokens=*" %%j in ('dir /A /B /S %%i\*.exe') do (
			call:cmdr %MAL%	icons	"%IE% /save %%j %MAL%\icons\!str!\exe\%%~nj -icons"
		)
		for /F "tokens=*" %%j in ('dir /A /B /S %%i\*.dll ^| findstr /V "imageres\.dll shell32\.dll netshell\.dll"') do (
			call:cmdr %MAL%	icons	"%IE% /save %%j %MAL%\icons\!str!\dll\%%~nj -icons"
		)
	)
	goto:eof

:yara
	call:cmdn %MAL%	yara		"%YAR% -m *.yar *"
	for /F "tokens=*" %%i in ('dir /B /S %TOOLS%\yara\rules\*.yar') do (
		for /F %%j in (%CFG%\nonrecursive.txt) do (
			call:cmdr %MAL%	yara	"%YAR% -m %%i %%j"
		)
		for /F %%j in (%CFG%\recursive.txt) do (
			call:cmdr %MAL%	yara	"%YAR% -m -r %%i %%j"
		)
	)
	goto:eof

:cmdr
	%~3 >> %~1\%~2.txt 2>&1
	goto:eof

:cmd
	call:cmdn %1 %2 %3
	%~3 >> %~1\%~2.txt 2>&1
	goto:eof

:cmdn
	call:date
	set /A in+=1
	echo  %datetime% running %in% out of %it%: %3
	echo  %datetime% running %in% out of %it%: %3 >> %LOG%
	echo. >> %~1\%~2.txt
	echo %NAME%-%VER% %datetime% (%TZ%): %3 >> %~1\%~2.txt
	echo. >> %~1\%~2.txt
	goto:eof

:cmdln
	call:date
	echo. >> %~1
	echo %NAME%-%VER% %datetime% (%TZ%): %2 >> %~1
	echo. >> %~1
	%~2 >> %~1 2>&1
	goto:eof

:date
	if "%date%A" lss "A" (set tok=1-3) else (set tok=2-4)
	for /F "tokens=2-4 delims=(-)" %%i in ('echo: ^| date') do (
		for /F "tokens=%tok% delims=.-/ " %%a in ('date /T') do (
			set %%i=%%a
			set %%j=%%b
			set %%k=%%c
		)
	)
	if %yy% lss 99 set yy=20%yy%
	:: regional independent date
	set yyyymmdd=%yy%%mm%%dd%
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

:init
	echo.
	cd /d %~dp0

	:: variables
	call:date

	set NAME=ir-rescue
	set VER=v1.2
	set TOOLS=tools-win
	set SYSTEM=%COMPUTERNAME%-%yyyymmdd%

	set DATA=data
	set ROOT=%DATA%\%SYSTEM%
	set META=%ROOT%\%NAME%
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

	set LOG=%META%\%NAME%.log
	set CONF=%CFG%\%NAME%.conf

	set GREP=%TOOLS%\cygwin\grep.exe
	set TR=%TOOLS%\cygwin\tr.exe
	set ZIP=%TOOLS%\7za.exe
	set SCR=%TOOLS%\screenshot-cmd.exe
	set SDEL=%TOOLS%\sdelete.exe
	set /A is=0
	set /A ia=0
	for %%i in (%TOOLS%\ascii\*.txt) do (
		set /A ia+=1
		set "asciiart[!ia!]=%%i"
	)
	set /A "rand=(%ia%*%random%)/32768+1"
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
	set RCP=%TOOLS%\fs\RawCopy.exe
	set EUJ=%TOOLS%\fs\ExtractUsnJrnl.exe
	set FLS=%TOOLS%\fs\tsk\fls.exe
	set ADS=%TOOLS%\fs\AlternateStreamView.exe
	set MD5=%TOOLS%\fs\md5deep.exe
	set PSP=%TOOLS%\mal\pslist.exe
	set PSS=%TOOLS%\mal\PsService.exe
	set DV=%TOOLS%\mal\DriverView.exe
	set PSD=%TOOLS%\mal\Listdlls.exe
	set PSH=%TOOLS%\mal\handle.exe
	set AR=%TOOLS%\mal\autoruns.exe
	set ARC=%TOOLS%\mal\autorunsc.exe
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
		set RCP=%TOOLS%\fs\RawCopy64.exe
		set EUJ=%TOOLS%\fs\ExtractUsnJrnl64.exe
		set ADS=%TOOLS%\fs\AlternateStreamView64.exe
		set MD5=%TOOLS%\fs\md5deep64.exe
		set PSD=%TOOLS%\mal\Listdlls64.exe
		set PSP=%TOOLS%\mal\pslist64.exe
		set PSS=%TOOLS%\mal\PsService64.exe
		set DV=%TOOLS%\mal\DriverView64.exe
		set PSH=%TOOLS%\mal\handle64.exe
		set AR=%TOOLS%\mal\Autoruns64.exe
		set ARC=%TOOLS%\mal\autorunsc64.exe
		set WPV=%TOOLS%\mal\WinPrefetchView64.exe
		set SIG=%TOOLS%\mal\sigcheck64.exe
		set DS=%TOOLS%\mal\densityscout64.exe
		set BHV=%TOOLS%\web\BrowsingHistoryView64.exe
		set OI=%TOOLS%\misc\OfficeIns64.exe
		set USB=%TOOLS%\misc\USBDeview64.exe
		set YAR=%TOOLS%\yara\yara64.exe
	)

	:: timezone
	for /f "usebackq tokens=*" %%i in (`tzutil /g`) do set TZ=%%i

	cls
	echo.&echo   initializing...
	set /A f=0

	:: check tools and files
	if not exist %CONF%	 (echo.&echo  ERROR: %CONF% not found. & set /A f=1)
	if not exist %GREP%	 (echo.&echo  ERROR: %GREP% not found. & set /A f=1)
	if not exist %TR%	 (echo.&echo  ERROR: %TR% not found. & set /A f=1)
	if not exist %ZIP%	 (echo.&echo  ERROR: %ZIP% not found. & set /A f=1)
	if not exist %SCR%	 (echo.&echo  ERROR: %SCR% not found. & set /A f=1)
	if not exist %SDEL%	 (echo.&echo  ERROR: %SDEL% not found. & set /A f=1)
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
	if not exist %RCP%	 (echo.&echo  ERROR: %RCP% not found. & set /A f=1)
	if not exist %EUJ%	 (echo.&echo  ERROR: %EUJ% not found. & set /A f=1)
	if not exist %FLS%	 (echo.&echo  ERROR: %FLS% not found. & set /A f=1)
	if not exist %ADS%	 (echo.&echo  ERROR: %ADS% not found. & set /A f=1)
	if not exist %MD5%	 (echo.&echo  ERROR: %MD5% not found. & set /A f=1)
	if not exist %PSP%	 (echo.&echo  ERROR: %PSP% not found. & set /A f=1)
	if not exist %PSS%	 (echo.&echo  ERROR: %PSS% not found. & set /A f=1)
	if not exist %DV%	 (echo.&echo  ERROR: %DV% not found. & set /A f=1)
	if not exist %PSD%	 (echo.&echo  ERROR: %PSD% not found. & set /A f=1)
	if not exist %PSH%	 (echo.&echo  ERROR: %PSH% not found. & set /A f=1)
	if not exist %ARC%	 (echo.&echo  ERROR: %ARC% not found. & set /A f=1)
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
		for /F "tokens=4 delims= " %%i in ('chcp') do set CHCP=%%i

		icacls . /grant Everyone:"(OI)(CI)F" /T > NUL 2>&1

		call:rconf killself ckillself
		call:rconf sdelete csdel
		call:rconf zip czip
		call:rconf zpassword czpassword
		call:rconf screenshot cscreenshot
		call:rconf ascii cascii
		call:rconf memory cmem
		if !cmem! equ true (
			call:rconf memory-all cmem-all
			call:rconf memory-dump cmem-dump !cmem-all!
			call:rconf memory-pagefile cmem-pf !cmem-all!
			call:rconf memory-minidump cmem-md !cmem-all!
		)
		call:rconf registry creg
		if !creg! equ true (
			call:rconf registry-all creg-all
			call:rconf registry-system creg-sys !creg-all!
			call:rconf registry-user creg-user !creg-all!
		)
		call:rconf events cevt
		if !cevt! equ true (
			call:rconf events-all cevt-all
			call:rconf events-evtx cevt-evtx !cevt-all!
			call:rconf events-txt cevt-txt !cevt-all!
		)
		call:rconf system csys
		if !csys! equ true (
			call:rconf system-all csys-all
			call:rconf system-info csys-info !csys-all!
			call:rconf system-account csys-acc !csys-all!
			call:rconf system-acl csys-acl !csys-all!
		)
		call:rconf network cnet
		if !cnet! equ true (
			call:rconf network-all cnet-all
		)
		call:rconf filesystem cfs
		if !cfs! equ true (
			call:rconf filesystem-all cfs-all
			call:rconf filesystem-ntfs cfs-ntfs !cfs-all!
			call:rconf filesystem-vss cfs-vss !cfs-all!
			call:rconf filesystem-dir-full cfs-dfull !cfs-all!
			call:rconf filesystem-dir-plain cfs-dplain !cfs-all!
			call:rconf filesystem-fls cfs-fls !cfs-all!
			call:rconf filesystem-md5 cfs-md5 !cfs-all!
			call:rconf filesystem-ads cfs-ads !cfs-all!
			call:rconf filesystem-mft cfs-mft !cfs-all!
			call:rconf filesystem-log cfs-log !cfs-all!
			call:rconf filesystem-usnjrnl cfs-jrnl !cfs-all!
		)
		call:rconf malware cmal
		if !cmal! equ true (
			call:rconf malware-all cmal-all
			call:rconf malware-info cmal-info !cmal-all!
			call:rconf malware-pf cmal-pf !cmal-all!
			call:rconf malware-services cmal-svcs !cmal-all!
			call:rconf malware-tasks cmal-tasks !cmal-all!
			call:rconf malware-processes cmal-proc !cmal-all!
			call:rconf malware-drivers cmal-drvs !cmal-all!
			call:rconf malware-dlls cmal-dlls !cmal-all!
			call:rconf malware-autoruns cmal-ar !cmal-all!
			call:rconf malware-hidden cmal-hid !cmal-all!
			call:rconf malware-startup cmal-startup !cmal-all!
			call:rconf malware-cache cmal-cache !cmal-all!
		)
		call:rconf web cweb
		if !cweb! equ true (
			call:rconf web-all cweb-all
			call:rconf web-history cweb-hist !cweb-all!
			call:rconf web-chrome cweb-chrome !cweb-all!
			call:rconf web-ie cweb-ie !cweb-all!
			call:rconf web-mozilla cweb-moz !cweb-all!
		)
		call:rconf misc cmisc
		if !cmisc! equ true (
			call:rconf misc-all cmisc-all
			call:rconf misc-mini-timeline cmisc-mtl !cmisc-all!
			call:rconf misc-office cmisc-office !cmisc-all!
			call:rconf misc-usb cmisc-usb !cmisc-all!
		)

		call:rconf sigcheck csigcheck
		call:rconf density cdensity
		call:rconf iconsext ciconsext
		call:rconf yara cyara

		call:cleandrn .\%DATA%
		call:cleanfn .\%SYSTEM%.7z

		set /A in=0
		set /A it=0

		set /A iu=3
		set /A ip=0
		set /A id=0

		set "users[1]=Administrator"
		set "users[2]=Guest"
		set "users[3]=HomeGroupUser$"
		for /F "tokens=3,*" %%i in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" /S /V ProfileImagePath ^| findstr "ProfileImagePath" ^| findstr /v "ServiceProfiles" ^| findstr /v "system32"') do (
			set /A iu+=1
			set /A ip+=1
			set "profiles[!ip!]=%%i"
			set "startup[!ip!]=%%i\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
			set "temp[!ip!]=%%i\AppData\Local\Temp"
			for /F "tokens=3 delims=\" %%j in ("%%i") do (
				set "users[!iu!]=%%j"
				set "usersp[!ip!]=%%j"
			)
		)

		mkdir .\%DATA% .\%ROOT% .\%META% > NUL 2>&1

		if !cascii! equ false	set ASCII=%TOOLS%\ascii\cyb.txt
		if !cmem! equ true (
			mkdir .\%MEM% > NUL 2>&1
			if !cmem-dump! equ true set /A it+=1
			if !cmem-pf! equ true set /A it+=1
			if !cmem-md! equ true set /A it+=1
		)
		if !creg! equ true (
			mkdir .\%REG% > NUL 2>&1
			if !creg-sys! equ true (mkdir .\%REG%\sys & set /A it+=4)
			if !creg-user! equ true (mkdir .\%REG%\user & set /A it+=!ip!+!ip!)
		)
		if !cevt! equ true (
			mkdir .\%EVT%  > NUL 2>&1
			if !cevt-evtx! equ true (mkdir .\%EVT%\evtx & set /A it+=4)
			if !cevt-txt! equ true (mkdir .\%EVT%\txt & set /A it+=4)
		)
		if !csys! equ true (
			mkdir .\%SYS% > NUL 2>&1
			if !csys-info! equ true set /A it+=5
			if !csys-acc! equ true set /A it+=10+!iu!+!iu!
			if !csys-acl! equ true set /A it+=2
		)
		if !cnet! equ true (
			mkdir .\%NET% > NUL 2>&1
			set /A it+=19
		)
		if !cfs! equ true (
			mkdir .\%FS% > NUL 2>&1
			for %%i in (c d e f g h i j k l m n o p q r s t u v w x y z) DO (
				if exist %%i: (
					set /A id+=1
					set "driveslc[!id!]=%%i"
				)
			)
			set /A id=0
			for %%i in (C D E F G H I J K L M N O P Q R S T U V W X Y Z) DO (
				if exist %%i: (
					set /A id+=1
					set "drivesuc[!id!]=%%i"
				)
			)
			if !cfs-ntfs! equ true set /A it+=2+!id!+!id!
			if !cfs-vss! equ true set /A it+=3
			if !cfs-dfull! equ true set /A it+=!id!
			if !cfs-dplain! equ true set /A it+=!id!
			if !cfs-fls! equ true set /A it+=!id!+1
			if !cfs-md5! equ true set /A it+=2
			if !cfs-ads! equ true set /A it+=2
			if !cfs-mft! equ true set /A it+=1
			if !cfs-log! equ true set /A it+=1
			if !cfs-jrnl! equ true set /A it+=1
		)
		if !cmal! equ true (
			mkdir .\%MAL% > NUL 2>&1
			if !cmal-pf! equ true set /A it+=2
			if !cmal-proc! equ true set /A it+=5
			if !cmal-drvs! equ true set /A it+=2
			if !cmal-dlls! equ true set /A it+=2
			if !cmal-svcs! equ true set /A it+=4
			if !cmal-tasks! equ true (
				set /A it+=3
				if exist "%PROGRAMFILES(X86)%" set /A it+=1
			)
			if !cmal-ar! equ true (mkdir .\%MAL%\autoruns & set /A it+=3)
			if !cmal-hid! equ true (mkdir .\%MAL%\hidden & set /A it+=2)
			if !cmal-startup! equ true set /A it+=1
			if !cmal-cache! equ true (mkdir .\%MAL%\cache & set /A it+=2)
		)
		if !cweb! equ true (
			mkdir .\%WEB% > NUL 2>&1
			if !cweb-hist! equ true set /A it+=1
			if !cweb-chrome! equ true (mkdir .\%WEB%\cache-chrome & set /A it+=2)
			if !cweb-ie! equ true (mkdir .\%WEB%\cache-ie & set /A it+=2)
			if !cweb-moz! equ true (mkdir .\%WEB%\cache-mozilla & set /A it+=2)
		)
		if !cmisc! equ true (
			mkdir .\%MISC% > NUL 2>&1
			if !cmisc-mtl! equ true set /A it+=1
			if !cmisc-office! equ true set /A it+=1
			if !cmisc-usb! equ true set /A it+=1
		)
		if !csigcheck! equ true (
			mkdir .\%MAL% > NUL 2>&1
			set /A it+=2
		)
		if !cdensity! equ true (
			mkdir .\%MAL% > NUL 2>&1
			set /A it+=2
		)
		if !ciconsext! equ true (
			mkdir .\%MAL% .\%MAL%\icons > NUL 2>&1
			set /A it+=2
		)
		if !cyara! equ true (
			mkdir .\%MAL% > NUL 2>&1
			set /A it+=1
		)
	)
	exit /B %f%

:end
	call:timestamp
	call:msg " compressing data and cleaning up..."
	call:screenshot

	:: delete Sysinternals registry keys?
	:: delete prefetch files?
	:: what other evidence pollutes the system?

	icacls . /grant Everyone:"(OI)(CI)F" /T > NUL 2>&1
	call:cmdln	"%LOG%" "attrib -H .\set.txt.tmp"
	:: delete empty folders before compressing
	if %cmal% equ true (
		for /L %%i in (1,1,%ip%) do (
			call:cleand .\!startupx[%%i]!
		)
	)
	if %cweb% equ true (
		call:cleand .\%WEB%\cache-chrome .\%WEB%\cache-ie .\%WEB%\cache-mozilla
	)
	:: delete icon folders in bins to reduce processing?
	if %ciconsext% equ true (
		for /f %%i in ('dir /A:D /B /S .\%MAL%\icons ^| sort /R') do (
			set tmp=%%i
			set tmp=!tmp:%~dp0=!
			call:cleand .\!tmp!
		)
	)

	call:packf	%MEM%\raw.mem %MEM%\pagefile.sys
	call:packd	"zip"	%MEM%\Minidump
	call:packd	"zip"	%REG%\sys
	call:packd	"zip"	%REG%\user
	call:packd	"zip"	%EVT%\evtx
	call:packd	"zip"	%EVT%\txt
	call:packf	%FS%\$MFT %FS%\$LogFile %FS%\$UsnJrnl_$J.bin
	call:packd	"zip"	%MAL%\Prefetch
	call:packd	"zip"	%MAL%\Tasks		%MAL%\Tasks
	call:packd	"zip"	%MAL%\Tasks32	%MAL%\Tasks
	call:packd	"zip"	%MAL%\Tasks64	%MAL%\Tasks
	if defined startupx[1] (
		for /L %%i in (1,1,%ip%) do (
			call:packd	"7z"	!startupx[%%i]!	%MAL%\Startup
		)
	)
	call:packd	"7z"	%WEB%\cache-chrome
	call:packd	"7z"	%WEB%\cache-ie
	call:packd	"7z"	%WEB%\cache-mozilla
	call:packd	"zip"	%MAL%\icons

	:: icacls . /grant Everyone:"(OI)(CI)F" /T > NUL 2>&1

	call:cleanf		.\set.txt.tmp
	call:cleanf		%TEMP%\pmem.tmp .\%MEM%\raw.mem .\%MEM%\pagefile.sys
	call:cleandr	.\%MEM%\Minidump
	call:cleandr	.\%REG%\sys .\%REG%\user
	call:cleandr	.\%EVT%\evtx .\%EVT%\txt
	call:cleanf		.\%FS%\$MFT .\%FS%\$LogFile .\%FS%\$UsnJrnl_$J.bin
	call:cleandr	.\%MAL%\Prefetch .\%MAL%\Tasks .\%MAL%\Tasks32 .\%MAL%\Tasks64
	if defined startupx[1] (
		for /L %%i in (1,1,%ip%) do (
			call:cleandr	.\!startupx[%%i]!
		)
	)
	call:cleandr	.\%WEB%\cache-chrome .\%WEB%\cache-ie .\%WEB%\cache-mozilla
	call:cleandr	.\%MAL%\icons

	icacls . /grant Everyone:"(OI)(CI)F" /T > NUL 2>&1

	call:timestamp
	call:ascii
	call:msg "  finishing..."
	call:screenshot

	call:cmdln	".\%META%\%SYSTEM%.md5"	"%MD5% -l -r -s -z . | sort /+47"

	if %czip% equ true (
		if not "%czpassword%" equ "" (
			%ZIP% a -t7z -xr"^!.*" -p"%czpassword%" -mhe -mmt=on %SYSTEM%.7z .\%ROOT% > NUL 2>&1
		) else (
			%ZIP% a -t7z -xr"^!.*" -mmt=on %SYSTEM%.7z .\%ROOT% > NUL 2>&1
		)
	)
	if %ckillself% equ true (
		call:cleandrn .\%DATA% .\%TOOLS%
		if %csdel% equ true	rmdir /Q /S .\%TOOLS% > NUL 2>&1
	)
	echo.&echo terminus / end / fin / fim / fine / einde / koniec
	chcp %CHCP% > NUL 2>&1
	call:pause
	goto:eof

:ascii
	echo.&type %ASCII%&echo.
	echo. >> %LOG%
	type %ASCII% >> %LOG%
	echo. >> %LOG%
	goto:eof

:screenshot
	if %cscreenshot% equ true (
		set /A is+=1
		call:cmdln	"%LOG%"	"%SCR% -o %META%\screenshot-%is%.png"
	)
	goto:eof

:rconf
	if "%~3" equ "true" (
		set %~2=true
	) else (
		for /F "eol=# tokens=1,2* delims==" %%i in ('findstr /B /I /L "%~1=" %CONF%') DO (
			set %~2=%%~j
		)
		if %~2 equ "" set %~2=false
	)
	goto:eof

:packf
	for %%i in (%*) do (
		if exist .\%%i (
			call:cmdln	"%LOG%"	"%ZIP% a -tzip .\%%i.zip .\%%i"
		)
	)
	goto:eof

:packd
	:: %ZIP% a -tzip -xr!.* ...
	if exist %~2 (
		if "%~3" equ "" (set tmp=%2) else (set tmp=%3)
		if "%~1" equ "zip" (
			call:cmdln	"%LOG%"	"%ZIP% a -tzip -r .\!tmp!.zip .\%~2"
		) else (
			call:cmdln	"%LOG%"	"%ZIP% a -t7z -r -pinfected .\!tmp!.7z .\%~2"
		)
	)
	goto:eof

:cleand
	call:clean "%LOG%" "rmdir" "nonrecursive" %*
	goto:eof

:cleandr
	call:clean "%LOG%" "rmdir" "recursive" %*
	goto:eof

:cleandrn
	call:clean "NUL" "rmdir" "recursive" %*
	goto:eof

:cleanf
	call:clean "%LOG%" "del" "nonrecursive" %*
	goto:eof

:cleanfn
	call:clean "NUL" "del" "nonrecursive" %*
	goto:eof

:clean
	for /F "tokens=3,* delims= " %%i in ("%*") do (
		for %%a in (%%j) do (
			if exist %%a goto:rm %*
		)
	)
	goto:eof

:rm
	for /F "tokens=3,* delims= " %%i in ("%*") do set tmp=%%j
	if %csdel% equ true (
		if "%~3" equ "recursive" (
			call:cmdln	%1	"%SDEL% -accepteula -s !tmp!"
		) else (
			call:cmdln	%1	"%SDEL% -accepteula !tmp!"
		)
	) else (
		if "%~3" equ "recursive" (
			call:cmdln	%1	"%~2 /Q /S !tmp!"
		) else (
			call:cmdln	%1	"%~2 /Q !tmp!"
		)
	)
	goto:eof

:pause
	set /P null=
	goto:eof

:help
	echo.&echo Usage: %~nx0
	echo.
	echo Output: text  files  per each  command executed  organized according to
	echo data type.
	echo.
	echo ir-rescue  is a batch script for collecting  incident  response data on
	echo Windows systems.  It uses third-party utilities kept in a folder called
	echo 'tools' under 'ir-rescue\tools\'.
	echo.
	echo Needs administrator rights to run.
	call:pause
	goto:eof

:: notes

:: del /A /S /Q *.DS_Store & ir-rescue\tools-win\fs\md5deep64.exe -l -r -s -z ir-rescue\ > ir-rescue\ir-rescue.md5

:: http://windowsir.blogspot.pt/p/books.html
:: http://www.woanware.co.uk/forensics/jumplister.html

:: VSS: reg, RFC, etc.; hard links; rip-vsc.txt
	:: 1-20
	:: 1-64: https://technet.microsoft.com/en-us/library/ee923636(v=ws.10).aspx
	:: 1-512?: https://technet.microsoft.com/en-us/library/ee923636(v=ws.10).aspx
	:: mklink /d %SystemDrive%\ShadowCopyLink \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy#
:: 'vss=true'
:: skip known-good hash values from 'recursive.txt' and 'nonrecursive.txt'
:: 'stream=true'
	:: 'netcat' data stream
	:: write to disk
	:: run from mapped drive, automatically data is streamed
:: 'admin=true'

:: BHO, browser addons
:: soft and hard links; jump lists
:: timestomping
:: Windows Error Reporting (WER)
	:: %ProgramData%\Microsoft\Windows\WER\
	:: %SystemDrive%\Users\%UserName%\AppData\Local\Microsoft\Windows\WER\

:: Windows Scripting
:: PowerShell and WMI

:: xcopy, robocopy

:: TZWorks pescan
:: TZWorks LNK Parsing; *.lnk
:: TZWorks ntfswalk, ntfscopy
:: Redline Comprehensive Collector; WinAudit
