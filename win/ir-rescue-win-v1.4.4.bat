@echo off

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
	set > .\set.txt.tmp 2>&1
	attrib +H set.txt.tmp > NUL 2>&1

	call:init
	if not %errorLevel% equ 0 (
		attrib -H .\set.txt.tmp > NUL 2>&1
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
	call:cmdl "%LOG%" "type %CONF%"
	call:msg " output: %coutpath%"
	call:msg " %LOGONSERVER%  %COMPUTERNAME%  %USERDOMAIN%\%USERNAME%"
	call:timestamp
	echo.

	call:screenshot

	call:memory
	call:filesystem
	call:malware
	call:network
	call:activity
	call:malware-contd
	call:filesystem-contd
	call:network-contd
	call:memory-contd
	call:system
	call:registry
	call:events
	call:web
	call:activity-contd
	call:disk

	call:sigcheck
	call:density
	call:iconsext
	call:yara

	call:end
	:: exit and delete self, "if %ckillself%" must come before "endlocal"
	:: start /B "" cmd /C del "%~f0" & exit /B
	:: if %ckillself% equ true goto 2 > NUL & del /F /Q %~f0
	:: end local variable environment
	endlocal
	exit /B 0


:activity
	if %cactiv-mtl% equ true (
		if %RUN% equ true (
			call:header "last activity items" "listing"
			call:cmd %ACTIV%\log "%LAV% /scomma %ACTIV%\mini-timeline.csv"
		) else (set /A it+=1, itt+=1)
	)
	goto:eof

:activity-contd
	if %cactiv% equ true (if %RUN% equ false mkdir %ACTIV%)

	if %cactiv-usb% equ true (
		if %RUN% equ true (
			call:header "USB device history"
			call:cmd %ACTIV%\log "%USB% /DisplayDisconnected 1 /DisplayNoPortSerial 1 /DisplayNoDriver 1 /RetrieveUSBPower /MarkConnectedDevices 1 /AddExportHeaderLine 1 /sort ~10 /scomma %ACTIV%\usb.csv"
		) else (set /A it+=1, itt+=1)
	)
	if %cactiv-jump% equ true (
		if %RUN% equ true (
			call:header "automatic and custom destinations jump lists" "parsing"
			for /L %%i in (1,1,%ip%) do (
				call:cmdn %ACTIV%\jump\log "%JLEC% --csv %ACTIV%\jump\!usersp[%%i]! -d !uprofiles[%%i]!\AppData\Roaming\Microsoft\Windows\Recent --dumpTo %ACTIV%\jump\!usersp[%%i]! --fd -q"
				%JLEC% --csv "%ACTIV%\jump\!usersp[%%i]!" -d "!uprofiles[%%i]!\AppData\Roaming\Microsoft\Windows\Recent" --dumpTo "%ACTIV%\jump\!usersp[%%i]!" --fd -q >> %ACTIV%\jump\log.txt 2>&1
			)
		) else (mkdir %ACTIV%\jump & set /A it+=1, itt+=%ip%)
		if %cactiv-vss% equ true (
			for /L %%i in (1,1,%ip%) do (
				if %RUN% equ true (
					call:cmdn %ACTIV%\jump\log "%JLEC% --csv %ACTIV%\jump\!usersp[%%i]!-vss* -d vss*!uprofiles[%%i]:~2!\AppData\Roaming\Microsoft\Windows\Recent --dumpTo %ACTIV%\jump\!usersp[%%i]!-vss* --fd -q"
				) else set /A itt+=1
				for /L %%a in (1,1,%iv%) do (
					if /I %UPROFILED% equ !vsscd[%%a]! (
						if %RUN% equ true (
							%JLEC% --csv "%ACTIV%\jump\!usersp[%%i]!-!vsscf[%%a]!" -d "!vssc[%%a]!!uprofiles[%%i]:~2!\AppData\Roaming\Microsoft\Windows\Recent" --dumpTo "%ACTIV%\jump\!usersp[%%i]!-!vsscf[%%a]!" --fd -q >> %ACTIV%\jump\log.txt 2>&1
						)
					)
				)
			)
		)
	)
	if %cactiv-lnk% equ true (
		if %RUN% equ true (
			call:header "LNK files" "parsing"
			for /L %%i in (1,1,%ip%) do (
				call:cmdn %ACTIV%\lnk "%EXIF% -csv !uprofiles[%%i]!\AppData\Roaming\Microsoft\Windows\Recent\*"
				%EXIF% -csv "!uprofiles[%%i]!\AppData\Roaming\Microsoft\Windows\Recent\*" >> %ACTIV%\lnk.txt 2>&1
				call:cmdn %ACTIV%\lnk "%EXIF% -csv !ustartup[%%i]!\*"
				%EXIF% -csv "!ustartup[%%i]!\*" >> %ACTIV%\lnk.txt 2>&1
			)
		) else (set /A it+=1, itt+=2*%ip%)
		if %cactiv-vss% equ true (
			for /L %%i in (1,1,%ip%) do (
				if %RUN% equ true (
					call:cmdn %ACTIV%\lnk "%EXIF% -csv vss*!uprofiles[%%i]:~2!\AppData\Roaming\Microsoft\Windows\Recent"
					call:cmdn %ACTIV%\lnk "%EXIF% -csv vss*!ustartup[%%i]:~2!"
				) else set /A itt+=2
				for /L %%a in (1,1,%iv%) do (
					if /I %UPROFILED% equ !vsscd[%%a]! (
						if %RUN% equ true (
							%EXIF% -csv "!vssc[%%a]!!uprofiles[%%i]:~2!\AppData\Roaming\Microsoft\Windows\Recent" >> %ACTIV%\lnk.txt 2>&1
							%EXIF% -csv "!vssc[%%a]!!ustartup[%%i]:~2!" >> %ACTIV%\lnk.txt 2>&1
						)
					)
				)
			)
		)
	)
	if %cactiv-bin% equ true (
		if %RUN% equ true (call:header "the recycle bin(s)" "parsing") else (set /A it+=1)
		for /L %%i in (1,1,%iu%) do (
			for /L %%a in (1,1,%idr%) do (
				set tmp=!drivesuc[%%a]!:\$Recycle.Bin\!usid[%%i]!
				if exist !tmp! (
					if %RUN% equ true (
						call:cmdn %ACTIV%\bin "%RB% -8 -t , !tmp!"
						echo  !usid[%%i]! !users[%%i]! >> %ACTIV%\bin.txt 2>&1
						echo. >> %ACTIV%\bin.txt 2>&1
						call:cmdr %ACTIV%\bin "%RB% -8 -t , !tmp!"
					) else set /A itt+=1
				)
			)
		)
		if %cactiv-vss% equ true (
			for /L %%i in (1,1,%iu%) do (
				for /L %%a in (1,1,%iv%) do (
					set tmp=!vssc[%%a]!\$Recycle.Bin\!usid[%%i]!
					if exist !tmp! (
						if %RUN% equ true (
							call:cmdn %ACTIV%\bin "%RB% -8 -t , !tmp!"
							echo  !usid[%%i]! !users[%%i]! >> %ACTIV%\bin.txt 2>&1
							echo. >> %ACTIV%\bin.txt 2>&1
							call:cmdr %ACTIV%\bin "%RB% -8 -t , !tmp!"
						) else set /A itt+=1
					)
				)
			)
		)
	)
	goto:eof

:disk
	if %cdisk% equ true (if %RUN% equ false mkdir %DISK%)

	if %cdisk-info% equ true (
		if %RUN% equ true (
			call:header "disk information"
			set tmp=.diskpart.tmp

			call:cmd %DISK%\disk "diskpart /S %TOOLS%\disk\diskpart-listvol.txt"
			for /L %%i in (0,1,%idii%) do (
				echo select disk %%i > !tmp! 2>NUL 2>&1
				echo list partition >> !tmp! 2>NUL 2>&1
				call:cmd %DISK%\disk "diskpart /S !tmp!"
				del /A !tmp! 2>NUL 2>&1
				call:cmd %DISK%\disk "%MMLS% -Brv !disk[%%i]!"
			)
		) else (set /A it+=1, itt+=1+2*%idi%)
	)
	if %cdisk-encrypt% equ true (
		if %RUN% equ true (
			call:header "for disk encryption" "checking"
			call:cmd %DISK%\encrypt "%EDD% /accepteula /batch"
		) else (set /A it+=1, itt+=1)
	)
	if %cdisk-boot% equ true (
		if %RUN% equ true (
			call:header "disk(s) boot sector" "dumping"
			for /L %%i in (0,1,%idii%) do (
				call:cmdn %DISK%\log "%MMCAT% !disk[%%i]! 0"
				%MMCAT% !disk[%%i]! 0 > %DISK%\boot-%%i.bin 2>&1
			)
		) else (set /A it+=1, itt+=%idi%)
	)
	goto:eof

:events
	if %cevt% equ true (if %RUN% equ false mkdir %EVT%)

	if %cevt-evtx% equ true (
		if %RUN% equ true (
			call:header "Windows event logs in *.evtx format"
			call:cmd %EVT%\log "%PLL% -accepteula -g %EVT%\evtx\Security.evtx Security"
			call:cmd %EVT%\log "%PLL% -accepteula -g %EVT%\evtx\System.evtx System"
			call:cmd %EVT%\log "%PLL% -accepteula -g %EVT%\evtx\Application.evtx Application"
			call:cmd %EVT%\log "%PLL% -accepteula -g %EVT%\evtx\Setup.evtx Setup"
		) else (mkdir %EVT%\evtx & set /A it+=1, itt+=4)
	)
	if %cevt-txt% equ true (
		if %RUN% equ true (
			call:header "Windows event logs in text format"
			call:cmd %EVT%\txt\Security "%PLL% -accepteula -s -x Security"
			call:cmd %EVT%\txt\System "%PLL% -accepteula -s -x System"
			call:cmd %EVT%\txt\Application "%PLL% -accepteula -s -x Application"
			call:cmd %EVT%\txt\Setup "%PLL% -accepteula -s -x Setup"
		) else (mkdir %EVT%\txt & set /A it+=1, itt+=4)
	)
	:: call:cmd %EVT%\log ^
	::	"xcopy %SystemRoot%\System32\winevt\logs\Security.evtx %EVT%\ /C /I /F /H /Y"
	goto:eof

:filesystem
	if %cfs% equ true (if %RUN% equ false mkdir %FS%)

	if %cfs-mft% equ true (
		if %RUN% equ true (
			call:header "NTFS MFT file(s)"
			for /L %%i in (1,1,%idr%) do (
				call:cmd %FS%\log "%RCP% /FileNamePath:!drivesuc[%%i]!:0 /OutputPath:%FS%"
				ren %FS%\$MFT $MFT-!driveslc[%%i]!.bin > NUL 2>&1
			)
		) else (set /A it+=1, itt+=%idr%)
	)
	if %cfs-log% equ true (
		if %RUN% equ true (
			call:header "NTFS log file(s)"
			for /L %%i in (1,1,%idr%) do (
				call:cmd %FS%\log "%RCP% /FileNamePath:!drivesuc[%%i]!:2 /OutputPath:%FS%"
				ren %FS%\$LogFile $LogFile-!driveslc[%%i]!.bin > NUL 2>&1
			)
		) else (set /A it+=1, itt+=%idr%)
	)
	if %cfs-jrnl% equ true (
		if %RUN% equ true (
			call:header "NTFS journal file(s)"
			for /L %%i in (1,1,%idr%) do (
				set tmp=
				if %FS:~0,2% equ .\ (set tmp=%~dp0%FS:~2%) else (set tmp=%FS%)
				call:cmdn %FS%\log "%EUJ% /DevicePath:!drivesuc[%%i]!: /OutputPath:!tmp!"
				%EUJ% /DevicePath:!drivesuc[%%i]!: /OutputPath:"!tmp!" >> %FS%\log.txt 2>&1
				ren %FS%\$UsnJrnl_$J.bin $UsnJrnl_$J-!driveslc[%%i]!.bin > NUL 2>&1
			)
		) else (set /A it+=1, itt+=%idr%)
	)
	goto:eof

:filesystem-contd
	if %cfs-ntfs% equ true (
		if %RUN% equ true (
			call:header "NTFS information"
			call:cmd %FS%\ntfs "reg query HKLM\SYSTEM\CurrentControlSet\Control\FileSystem /S"
			call:cmd %FS%\ntfs "fsutil fsinfo drives"
			for /L %%i in (1,1,%idr%) do (
				call:cmd %FS%\ntfs "fsutil fsinfo ntfsinfo !drivesuc[%%i]!:\"
				call:cmd %FS%\ntfs "%NTFS% -accepteula !drivesuc[%%i]!:\"
			)
		) else (set /A it+=1, itt+=2+2*%idr%)
	)
	if %cfs-vssi% equ true (
		if %RUN% equ true (
			call:header "VSS information"
			call:cmd %FS%\vss "vssadmin list volumes"
			call:cmd %FS%\vss "vssadmin list shadowstorage"
			call:cmd %FS%\vss "vssadmin list shadows"
		) else (set /A it+=1, itt+=3)
	)
	if %cfs-dfull% equ true (
		if %RUN% equ true (
			call:header "files and directories" "fully listing"
			call:vssoff
			for /L %%i in (1,1,%idr%) do (
				call:cmd %FS%\dir-!driveslc[%%i]!-m "dir /A /O:D /Q /T:W /R /S !drivesuc[%%i]!:\"
			)
			call:vsson
		) else (set /A it+=1, itt+=%idr%)
		if %cfs-vss% equ true (
			if %RUN% equ true (
				for /L %%i in (1,1,%iv%) do (
					call:cmd %FS%\dir-!vsscf[%%i]!-m "dir /A /O:D /Q /T:W /R /S !vssc[%%i]!\"
				)
			) else set /A itt+=%iv%
		)
	)
	if %cfs-dplain% equ true (
		if %RUN% equ true (
			call:header "of files and directories" "plain listing"
			call:vssoff
			for /L %%i in (1,1,%idr%) do (
				call:cmd %FS%\dir-!driveslc[%%i]! "dir /A /B /S !drivesuc[%%i]!:\"
			)
			call:vsson
		) else (set /A it+=1, itt+=%idr%)
		if %cfs-vss% equ true (
			if %RUN% equ true (
				for /L %%i in (1,1,%iv%) do (
					call:cmd %FS%\dir-!vsscf[%%i]! "dir /A /B /S !vssc[%%i]!\"
				)
			) else set /A itt+=%iv%
		)
	)
	:: Win32 device namespace (`NamedPipe`)
	if %cfs-fls% equ true (
		if %RUN% equ true (
			call:header "the MFT" "walking"
			for /L %%i in (1,1,%idr%) do (
				call:cmd %FS%\fls-!driveslc[%%i]! "%FLS% -l -p -r \\.\!drivesuc[%%i]!:"
			)
			call:cmd %FS%\bin "type %FS%\fls-*.txt | findstr /I $Recycle.Bin"
		) else (set /A it+=1, itt+=%idr%+1)
	)
	if %cfs-md5% equ true (
		if %RUN% equ true (
			call:header "MD5 values" "computing"
			call:vssoff
			call:cmd %FS%\md5-nr "%MD5% -f %CFG%\nonrecursive-md5deep.txt -s -t -z | sort /+67"
			call:cmd %FS%\md5-r "%MD5% -f %CFG%\recursive-md5deep.txt -r -s -t -z | sort /+67"
			call:vsson
		) else (set /A it+=1, itt+=2)
		if %cfs-vss% equ true (
			if %RUN% equ false set /A itt+=2*%iv%

			for /L %%i in (1,1,%iv%) do (
				if %RUN% equ true (
					call:cmdn %FS%\md5-nr "%MD5% -f %CFG%\nonrecursive-md5deep.txt -s -t -z !vsscf[%%i]! | sort /+67"
				)
				for /F %%a in (%CFG%\nonrecursive-md5deep.txt) do (
				set tmp=%%a
				set tmpp=!tmp:~0,1!
					if /I !tmpp! equ !vsscd[%%i]! (
						if %RUN% equ true (
							call:cmdr %FS%\md5-nr "%MD5% -s -t -z !vssc[%%i]!!tmp:~2! | sort /+67"
						)
					)
				)
			)
			for /L %%i in (1,1,%iv%) do (
				if %RUN% equ true (
					call:cmdn %FS%\md5-r "%MD5% -f %CFG%\recursive-md5deep.txt -r -s -t -z !vsscf[%%i]! | sort /+67"
				)
				for /F %%a in (%CFG%\recursive-md5deep.txt) do (
				set tmp=%%a
				set tmpp=!tmp:~0,1!
					if /I !tmpp! equ !vsscd[%%i]! (
						if %RUN% equ true (
							call:cmdr %FS%\md5-r "%MD5% -r -s -t -z !vssc[%%i]!!tmp:~2! | sort /+67"
						)
					)
				)
			)
		)
	)
	if %cfs-ads% equ true (
		if %RUN% equ true (
			call:header "NTFS ADSs" "listing"
			for /L %%i in (1,1,%idr%) do (
				call:cmd %FS%\log "%ADS% /FolderPath !drivesuc[%%i]!:\ /ScanSubfolders 1 /SubFolderDept 0 /ShowZeroLengthStreams 1 /scomma %FS%\ads-!driveslc[%%i]!.csv"
			)
		) else (set /A it+=1, itt+=%idr%)
	)
	:: "reg query HKLM\SYSTEM\CurrentControlSet\Services\VSS"
	:: Sysinternals junctions
	:: Sysinternals streams64.exe -s %SystemDrive% | findstr /C:"Error opening" /V | findstr /C:"The system cannot find the path specified." /V | findstr /R /V "^$"
	goto:eof

:malware
	if %cmal% equ true (if %RUN% equ false mkdir %MAL%)

	if %cmal-pf% equ true (
		if %RUN% equ true (
			call:header "prefetch files"
			call:cmdn %MAL%\prefetch "reg query HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters /S"
			reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /S >> %MAL%\prefetch.txt 2>&1
			call:xcp %MAL%\prefetch "%SystemRoot%\Prefetch\*.pf" "%MAL%\Prefetch-live"
			call:cmdn %MAL%\prefetch "%WPV% /prefetchfile %SystemRoot%\Prefetch\*.pf /sort ~7 /scomma %MAL%\Prefetch-live\*.csv"
			for /F "tokens=*" %%i in ('dir /B /S %SystemRoot%\Prefetch\*.pf 2^>NUL') do (
				%WPV% /prefetchfile "%%i" /sort ~7 /scomma "%MAL%\Prefetch-live\%%~ni.csv" >> %MAL%\prefetch.txt 2>&1
			)
		) else (set /A it+=1, itt+=3)
		if %cmal-vss% equ true (
			for /L %%i in (1,1,%iv%) do (
				if /I %SYSROOTD% equ !vsscd[%%i]! (
					if %RUN% equ true (
						call:xcp %MAL%\prefetch "!vssc[%%i]!%SYSROOTP%\Prefetch\*.pf" "%MAL%\Prefetch-!vsscf[%%i]!\"
						call:cmdn %MAL%\prefetch "%WPV% /prefetchfile !vssc[%%i]!%SYSROOTP%\Prefetch\*.pf /sort ~7 /scomma %MAL%\Prefetch-!vsscf[%%i]!\*.csv"
						for /F "tokens=*" %%a in ('dir /B /S !vssc[%%i]!%SYSROOTP%\Prefetch\*.pf 2^>NUL') do (
							%WPV% /prefetchfile "%%a" /sort ~7 /scomma "%MAL%\Prefetch-!vsscf[%%i]!\%%~na.csv" >> %MAL%\prefetch.txt 2>&1
						)
					) else set /A itt+=2
				)
			)
		)
	)
	if %cmal-cache% equ true (
		if %RUN% equ true (
			call:header "program execution cache files" "copying"
			call:xcp %MAL%\log "%SystemRoot%\AppCompat\Programs\RecentFileCache.bcf" "%MAL%\cache"
			call:cmd %MAL%\log "%RCP% /FileNamePath:%SystemRoot%\AppCompat\Programs\Amcache.hve /OutputPath:%MAL%\cache"
			call:attren "%MAL%\cache\RecentFileCache.bcf" "RecentFileCache-live.bcf"
			call:attren "%MAL%\cache\Amcache.hve" "Amcache-live.hve"
		) else (mkdir %MAL%\cache & set /A it+=1, itt+=2)
		if %cmal-vss% equ true (
			for /L %%i in (1,1,%iv%) do (
				if /I %SYSROOTD% equ !vsscd[%%i]! (
					if %RUN% equ true (
						call:xcp %MAL%\log "!vssc[%%i]!%SYSROOTP%\AppCompat\Programs\RecentFileCache.bcf" "%MAL%\cache"
						call:xcp %MAL%\log "!vssc[%%i]!%SYSROOTP%\AppCompat\Programs\Amcache.hve" "%MAL%\cache"
						call:attren "%MAL%\cache\RecentFileCache.bcf" "RecentFileCache-!vsscf[%%i]!.bcf"
						call:attren "%MAL%\cache\Amcache.hve" "Amcache-!vsscf[%%i]!.hve"
					) else set /A itt+=2
				)
			)
		)
	)
	goto:eof

:malware-contd
	:: "findstr /C:DisplayName /C:ImagePath /C:ServiceDll /L | findstr /V ServiceDllUnloadOnStop"
	if %cmal-proc% equ true (
		if %RUN% equ true (
			call:header "running processes" "listing"
			call:cmd %MAL%\proc "%PSP% -accepteula"
			call:cmd %MAL%\proc "%PSP% -accepteula -t"
			call:cmd %MAL%\proc "tasklist /V"
			call:cmd %MAL%\proc "tasklist /M"
			call:cmd %MAL%\handles "%PSH% -accepteula -s"
			call:cmd %MAL%\handles "%PSH% -accepteula -u"
		) else (set /A it+=1, itt+=6)
	)
	if %cmal-drvs% equ true (
		if %RUN% equ true (
			call:header "loaded drivers" "listing"
			call:cmd %MAL%\drivers "%DV% /sort ~12 /scomma %MAL%\drivers.csv"
			call:cmd %MAL%\drivers "driverquery /FO csv /V"
		) else (set /A it+=1, itt+=2)
	)
	if %cmal-dlls% equ true (
		if %RUN% equ true (
			call:header "loaded DLLs" "listing"
			call:cmdn %MAL%\dlls-known "reg query HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs /S"
			reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs" /S >> %MAL%\dlls-known.txt 2>&1
			call:cmd %MAL%\dlls-unsign "%PSD% -accepteula -r -v"
			call:cmd %MAL%\arg "%GREP% -F 'Command line: ' %MAL%\dlls-unsign.txt"
		) else (set /A it+=1, itt+=3)
	)
	if %cmal-svcs% equ true (
		if %RUN% equ true (
			call:header "running services" "listing"
			call:cmdn %MAL%\svcs "reg query HKLM\SYSTEM\CurrentControlSet\Services /S | %GREP% -E 'DisplayName|ImagePath|ServiceDll'"
			(reg query HKLM\SYSTEM\CurrentControlSet\Services\ /S | %GREP% -E "HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\|DisplayName|ImagePath|ServiceDll" | %GREP% -F -v "ServiceDllUnloadOnStop") >> %MAL%\svcs.txt 2>&1
			call:cmd %MAL%\svcs "tasklist /svc"
			call:cmd %MAL%\svcs "sc queryex"
			call:cmd %MAL%\svcs "%PSS% -accepteula"
		) else (set /A it+=1, itt+=4)
	)
	if %cmal-tasks% equ true (
		if %RUN% equ true (
			call:header "scheduled tasks and copying tasks files" "listing"
			call:cmd %MAL%\tasks "schtasks /query /FO csv /V"
			call:xcp %MAL%\log "%SystemRoot%\Tasks" "%MAL%\Tasks-live"
			call:xcp %MAL%\log "%SystemRoot%\System32\Tasks" "%MAL%\Tasks32-live"
		) else (set /A it+=1, itt+=3)
		if exist "%PROGRAMFILES(X86)%" (
			if %RUN% equ true (
				call:xcp %MAL%\log "%SystemRoot%\SysWOW64\Tasks" "%MAL%\Tasks64-live"
			) else set /A itt+=1
		)
		if %cmal-vss% equ true (
			for /L %%i in (1,1,%iv%) do (
				if /I %SYSROOTD% equ !vsscd[%%i]! (
					if %RUN% equ true (
						call:xcp %MAL%\log "!vssc[%%i]!%SYSROOTP%\Tasks" "%MAL%\Tasks-!vsscf[%%i]!"
						call:xcp %MAL%\log "!vssc[%%i]!%SYSROOTP%\System32\Tasks" "%MAL%\Tasks32-!vsscf[%%i]!"
					) else set /A itt+=2
					if exist "%PROGRAMFILES(X86)%" (
						if %RUN% equ true (
							call:xcp %MAL%\log "!vssc[%%i]!%SYSROOTP%\SysWOW64\Tasks" "%MAL%\Tasks64-!vsscf[%%i]!"
						) else set /A itt+=1
					)
				)
			)
		)
	)
	if %cmal-ar% equ true (
		if %RUN% equ true (
			call:header "autorun entries"
			call:cmd %MAL%\autoruns\autoruns "%AR% -accepteula -a %MAL%\autoruns\autoruns.arn"
			call:cmd %MAL%\autoruns\autoruns "%ARC% -accepteula -a * -c -h -s -t * | %TR% -dc '[:print:]\n'"
			call:cmdn %MAL%\autoruns\autorun.inf "type *:\autorun.inf"
			for /L %%i in (1,1,%idr%) do (
				call:cmdl %MAL%\autoruns\autorun.inf.txt "type !drivesuc[%%i]!:\autorun.inf"
			)
		) else (mkdir %MAL%\autoruns & set /A it+=1, itt+=3)
	)
	if %cmal-addons% equ true (
		if %RUN% equ true (
			call:header "browsers plugins, add-ons and toolbars"
			call:cmd %MAL%\log "%BAV% /sort Name /scomma %MAL%\browsers-addons.csv"

			call:cmdn %MAL%\addons "reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects /S"
			reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /S >> %MAL%\addons.txt 2>&1
			call:cmdn %MAL%\addons "reg query HKLM\SOFTWARE\Classes\CLSID\*"
			for /F "delims=\ tokens=8,*" %%i in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /S 2^>^&1 ^| findstr /C:"Browser Helper Objects"') do (
				call:cmdr %MAL%\addons "reg query HKLM\SOFTWARE\Classes\CLSID\%%i /S"
			)
			call:cmdn %MAL%\addons "reg query HKLM\SOFTWARE\Microsoft\Internet Explorer\Extensions /S"
			reg query "HKLM\SOFTWARE\Microsoft\Internet Explorer\Extensions" /S >> %MAL%\addons.txt 2>&1
			call:cmdn %MAL%\addons "reg query HKLM\SOFTWARE\Microsoft\Internet Explorer\Toolbar /S"
			reg query "HKLM\SOFTWARE\Microsoft\Internet Explorer\Toolbar" /S >> %MAL%\addons.txt 2>&1
			call:cmd %MAL%\addons "reg query HKLM\SOFTWARE\Google\Chrome\Extensions /S"
			call:cmd %MAL%\addons "reg query HKLM\SOFTWARE\Mozilla /S"
			call:cmd %MAL%\addons "reg query HKLM\SOFTWARE\MozillaPlugins /S"
		) else (set /A it+=1, itt+=8)
		if exist "%PROGRAMFILES(X86)%" (
			if %RUN% equ true (
				call:cmdn %MAL%\addons "reg query HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects /S"
				reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /S >> %MAL%\addons.txt 2>&1
				call:cmdn %MAL%\addons "reg query HKLM\SOFTWARE\Classes\CLSID\*"
				for /F "delims=\ tokens=8,*" %%i in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /S 2^>^&1 ^| findstr /C:"Browser Helper Objects"') do (
					call:cmdr %MAL%\addons "reg query HKLM\SOFTWARE\Classes\CLSID\%%i /S"
				)
				call:cmdn %MAL%\addons "reg query HKLM\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Extensions /S"
				reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Extensions" /S >> %MAL%\addons.txt 2>&1
				call:cmdn %MAL%\addons "reg query HKLM\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Toolbar /S"
				reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Toolbar" /S >> %MAL%\addons.txt 2>&1
				call:cmd %MAL%\addons "reg query HKLM\SOFTWARE\Wow6432Node\Google\Chrome\Extensions /S"
				call:cmd %MAL%\addons "reg query HKLM\SOFTWARE\Wow6432Node\Mozilla /S"
				call:cmd %MAL%\addons "reg query HKLM\SOFTWARE\Wow6432Node\MozillaPlugins /S"
			) else set /A itt+=7
		)
	)
	if %cmal-office% equ true (
		if %RUN% equ true (
			call:header "Office Add-Ins" "listing"
			call:cmd %MAL%\log "%OI% /stext %MAL%\office-addins.txt"
		) else (set /A it+=1, itt+=1)
	)
	:: "findstr /C:'    H' /C:'   S' /C:'   SH' /C:'A   H' /C:'A  S' /C:'A  SH'"
	if %cmal-hid% equ true (
		if %RUN% equ true (
			call:header "hidden files and folders" "listing"
			call:cmdn %MAL%\hidden\dir-hidden "dir /A:H /O:D /Q /T:W %CFG%\nonrecursive.txt"
			call:cmdn %MAL%\hidden\attrib-hidden "attrib /L %CFG%\nonrecursive.txt"
			for /F %%i in (%CFG%\nonrecursive.txt) do (
				call:cmdr %MAL%\hidden\dir-hidden "dir /A:H /O:D /Q /T:W %%i"
				call:cmdr %MAL%\hidden\attrib-hidden "attrib %%i\* /L  %GREP% -E '^A?\s{2,4}[SH]{1,2}.+$'"
			)
			call:cmdn %MAL%\hidden\dir-hidden "dir /A:H /O:D /Q /S /T:W %CFG%\recursive.txt"
			call:cmdn %MAL%\hidden\attrib-hidden "attrib /D /L /S %CFG%\recursive.txt"
			for /F %%i in (%CFG%\recursive.txt) do (
				call:cmdr %MAL%\hidden\dir-hidden "dir /A:H /O:D /Q /S /T:W %%i"
				call:cmdr %MAL%\hidden\attrib-hidden "attrib %%i\* /D /L /S | %GREP% -E '^A?\s{2,4}[SH]{1,2}.+$'"
			)
		) else (mkdir %MAL%\hidden & set /A it+=1, itt+=4)
		if %cmal-vss% equ true (
			if %RUN% equ false set /A itt+=4*%iv%
			for /L %%i in (1,1,%iv%) do (
				if %RUN% equ true (
					call:cmdn %MAL%\hidden\dir-hidden "dir /A:HS /O:D /Q /T:W !vsscf[%%i]!\*"
					call:cmdn %MAL%\hidden\attrib-hidden "attrib /L !vsscf[%%i]!\*"
				)
				for /F %%a in (%CFG%\nonrecursive.txt) do (
					set tmp=%%a
					set tmpp=!tmp:~0,1!
					if /I !tmpp! equ !vsscd[%%i]! (
						if %RUN% equ true (
							call:cmdr %MAL%\hidden\dir-hidden "dir /A:HS /O:D /Q /T:W !vssc[%%i]!!tmp:~2!"
							call:cmdr %MAL%\hidden\attrib-hidden "attrib !vssc[%%i]!!tmp:~2!\* /L | %GREP% -E '^A?\s{2,4}[SH]{1,2}.+$'"
						)
					)
				)
				if %RUN% equ true (
					call:cmdn %MAL%\hidden\dir-hidden "dir /A:HS /O:D /Q /S /T:W !vsscf[%%i]!\*"
					call:cmdn %MAL%\hidden\attrib-hidden "attrib /D /L /S !vsscf[%%i]!\*"
				)
				for /F %%a in (%CFG%\recursive.txt) do (
					set tmp=%%a
					set tmpp=!tmp:~0,1!
					if /I !tmpp! equ !vsscd[%%i]! (
						if %RUN% equ true (
							call:cmdr %MAL%\hidden\dir-hidden "dir /A:HS /O:D /Q /S /T:W !vssc[%%i]!!tmp:~2!"
							call:cmdr %MAL%\hidden\attrib-hidden "attrib !vssc[%%i]!!tmp:~2!\* /D /L /S | %GREP% -E '^A?\s{2,4}[SH]{1,2}.+$'"
						)
					)
				)
			)
		)
	)
	if %cmal-startup% equ true (
		if %RUN% equ true (
			call:header "user and system startup items" "copying"
			call:cmdn %MAL%\log "xcopy *\Startup %MAL%\Startup-*-live /C /E /F /H /I /Y"
			xcopy "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup" %MAL%\Startup-sys-live /C /E /F /H /I /Y >> %MAL%\log.txt 2>&1
			for /L %%i in (1,1,%ip%) do (
				xcopy "!ustartup[%%i]!" %MAL%\Startup-!usersp[%%i]!-live /C /E /F /H /I /Y >> %MAL%\log.txt 2>&1
			)
		) else (set /A it+=1, itt+=1)
		if %cmal-vss% equ true (
			for /L %%i in (1,1,%ip%) do (
				if %RUN% equ true (
					call:cmdn %MAL%\log "xcopy vss*\Startup %MAL%\Startup-*-* /C /E /F /H /I /Y"
				) else set /A itt+=1
				if %RUN% equ true (
					for /L %%a in (1,1,%iv%) do (
						if /I %UPROFILED% equ !vsscd[%%a]! (
							xcopy "!vssc[%%a]!!ustartup[%%i]:~2!" %MAL%\Startup-!usersp[%%i]!-!vsscf[%%a]! /C /E /F /H /I /Y >> %MAL%\log.txt 2>&1
						)
						if /I %SYSROOTD% equ !vsscd[%%a]! (
							xcopy "!vssc[%%a]!%ProgramData:~2%\Microsoft\Windows\Start Menu\Programs\Startup" %MAL%\Startup-sys-!vsscf[%%a]! /C /E /F /H /I /Y >> %MAL%\log.txt 2>&1
						)
					)
				)
			)
		)
	)
	goto:eof

:memory
	if %cmem% equ true (if %RUN% equ false mkdir %MEM%)

	if %cmem-dump% equ true (
		if %RUN% equ true (
			call:header "live memory" "dumping"
			call:cmd %MEM%\log "%PMEM% -d %TEMPIR%\pmem.tmp %MEM%\raw.mem"
		) else (set /A it+=1, itt+=1)
	)
	goto:eof

:memory-contd
	if %cmem-pf% equ true (
		if %RUN% equ true (
			call:header "the memory page file(s)"
			call:cmd %MEM%\log "%RCP% /FileNamePath:!tmem-pf! /OutputPath:%MEM%"
			ren %MEM%\%tmem-pf:~3% %tmem-pf:~3,-4%-live.%tmem-pf:~-3% > NUL 2>&1
		) else (
			set /A it+=1, itt+=1
			for /F "skip=2 tokens=1-3" %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /V ExistingPageFiles') do (
				set tmem-pf=%%k
				set tmem-pf=!tmem-pf:~4!
			)
		)
		if %cmem-vss% equ true (
			set tmp=!tmem-pf:~0,1!
			for /L %%i in (1,1,%iv%) do (
				if /I !tmp! equ !vsscd[%%i]! (
					if %RUN% equ true (
						call:xcp %MEM%\log "!vssc[%%i]!%tmem-pf:~2%" "%MEM%"
						call:attren "%MEM%\%tmem-pf:~3%" "%tmem-pf:~3,-4%-!vsscf[%%i]!.%tmem-pf:~-3%"
					) else set /A itt+=1
				)
			)
		)
	)
	if %cmem-hf% equ true (
		if %RUN% equ true (
			call:header "the memory hibernation file(s)" "copying"
			call:cmd %MEM%\log "%RCP% /FileNamePath:%SystemDrive%\hiberfil.sys /OutputPath:%MEM%"
			ren %MEM%\hiberfil.sys hiberfil-live.sys > NUL 2>&1
		) else (set /A it+=1, itt+=1)
		if %cmem-vss% equ true (
			for /L %%i in (1,1,%iv%) do (
				if /I %SystemDrive:~0,1% equ !vsscd[%%i]! (
					if %RUN% equ true (
						call:xcp %MEM%\log "!vssc[%%i]!\hiberfil.sys" "%MEM%"
						call:attren "%MEM%\hiberfil.sys" "hiberfil-!vsscf[%%i]!.sys"
					) else set /A itt+=1
				)
			)
		)
	)
	if %cmem-md% equ true (
		if %RUN% equ true (
			call:header "the Windows crash dump(s)" "copying"
			call:xcp %MEM%\log "!tmem-md!" "%MEM%\Minidump-live"
		) else (
			for /F "skip=2 tokens=1-3" %%i in ('reg query "HKLM\System\CurrentControlSet\Control\CrashControl" /V MinidumpDir') do (set tmem-md=%%k)
			set /A it+=1, itt+=1
		)
		if %cmem-vss% equ true (
			for /F "delims=" %%i in ('echo !tmem-md!') do set tmp=%%i
			set tmpp=!tmp:~0,1!
			for /L %%i in (1,1,%iv%) do (
				if /I !tmpp! equ !vsscd[%%i]! (
					if %RUN% equ true (
						call:xcp %MEM%\log "!vssc[%%i]!!tmp:~2!" "%MEM%\Minidump-!vsscf[%%i]!"
					) else set /A itt+=1
				)
			)
		)
	)
	if %cmem-ad% equ true (
		if %RUN% equ true (
			call:header "user application crash dumps" "copying"
			call:cmdn %MEM%\appdumps "reg query HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps /S"
			reg query "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" /S >> %MEM%\appdumps.txt 2>&1
			for /L %%i in (1,1,%ip%) do (
				call:xcp %MEM%\log "!uprofiles[%%i]!\AppData\Local\CrashDumps" "%MEM%\CrashDumps-!usersp[%%i]!-live"
			)
		) else (set /A it+=1, itt+=1+%ip%)
		if %cmem-vss% equ true (
			for /L %%i in (1,1,%ip%) do (
				for /L %%a in (1,1,%iv%) do (
					if /I %UPROFILED% equ !vsscd[%%a]! (
						if %RUN% equ true (
							call:xcp %MEM%\log "!vssc[%%a]!!uprofiles[%%i]:~2!\AppData\Local\CrashDumps" "%MEM%\CrashDumps-!usersp[%%i]!-!vsscf[%%a]!"
						) else set /A itt+=1
					)
				)
			)
		)
	)
	goto:eof

:network
	if %cnet% equ true (if %RUN% equ false mkdir %NET%)
	:: NirSoft CurrPorts "cports.exe"
	:: "nmap -sn --traceroute www.google.com"
	:: nping, ncat
	:: no portable versions
	:: "netstat -nr"
	if %cnet% equ true (
		if %RUN% equ true (
			call:header "network data"
			call:cmd %NET%\ip "ipconfig /all"
			call:cmd %NET%\ip "ipconfig /displaydns"
			call:cmd %NET%\conn "netstat -abno"
			call:cmd %NET%\conn "%TCPV% -accepteula -a -n -c"
			call:cmd %NET%\netbios "nbtstat -c"
			call:cmd %NET%\netbios "nbtstat -n"
			call:cmd %NET%\netbios "nbtstat -S"
			call:cmd %NET%\tables "route print"
			call:cmd %NET%\tables "arp -a"
			call:cmd %NET%\net "net use"
			call:cmd %NET%\net "net sessions"
			call:cmd %NET%\net "net view"
			call:cmd %NET%\shares "net statistics server"
			call:cmd %NET%\shares "net statistics workstation"
			call:cmd %NET%\shares "net share"
			call:cmd %NET%\shares "net files"
			call:cmd %NET%\shares "openfiles"
			call:cmd %NET%\shares "%PSF% -accepteula"
		) else (set /A it+=1, itt+=18)
	)
	goto:eof

:network-contd
	if %cnet% equ true (
		if %RUN% equ true (
			call:header "more network data"
			call:cmd %NET%\intf "netsh interface show interface"
			call:cmd %NET%\intf "netsh mbn show interface"
			call:cmd %NET%\intf "netsh bridge show adapter"
			call:cmd %NET%\intf "netsh interface dump"
			call:cmd %NET%\intf "netsh bridge dump"
			call:cmd %NET%\proxy "netsh interface portproxy show all"
			call:cmd %NET%\conn "ping -a -n 1 %cnet-targ%"
			call:cmd %NET%\conn "tracert -h 16 -w 256 %cnet-targ%"
			call:xcp %NET%\log "%SystemRoot%\System32\drivers\etc\hosts" "%NET%\"
			call:xcp %NET%\log "%SystemRoot%\System32\drivers\etc\lmhosts.sam" "%NET%\"
		) else (set /A it+=1, itt+=10)
	)
	goto:eof

:registry
	if %creg% equ true (if %RUN% equ false mkdir %REG%)

	if %creg-sys% equ true (
		if %RUN% equ true (
			call:header "system registry hives"
			call:cmd %REG%\log "%RCP% /FileNamePath:%SystemRoot%\System32\config\SAM /OutputPath:%REG%\sys"
			call:cmd %REG%\log "%RCP% /FileNamePath:%SystemRoot%\System32\config\SECURITY /OutputPath:%REG%\sys"
			call:cmd %REG%\log "%RCP% /FileNamePath:%SystemRoot%\System32\config\SOFTWARE /OutputPath:%REG%\sys"
			call:cmd %REG%\log "%RCP% /FileNamePath:%SystemRoot%\System32\config\SYSTEM /OutputPath:%REG%\sys"
			ren %REG%\sys\SAM SAM-live
			ren %REG%\sys\SECURITY SECURITY-live
			ren %REG%\sys\SOFTWARE SOFTWARE-live
			ren %REG%\sys\SYSTEM SYSTEM-live
		) else (mkdir %REG%\sys & set /A it+=1, itt+=4)
		if %creg-vss% equ true (
			for /L %%i in (1,1,%iv%) do (
				if /I %SYSROOTD% equ !vsscd[%%i]! (
					if %RUN% equ true (
						call:cpf %REG%\log "!vssc[%%i]!%SYSROOTP%\System32\config\SAM" "%REG%\sys\SAM-!vsscf[%%i]!"
						call:cpf %REG%\log "!vssc[%%i]!%SYSROOTP%\System32\config\SECURITY" "%REG%\sys\SECURITY-!vsscf[%%i]!"
						call:cpf %REG%\log "!vssc[%%i]!%SYSROOTP%\System32\config\SOFTWARE" "%REG%\sys\SOFTWARE-!vsscf[%%i]!"
						call:cpf %REG%\log "!vssc[%%i]!%SYSROOTP%\System32\config\SYSTEM" "%REG%\sys\SYSTEM-!vsscf[%%i]!"
					) else set /A itt+=4
				)
			)
		)
	)
	if %creg-user% equ true (
		set /A tmp=0
		if %RUN% equ true (
			call:header "user registry hives"
			for /L %%i in (1,1,%ip%) do (
				call:cmdn %REG%\log "%RCP% /FileNamePath:!uprofiles[%%i]!\NTUSER.dat /OutputPath:%REG%\user\"
				%RCP% /FileNamePath:"!uprofiles[%%i]!\NTUSER.dat" /OutputPath:%REG%\user\ >> %REG%\log.txt 2>&1
				call:cmdn %REG%\log "%RCP% /FileNamePath:!uprofiles[%%i]!\AppData\Local\Microsoft\Windows\UsrClass.dat /OutputPath:%REG%\user\"
				%RCP% /FileNamePath:"!uprofiles[%%i]!\AppData\Local\Microsoft\Windows\UsrClass.dat" /OutputPath:%REG%\user\ >> %REG%\log.txt 2>&1
				call:attren "%REG%\user\NTUSER.dat" "NTUSER-!usersp[%%i]!-live.dat"
				call:attren "%REG%\user\UsrClass.dat" "UsrClass-!usersp[%%i]!-live.dat"
			)
		) else (mkdir %REG%\user & set /A it+=1, itt+=2*%ip%, tmp+=%ip%)
		if %creg-vss% equ true (
			for /L %%i in (1,1,%ip%) do (
				for /L %%a in (1,1,%iv%) do (
					if /I %UPROFILED% equ !vsscd[%%a]! (
						if %RUN% equ true (
							call:xcp %REG%\log "!vssc[%%a]!!uprofiles[%%i]:~2!\NTUSER.dat" "%REG%\user"
							call:attren "%REG%\user\NTUSER.dat" "NTUSER-!usersp[%%i]!-!vsscf[%%a]!.dat"
							call:xcp %REG%\log "!vssc[%%a]!!uprofiles[%%i]:~2!\AppData\Local\Microsoft\Windows\UsrClass.dat" "%REG%\user"
							call:attren "%REG%\user\UsrClass.dat" "UsrClass-!usersp[%%i]!-!vsscf[%%a]!.dat"
						) else (set /A itt+=2, tmp+=1)
					)
				)
			)
		)
	)
	if %creg-text% equ true (
		if %RUN% equ true (
			call:header "registry hives" "exporting"
			call:cmd %REG%\log "reg export HKCR %REG%\txt\hkcr.reg /Y"
			call:cmd %REG%\log "reg export HKLM %REG%\txt\hklm.reg /Y"
			call:cmd %REG%\log "reg export HKU %REG%\txt\hku.reg /Y"
		) else (mkdir %REG%\txt & set /A it+=1, itt+=3)
	)
	:: export in text
	:: for /F "tokens=*" %%p in ('reg query HKU') do (
	::	set key=%%p
	::	set key=!key:\=-!.txt
	::	call:cmd %REG%\log "reg export %%p %REG%\hives\!key!"
	:: )
	:: reg save HKLM\key reg.hiv
	goto:eof

:system
	if %csys% equ true (if %RUN% equ false mkdir %SYS%)

	:: "setx /?"
	if %csys-info% equ true (
		if %RUN% equ true (
			call:header "system information"
			call:cmd %SYS%\sys "date /T"
			call:cmd %SYS%\sys "w32tm /query /status"
			call:cmd %SYS%\sys "net time"
			call:cmd %SYS%\sys "hostname"
			call:cmd %SYS%\sys "ver"
			call:cmd %SYS%\sys "type set.txt.tmp"
			call:cmd %SYS%\sys "systeminfo"
			call:cmd %SYS%\sys "%PSI% -accepteula -h -s -d"
			call:cmd %SYS%\sys "powercfg /query"
		) else (set /A it+=1, itt+=9)
	)
	if %csys-acc% equ true (
		if %RUN% equ true (
			call:header "Windows user account and login data"
			call:cmd %SYS%\acc "whoami"
			call:cmd %SYS%\acc "%PSLO% -accepteula"
			call:cmd %SYS%\acc "%PSL% -accepteula -c -p"
			call:cmd %SYS%\acc "cmdkey /list"
			call:cmd %SYS%\acc "net accounts"
			call:cmd %SYS%\acc "net localgroup"
			call:cmd %SYS%\acc "net localgroup Administrators"
			call:cmd %SYS%\acc "net localgroup Users"
			call:cmd %SYS%\acc "net localgroup HomeUsers"
			call:cmd %SYS%\acc "net localgroup Guests"
			call:cmd %SYS%\sid "%PSG% -accepteula \\%COMPUTERNAME%"
			for /L %%i in (1,1,%iu%) do (
				net user !users[%%i]! /domain > NUL 2>&1
				if not !errorLevel! equ 0 (
					call:cmd %SYS%\acc "net user !users[%%i]!"
				) else (
					call:cmd %SYS%\acc "net user !users[%%i]! /domain"
				)
				call:cmd %SYS%\sid "%PSG% -accepteula !usid[%%i]!"
			)
		) else (set /A it+=1, itt+=11+2*%iu%)
	)
	if %csys-sec% equ true (
		if %RUN% equ true (
			call:header "system security information"
			call:cmd %SYS%\firewall "netsh firewall show config verbose=enable"
			call:cmd %SYS%\firewall "netsh advfirewall show global"
			call:cmd %SYS%\firewall "netsh advfirewall show allprofiles"
			call:cmd %SYS%\firewall "netsh advfirewall dump"
			call:cmd %SYS%\firewall "netsh advfirewall firewall dump"
			call:cmd %SYS%\firewall "netsh firewall show allowedprogram verbose=enable"
			call:cmd %SYS%\firewall "netsh advfirewall firewall show rule name=all verbose"
			call:cmd %SYS%\firewall "netsh advfirewall firewall show logging"
			call:cmd %SYS%\firewall "type %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log"
			call:cmd %SYS%\httperr "type %SystemRoot%\System32\LogFiles\HTTPERR\httperr*.log"
			call:cmd %SYS%\cert "certutil -store CA"
			call:cmd %SYS%\cert "certutil -store Root"
		) else (set /A it+=1, itt+=12)
	)
	:: ACL for C$, D$, ADMIN$, IPC$?
	:: "icacls %SystemDrive%\Users\* /C"
	if %csys-acl% equ true (
		if %RUN% equ true (
			call:header "ACL permissions"
			call:cmdn %SYS%\acl "%AC% -accepteula -d -l %CFG%\nonrecursive-acl"
			for /F %%i in (%CFG%\nonrecursive-accesschk.txt) do (
				call:cmdr %SYS%\acl "%AC% -accepteula -d -l %%i"
			)
			call:cmdn %SYS%\acl "%AC% -accepteula -l %CFG%\recursive-acl"
			for /F %%i in (%CFG%\recursive-accesschk.txt) do (
				call:cmdr %SYS%\acl "%AC% -accepteula -l %%i"
			)
		) else (set /A it+=1, itt+=2)
	)
	goto:eof

:web
	if %cweb% equ true (if %RUN% equ false mkdir %WEB%)

	if %cweb-hist% equ true (
		if %RUN% equ true (
			call:header "Internet browsing history"
			call:cmd %WEB%\log "%BHV% /HistorySource 1 /VisitTimeFilterType 1 /LoadIE 1 /LoadFirefox 1 /LoadChrome 1 /LoadSafari 0 /sort ~2 /scomma %WEB%\browsing-history.csv"
		) else (set /A it+=1, itt+=1)
	)
	if %cweb-chrome% equ true (
		if %RUN% equ true (
			call:header "the Google Chrome cache"
			call:cmd %WEB%\log "%CCV% /scomma %WEB%\cache-chrome.csv"
			call:cmdn %WEB%\log "%CCV% /copycache /CopyFilesFolder %WEB%\cache-chrome /UseWebSiteDirStructure 0"
			%CCV% /copycache "" "" /CopyFilesFolder "%WEB%\cache-chrome" /UseWebSiteDirStructure 0 >> %WEB%\log.txt 2>&1
		) else (mkdir %WEB%\cache-chrome & set /A it+=1, itt+=2)
	)
	if %cweb-ie% equ true (
		if %RUN% equ true (
			call:header "the Internet Explorer cache"
			call:cmd %WEB%\log "%IECV% /scomma %WEB%\cache-ie.csv"
			call:cmdn %WEB%\log "%IECV% /copycache /CopyFilesFolder %WEB%\cache-ie /UseWebSiteDirStructure 0"
			%IECV% /copycache "" "" /CopyFilesFolder "%WEB%\cache-ie" /UseWebSiteDirStructure 0 >> %WEB%\log.txt 2>&1
		) else (mkdir %WEB%\cache-ie & set /A it+=1, itt+=2)
	)
	if %cweb-moz% equ true (
		if %RUN% equ true (
			call:header "the Mozilla Firefox cache"
			call:cmd %WEB%\log "%MCV% /scomma %WEB%\cache-mozilla.csv"
			call:cmdn %WEB%\log "%MCV% /copycache /CopyFilesFolder %WEB%\cache-mozilla /UseWebSiteDirStructure 0"
			%MCV% /copycache "" "" /CopyFilesFolder "%WEB%\cache-mozilla" /UseWebSiteDirStructure 0 >> %WEB%\log.txt 2>&1
		) else (mkdir %WEB%\cache-mozilla & set /A it+=1, itt+=2)
	)
	goto:eof


:sigcheck
	if %csigcheck% equ true (if %RUN% equ false (mkdir %MAL% & set /A it+=1))
	if %csigcheck% equ true (
		if %RUN% equ true (
			call:header "digital signatures and certificates of programs" "checking"
			call:cmdn %MAL%\sig "%SIG% -accepteula -nobanner -a -c -e -h %CFG%\nonrecursive.txt"
			for /F %%i in (%CFG%\nonrecursive.txt) do (
				call:cmdr %MAL%\sig "%SIG% -accepteula -nobanner -a -c -e -h %%i"
			)
			call:cmdn %MAL%\sig "%SIG% -accepteula -nobanner -a -c -e -h -s %CFG%\recursive.txt"
			for /F %%i in (%CFG%\recursive.txt) do (
				call:cmdr %MAL%\sig "%SIG% -accepteula -nobanner -a -c -e -h -s %%i"
			)
		) else set /A itt+=2
	)
	goto:eof

:density
	if %cdensity% equ true (if %RUN% equ false (mkdir %MAL% & set /A it+=1))
	if %cdensity% equ true (
		if %RUN% equ true (
			call:header "density values of programs" "computing"
			call:cmdn %MAL%\density "%DS% %CFG%\nonrecursive.txt -o %MAL%\density\*.txt"
			for /F %%i in (%CFG%\nonrecursive.txt) do (
				set str=%%i
				set str=!str:\=-!
				set str=!str::=!
				call:cmdr %MAL%\density "%DS% %%i -o %MAL%\density\!str!.txt | %TR% -dc '[:print:]\n'"
			)
			call:cmdn %MAL%\density "%DS% -r %CFG%\recursive.txt -o %MAL%\density\*.txt"
			for /F %%i in (%CFG%\recursive.txt) do (
				set str=%%i
				set str=!str:\=-!
				set str=!str::=!
				call:cmdr %MAL%\density "%DS% -r %%i -o %MAL%\density\!str!.txt | %TR% -dc '[:print:]\n'"
			)
		) else set /A itt+=2
	)
	goto:eof

:iconsext
	if %ciconsext% equ true (if %RUN% equ false (mkdir %MAL% & set /A it+=1))
	if %ciconsext% equ true (
		if %RUN% equ true (
			call:header "icons of programs" "extracting"
			call:cmdn %MAL%\log "%IE% /save %CFG%\nonrecursive-iconsext.txt %MAL%\icons\* -icons"
			for /F %%i in (%CFG%\nonrecursive-iconsext.txt) do (
				set str=%%i
				set str=!str:\=-!
				set str=!str::=!
				for /F "tokens=*" %%j in ('dir /A /B %%i\*.exe') do (
					call:cmdr %MAL%\log "%IE% /save %%j %MAL%\icons\!str!\exe\%%~nj -icons"
				)
				for /F "tokens=*" %%j in ('dir /A /B %%i\*.dll 2^>^&1 ^| findstr /V "imageres\.dll shell32\.dll netshell\.dll"') do (
					call:cmdr %MAL%\log "%IE% /save %%j %MAL%\icons\!str!\dll\%%~nj -icons"
				)
			)
			call:cmdn %MAL%\log "%IE% /save %CFG%\recursive-iconsext.txt %MAL%\icons\* -icons"
			for /F %%i in (%CFG%\recursive-iconsext.txt) do (
				set str=%%i
				set str=!str:\=-!
				set str=!str::=!
				for /F "tokens=*" %%j in ('dir /A /B /S %%i\*.exe') do (
					call:cmdr %MAL%\log "%IE% /save %%j %MAL%\icons\!str!\exe\%%~nj -icons"
				)
				for /F "tokens=*" %%j in ('dir /A /B /S %%i\*.dll 2^>^&1 ^| findstr /V "imageres\.dll shell32\.dll netshell\.dll"') do (
					call:cmdr %MAL%\log "%IE% /save %%j %MAL%\icons\!str!\dll\%%~nj -icons"
				)
			)
		) else set /A itt+=2
	)
	goto:eof

:yara
	if %cyara% equ true (if %RUN% equ false (mkdir %MAL% & set /A it+=1))
	if %cyara% equ true (
		if %RUN% equ true (
			call:header "YARA scans" "running"
			call:cmdn %MAL%\yara "%YAR% -m *.yar *"
			for /F "tokens=*" %%i in ('dir /B /S %TOOLS%\yara\rules\*.yar') do (
				for /F %%j in (%CFG%\nonrecursive.txt) do (
					call:cmdr %MAL%\yara "%YAR% -m %%i %%j"
				)
				for /F %%j in (%CFG%\recursive.txt) do (
					call:cmdr %MAL%\yara "%YAR% -m -r %%i %%j"
				)
			)
		) else set /A itt+=2
	)
	goto:eof


:header <msg> <term>
	call:datetm
	set /A in+=1
	set col=collecting
	if not "%~2" equ "" set "col=%~2"
	echo  %datetime% %in% out of !it!: "%col% %~1"
	goto:eof

:cmdr <logf> <cmd>
	(%~2) >> %~1.txt 2>&1
	goto:eof

:cmd <logf> <cmd>
	call:cmdn %1 %2
	(%~2) >> %~1.txt 2>&1
	goto:eof

:cmdn <logf> <cmd>
	call:datetm
	set /A inn+=1
	echo  %datetime% %COMPUTERNAME% running %inn% out of %itt%: %2 >> %LOG%
	echo  %datetime% %COMPUTERNAME% running %inn% out of %itt%: %2 >> %SYSROOTT%
	echo. >> %~1.txt
	echo %NAME%-%VER% %datetime% (%TZ%): %2 >> %~1.txt
	echo. >> %~1.txt
	goto:eof

:cmdl <logf> <cmd>
	call:datetm
	echo. >> %~1
	echo %NAME%-%VER% %datetime% (%TZ%): %2 >> %~1
	echo. >> %~1
	(%~2) >> %~1 2>&1
	goto:eof

:attren <srcfd> <dstfd>
	attrib -H -S %~1 > NUL 2>&1
	ren %~1 %~2 > NUL 2>&1
	goto:eof

:cpf <logf> <srcf> <dstf>
	:: "copy" sees hidden files, "xcopy" does not --> yes it does with '/H'
	call:cmd %~1 "copy %~2 %~3 /Y"
	goto:eof

:cpfl <logf> <srcf> <dstf>
	call:cmdl %~1 "copy %~2 %~3 /Y"
	goto:eof

:xcp <logf> <src> <dst>
	call:cmd %~1 "xcopy %~2 %~3 /C /F /H /I /Y"
	goto:eof

:vssoff
	for /L %%i in (1,1,%iv%) do (
		rmdir !vssc[%%i]! > NUL 2>&1
	)
	goto:eof

:vsson
	for /L %%i in (1,1,%iv%) do (
		mklink /D !vssc[%%i]! !vsscl[%%i]! > NUL 2>&1
	)
	goto:eof

:date
	:: intrusive
	for /F "tokens=3 delims= " %%i in ('reg query "HKCU\Control Panel\International" 2^>^&1 ^| findstr "sShortDate"') do set "hkcuShortDate=%%i"
	for /F "tokens=3 delims= " %%i in ('reg query "HKCU\Control Panel\International" 2^>^&1 ^| findstr "sShortDate"') do set "hkuShortDate=%%i"
	reg add "HKCU\Control Panel\International" /F /V sShortDate /T REG_SZ /D "yyyyMMdd" > NUL 2>&1
	reg add "HKU\.DEFAULT\Control Panel\International" /F /V sShortDate /T REG_SZ /D "yyyyMMdd" > NUL 2>&1
	set YYYYMMDD=%date%
	reg add "HKCU\Control Panel\International" /F /V sShortDate /T REG_SZ /D "%hkcuShortDate%" > NUL 2>&1
	reg add "HKU\.DEFAULT\Control Panel\International" /F /V sShortDate /T REG_SZ /D "%hkuShortDate%" > NUL 2>&1
	call:len YYYYMMDD len
	if %len% neq 8 set YYYYMMDD=DATE-UNAVAIL
	call:datetm
	:: nonintrusive
	:: if "%date%A" lss "A" (set tok=1-3) else (set tok=2-4)
	:: for /F "tokens=2-4 delims=(-)" %%i in ('echo:^| date') do (
	:: 	for /F "tokens=%tok% delims=.-/ " %%a in ('date /T') do (
	:: 		set '%%i'=%%a
	:: 		set '%%j'=%%b
	:: 		set '%%k'=%%c
	:: 	)
	:: )
	:: if %'yy'% lss 99 set 'yy'=20%'yy'%
	:: regional independent date
	:: set YYYYMMDD=%'yy'%%'mm'%%'dd'%
	:: set datetime=%YYYYMMDD% %TIME%
	goto:eof

:datetm
	set datetime=%YYYYMMDD% %TIME%
	goto:eof

:timestamp
	call:datetm
	call:msg "%NAME%-%VER% %YYYYMMDD% %TIME% (%TZ%)"
	goto:eof

:msg <msg>
	echo.&echo %~1
	echo. >> %LOG%
	echo %~1 >> %LOG%
	goto:eof

:init
	echo.
	cd /d %~dp0

	:: variables
	call:date
	set NAME=ir-rescue-win
	set VER=v1.4.3
	set TOOLS=tools-win

	set CFG=%TOOLS%\cfg
	set CONF=%CFG%\%NAME%.conf
	set TEMPIR=%TEMP%\%NAME%

	set GREP=%TOOLS%\cygwin\grep.exe
	set NIRC=%TOOLS%\nircmdc.exe
	set TR=%TOOLS%\cygwin\tr.exe
	set SDEL=%TOOLS%\sdelete.exe
	set ZIP=%TOOLS%\7za.exe

	set AC=%TOOLS%\sys\accesschk.exe
	set ADS=%TOOLS%\fs\AlternateStreamView.exe
	set AR=%TOOLS%\mal\autoruns.exe
	set ARC=%TOOLS%\mal\autorunsc.exe
	set BAV=%TOOLS%\mal\BrowserAddonsView.exe
	set BHV=%TOOLS%\web\BrowsingHistoryView.exe
	set CCV=%TOOLS%\web\ChromeCacheView.exe
	set DS=%TOOLS%\mal\densityscout.exe
	set DV=%TOOLS%\mal\DriverView.exe
	set EDD=%TOOLS%\disk\EDD.exe
	set EUJ=%TOOLS%\fs\ExtractUsnJrnl.exe
	set EXIF=%TOOLS%\activ\exiftool.exe
	set FLS=%TOOLS%\fs\tsk\fls.exe
	set IE=%TOOLS%\mal\iconsext.exe
	set IECV=%TOOLS%\web\IECacheView.exe
	set JLEC=%TOOLS%\activ\JLECmd.exe
	set LAV=%TOOLS%\activ\LastActivityView.exe
	set MCV=%TOOLS%\web\MozillaCacheView.exe
	set MD5=%TOOLS%\fs\md5deep.exe
	set MMCAT=%TOOLS%\fs\tsk\mmcat.exe
	set MMLS=%TOOLS%\fs\tsk\mmls.exe
	set NTFS=%TOOLS%\fs\ntfsinfo.exe
	set OI=%TOOLS%\mal\OfficeIns.exe
	set PLL=%TOOLS%\evt\psloglist.exe
	set PMEM=%TOOLS%\mem\winpmem_1.6.2.exe
	set PSD=%TOOLS%\mal\Listdlls.exe
	set PSF=%TOOLS%\net\psfile.exe
	set PSG=%TOOLS%\sys\PsGetsid.exe
	set PSH=%TOOLS%\mal\handle.exe
	set PSI=%TOOLS%\sys\Psinfo.exe
	set PSL=%TOOLS%\sys\logonsessions.exe
	set PSLO=%TOOLS%\sys\psloggedon.exe
	set PSP=%TOOLS%\mal\pslist.exe
	set PSS=%TOOLS%\mal\PsService.exe
	set RB=%TOOLS%\activ\rifiuti-vista.exe
	set RCP=%TOOLS%\fs\RawCopy.exe
	set SIG=%TOOLS%\mal\sigcheck.exe
	set TCPV=%TOOLS%\net\tcpvcon.exe
	set USB=%TOOLS%\activ\USBDeview.exe
	set WPV=%TOOLS%\mal\WinPrefetchView.exe
	set YAR=%TOOLS%\yara\yara32.exe
	if exist "%PROGRAMFILES(X86)%" (
		set AC=%TOOLS%\sys\accesschk64.exe
		set ADS=%TOOLS%\fs\AlternateStreamView64.exe
		set AR=%TOOLS%\mal\Autoruns64.exe
		set ARC=%TOOLS%\mal\autorunsc64.exe
		set BAV=%TOOLS%\mal\BrowserAddonsView64.exe
		set BHV=%TOOLS%\web\BrowsingHistoryView64.exe
		set DS=%TOOLS%\mal\densityscout64.exe
		set DV=%TOOLS%\mal\DriverView64.exe
		set EUJ=%TOOLS%\fs\ExtractUsnJrnl64.exe
		set MD5=%TOOLS%\fs\md5deep64.exe
		set NIRC=%TOOLS%\nircmdc64.exe
		set NTFS=%TOOLS%\fs\ntfsinfo64.exe
		set OI=%TOOLS%\mal\OfficeIns64.exe
		set PSD=%TOOLS%\mal\Listdlls64.exe
		set PSF=%TOOLS%\net\psfile64.exe
		set PSG=%TOOLS%\sys\PsGetsid64.exe
		set PSH=%TOOLS%\mal\handle64.exe
		set PSI=%TOOLS%\sys\PsInfo64.exe
		set PSL=%TOOLS%\sys\logonsessions64.exe
		set PSLO=%TOOLS%\sys\PsLoggedon64.exe
		set PSP=%TOOLS%\mal\pslist64.exe
		set PSS=%TOOLS%\mal\PsService64.exe
		set RB=%TOOLS%\activ\rifiuti-vista64.exe
		set RCP=%TOOLS%\fs\RawCopy64.exe
		set SDEL=%TOOLS%\sdelete64.exe
		set SIG=%TOOLS%\mal\sigcheck64.exe
		set USB=%TOOLS%\activ\USBDeview64.exe
		set WPV=%TOOLS%\mal\WinPrefetchView64.exe
		set YAR=%TOOLS%\yara\yara64.exe
	)

	:: if !cascii! equ true within if %f%, does not work due to variable expansion for some reason
	set ASCII=""
	for %%i in (%TOOLS%\ascii\*.txt) do (
		set /A ia+=1
		set "asciiart[!ia!]=%%~i"
	)
	set /A "rand=(!ia!*%random%)/32768+1"
	set ASCII=!asciiart[%rand%]!
	if "%ASCII%" equ "" set ASCII=""

	:: timezone
	for /F "usebackq tokens=*" %%i in (`tzutil /g`) do set TZ=%%i

	cls
	echo.&echo   initializing...
	set /A f=0

	:: check tools and files
	if not exist %AC%	 (echo.&echo  ERROR: %AC% not found. & set /A f=1)
	if not exist %ADS%	 (echo.&echo  ERROR: %ADS% not found. & set /A f=1)
	if not exist %AR%	 (echo.&echo  ERROR: %AR% not found. & set /A f=1)
	if not exist %ARC%	 (echo.&echo  ERROR: %ARC% not found. & set /A f=1)
	if not exist %BAV%	 (echo.&echo  ERROR: %BAV% not found. & set /A f=1)
	if not exist %BHV%	 (echo.&echo  ERROR: %BHV% not found. & set /A f=1)
	if not exist %CCV%	 (echo.&echo  ERROR: %CCV% not found. & set /A f=1)
	if not exist %CONF%	 (echo.&echo  ERROR: %CONF% not found. & set /A f=1)
	if not exist %DS%	 (echo.&echo  ERROR: %DS% not found. & set /A f=1)
	if not exist %DV%	 (echo.&echo  ERROR: %DV% not found. & set /A f=1)
	if not exist %EUJ%	 (echo.&echo  ERROR: %EUJ% not found. & set /A f=1)
	if not exist %EXIF%	 (echo.&echo  ERROR: %EXIF% not found. & set /A f=1)
	if not exist %FLS%	 (echo.&echo  ERROR: %FLS% not found. & set /A f=1)
	if not exist %GREP%	 (echo.&echo  ERROR: %GREP% not found. & set /A f=1)
	if not exist %IE%	 (echo.&echo  ERROR: %IE% not found. & set /A f=1)
	if not exist %IECV%	 (echo.&echo  ERROR: %IECV% not found. & set /A f=1)
	if not exist %JLEC%	 (echo.&echo  ERROR: %JLEC% not found. & set /A f=1)
	if not exist %LAV%	 (echo.&echo  ERROR: %LAV% not found. & set /A f=1)
	if not exist %MCV%	 (echo.&echo  ERROR: %MCV% not found. & set /A f=1)
	if not exist %MD5%	 (echo.&echo  ERROR: %MD5% not found. & set /A f=1)
	if not exist %NIRC%	 (echo.&echo  ERROR: %NIRC% not found. & set /A f=1)
	if not exist %NTFS%	 (echo.&echo  ERROR: %NTFS% not found. & set /A f=1)
	if not exist %OI%	 (echo.&echo  ERROR: %OI% not found. & set /A f=1)
	if not exist %PLL%	 (echo.&echo  ERROR: %PLL% not found. & set /A f=1)
	if not exist %PMEM%	 (echo.&echo  ERROR: %PMEM% not found. & set /A f=1)
	if not exist %PSD%	 (echo.&echo  ERROR: %PSD% not found. & set /A f=1)
	if not exist %PSF%	 (echo.&echo  ERROR: %PSF% not found. & set /A f=1)
	if not exist %PSG%	 (echo.&echo  ERROR: %PSG% not found. & set /A f=1)
	if not exist %PSH%	 (echo.&echo  ERROR: %PSH% not found. & set /A f=1)
	if not exist %PSI%	 (echo.&echo  ERROR: %PSI% not found. & set /A f=1)
	if not exist %PSL%	 (echo.&echo  ERROR: %PSL% not found. & set /A f=1)
	if not exist %PSLO%	 (echo.&echo  ERROR: %PSLO% not found. & set /A f=1)
	if not exist %PSP%	 (echo.&echo  ERROR: %PSP% not found. & set /A f=1)
	if not exist %PSS%	 (echo.&echo  ERROR: %PSS% not found. & set /A f=1)
	if not exist %RB%	 (echo.&echo  ERROR: %RB% not found. & set /A f=1)
	if not exist %RCP%	 (echo.&echo  ERROR: %RCP% not found. & set /A f=1)
	if not exist %SDEL%	 (echo.&echo  ERROR: %SDEL% not found. & set /A f=1)
	if not exist %SIG%	 (echo.&echo  ERROR: %SIG% not found. & set /A f=1)
	if not exist %TCPV%	 (echo.&echo  ERROR: %TCPV% not found. & set /A f=1)
	if not exist %TR%	 (echo.&echo  ERROR: %TR% not found. & set /A f=1)
	if not exist %USB%	 (echo.&echo  ERROR: %USB% not found. & set /A f=1)
	if not exist %WPV%	 (echo.&echo  ERROR: %WPV% not found. & set /A f=1)
	if not exist %YAR%	 (echo.&echo  ERROR: %YAR% not found. & set /A f=1)
	if not exist %ZIP%	 (echo.&echo  ERROR: %ZIP% not found. & set /A f=1)

	if not exist %CFG%\nonrecursive.txt (
		echo.&echo  ERROR: %CFG%\nonrecursive.txt not found. & set /A f=1
	)
	if not exist %CFG%\recursive.txt (
		echo.&echo  ERROR: %CFG%\recursive.txt not found. & set /A f=1
	)
	if not exist %CFG%\nonrecursive-accesschk.txt (
		echo.&echo  ERROR: %CFG%\nonrecursive-accesschk.txt not found. & set /A f=1
	)
	if not exist %CFG%\recursive-accesschk.txt (
		echo.&echo  ERROR: %CFG%\recursive-accesschk.txt not found. & set /A f=1
	)
	if not exist %CFG%\nonrecursive-iconext.txt (
		echo.&echo  ERROR: %CFG%\nonrecursive-iconext.txt not found. & set /A f=1
	)
	if not exist %CFG%\recursive-iconext.txt (
		echo.&echo  ERROR: %CFG%\recursive-iconext.txt not found. & set /A f=1
	)
	if not exist %CFG%\nonrecursive-md5deep.txt (
		echo.&echo  ERROR: %CFG%\nonrecursive-md5deep.txt not found. & set /A f=1
	)
	if not exist %CFG%\recursive-md5deep.txt (
		echo.&echo  ERROR: %CFG%\recursive-md5deep.txt not found. & set /A f=1
	)

	if %f% equ 0 (
		for /F "tokens=4 delims= " %%i in ('chcp') do set CHCP=%%i

		icacls . /grant Everyone:"(OI)(CI)F" /T > NUL 2>&1

		call:rconf killself ckillself
		call:rconf sdelete csdel
		call:rconf outpath coutpath
		call:rconf rm-glog crm-glog
		call:rconf screenshot cscreenshot
		call:rconf ascii cascii

		call:rconf zip czip
		call:rconf zpassword czpassword
		call:rconf hash chash
		call:rconf vss cvss
		call:rconff vss-limit cvss-limit "" !cvss!
		call:rconf drives-limit cdrives-limit

		call:rconf activity cactiv
		call:rconf activity-all cactiv-all
		if !cactiv! equ false set cactiv-all=false
		call:rconff activity-vss cactiv-vss !cactiv-all! !cactiv! !cvss!
		call:rconff activity-mini-timeline cactiv-mtl !cactiv-all! !cactiv!
		call:rconff activity-usb cactiv-usb !cactiv-all! !cactiv!
		call:rconff activity-jump cactiv-jump !cactiv-all! !cactiv!
		call:rconff activity-lnk cactiv-lnk !cactiv-all! !cactiv!
		call:rconff activity-bin cactiv-bin !cactiv-all! !cactiv!

		call:rconf disk cdisk
		call:rconf disk-all cdisk-all
		if !cdisk! equ false set cdisk-all=false
		call:rconff disk-info cdisk-info !cdisk-all! !cdisk!
		call:rconff disk-encryption cdisk-encrypt !cdisk-all! !cdisk!
		call:rconff disk-boot cdisk-boot !cdisk-all! !cdisk!

		call:rconf events cevt
		call:rconf events-all cevt-all
		if !cevt! equ false set cevt-all=false
		call:rconff events-evtx cevt-evtx !cevt-all! !cevt!
		call:rconff events-txt cevt-txt !cevt-all! !cevt!

		call:rconf filesystem cfs
		call:rconf filesystem-all cfs-all
		if !cfs! equ false set cfs-all=false
		call:rconff filesystem-vss cfs-vss !cfs-all! !cfs! !cvss!
		call:rconff filesystem-ntfs cfs-ntfs !cfs-all! !cfs!
		call:rconff filesystem-vss-info cfs-vssi !cfs-all! !cfs!
		call:rconff filesystem-dir-full cfs-dfull !cfs-all! !cfs!
		call:rconff filesystem-dir-plain cfs-dplain !cfs-all! !cfs!
		call:rconff filesystem-fls cfs-fls !cfs-all! !cfs!
		call:rconff filesystem-md5 cfs-md5 !cfs-all! !cfs!
		call:rconff filesystem-ads cfs-ads !cfs-all! !cfs!
		call:rconff filesystem-mft cfs-mft !cfs-all! !cfs!
		call:rconff filesystem-log cfs-log !cfs-all! !cfs!
		call:rconff filesystem-usnjrnl cfs-jrnl !cfs-all! !cfs!

		call:rconf malware cmal
		call:rconf malware-all cmal-all
		if !cmal! equ false set cmal-all=false
		call:rconff malware-vss cmal-vss !cmal-all! !cmal! !cvss!
		call:rconff malware-prefetch cmal-pf !cmal-all! !cmal!
		call:rconff malware-services cmal-svcs !cmal-all! !cmal!
		call:rconff malware-tasks cmal-tasks !cmal-all! !cmal!
		call:rconff malware-processes cmal-proc !cmal-all! !cmal!
		call:rconff malware-drivers cmal-drvs !cmal-all! !cmal!
		call:rconff malware-dlls cmal-dlls !cmal-all! !cmal!
		call:rconff malware-autoruns cmal-ar !cmal-all! !cmal!
		call:rconff malware-addons cmal-addons !cmal-all! !cmal!
		call:rconff malware-office cmal-office !cmal-all! !cmal!
		call:rconff malware-hidden cmal-hid !cmal-all! !cmal!
		call:rconff malware-startup cmal-startup !cmal-all! !cmal!
		call:rconff malware-cache cmal-cache !cmal-all! !cmal!

		call:rconf memory cmem
		call:rconf memory-all cmem-all
		if !cmem! equ false set cmem-all=false
		call:rconff memory-vss cmem-vss !cmem-all! !cmem! !cvss!
		call:rconff memory-dump cmem-dump !cmem-all! !cmem!
		call:rconff memory-pagefile cmem-pf !cmem-all! !cmem!
		call:rconff memory-hiberfil cmem-hf !cmem-all! !cmem!
		call:rconff memory-minidump cmem-md !cmem-all! !cmem!
		call:rconff memory-appdumps cmem-ad !cmem-all! !cmem!

		call:rconf network cnet
		call:rconf network-all cnet-all
		if !cnet! equ false set cnet-all=false
		call:rconff network-target cnet-targ "" !cnet!

		call:rconf registry creg
		call:rconf registry-all creg-all
		if !creg! equ false set creg-all=false
		call:rconff registry-vss creg-vss !creg-all! !creg! !cvss!
		call:rconff registry-system creg-sys !creg-all! !creg!
		call:rconff registry-user creg-user !creg-all! !creg!
		call:rconff registry-text creg-text !creg-all! !creg!

		call:rconf system csys
		call:rconf system-all csys-all
		if !csys! equ false set csys-all=false
		call:rconff system-info csys-info !csys-all! !csys!
		call:rconff system-account csys-acc !csys-all! !csys!
		call:rconff system-security csys-sec !csys-all! !csys!
		call:rconff system-acl csys-acl !csys-all! !csys!

		call:rconf web cweb
		call:rconf web-all cweb-all
		if !cweb! equ false set cweb-all=false
		call:rconff web-history cweb-hist !cweb-all! !cweb!
		call:rconff web-chrome cweb-chrome !cweb-all! !cweb!
		call:rconff web-ie cweb-ie !cweb-all! !cweb!
		call:rconff web-mozilla cweb-moz !cweb-all! !cweb!

		call:rconf sigcheck csigcheck
		call:rconf density cdensity
		call:rconf iconsext ciconsext
		call:rconf yara cyara

		set /A in=0, inn=0, it=0, itt=0
		set /A iu=3, ip=0, idi=0, idii=-1, idr=0, iv=0
		set /A is=0, ia=0

		set "users[1]=Administrator"
		set "users[2]=Guest"
		set "users[3]=HomeGroupUser$"
		for /F "tokens=3,*" %%i in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" /S /V ProfileImagePath 2^>^&1 ^| findstr "ProfileImagePath" ^| findstr /V "ServiceProfiles" ^| findstr /V "system32"') do (
			set /A iu+=1, ip+=1
			set "uprofiles[!ip!]=%%i"
			set "ustartup[!ip!]=%%i\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
			for /F "tokens=3 delims=\" %%j in ("%%i") do (
				set "users[!iu!]=%%j"
				set "usersp[!ip!]=%%j"
			)
		)
		for /L %%i in (1,1,!iu!) do (
			for /F "skip=1" %%a in ('%PSG% -nobanner -accepteula !users[%%i]! 2^>^&1') do (
				set "usid[%%i]=%%a"
			)
			if "!usid[%%i]!" equ "Error" set "usid[%%i]=!users[%%i]!"
			if "!usid[%%i]!" equ "" set "usid[%%i]=!users[%%i]!"
		)

		:: translate %SystemRoot% to absolute path
		for /F "delims=" %%i in ('echo %SystemRoot%') do set tmp=%%i
		set SYSROOTD=!tmp:~0,1!
		set SYSROOTP=!tmp:~2!
		set SYSROOTT=!tmp!\Temp\%NAME%.log
		:: at least one profile exists
		set UPROFILED=!uprofiles[1]:~0,1!

		:: remove all previous VSS links (if any) from all user profiles
		for /L %%i in (1,1,!ip!) do (
			for /F "tokens=*" %%j in ('dir /A:D /B /S "!uprofiles[%%i]!\AppData\Local\Temp\%NAME%\vss-*" 2^>NUL') do (
				rmdir "%%j" > NUL 2>&1
			)
		)

		if not exist !coutpath! set coutpath=.
		set SYSDATE=%COMPUTERNAME%-%YYYYMMDD%
		set SYSTEM=!coutpath!\!SYSDATE!
		set DATA=!coutpath!\data
		set ROOT=!DATA!\!SYSDATE!
		set META=!ROOT!\%NAME%
		set ACTIV=!ROOT!\activ
		set DISK=!ROOT!\disk
		set EVT=!ROOT!\evt
		set FS=!ROOT!\fs
		set MAL=!ROOT!\mal
		set MEM=!ROOT!\mem
		set NET=!ROOT!\net
		set REG=!ROOT!\reg
		set SYS=!ROOT!\sys
		set WEB=!ROOT!\web
		set LOG=!META!\%NAME%.log

		call:cleandrn !DATA! %TEMPIR%
		call:cleanfn !SYSTEM!.7z
		mkdir !DATA! !ROOT! !META! %TEMPIR%

		if not !cascii! equ true (if exist %TOOLS%\ascii\cyb.txt set ASCII=%TOOLS%\ascii\cyb.txt)
		if !cnet-targ! equ false set cnet-targ=www.google.com
		if !cvss! equ true (
			if !cmem-vss! equ true set /A iv=1
			if !creg-vss! equ true set /A iv=1
			if !cevt-vss! equ true set /A iv=1
			if !csys-vss! equ true set /A iv=1
			if !cfs-vss! equ true set /A iv=1
			if !cmal-vss! equ true set /A iv=1
			if !cactiv-vss! equ true set /A iv=1
			if !iv! equ 1 (
				set /A ivt=0, iv=0
				for /F "tokens=3-4 delims= " %%i in ('vssadmin list shadows 2^>^&1 ^| findstr /C:"Original Volume" /C:"Shadow Copy Volume"') do (
					set /A ivt+=1
					set /A tmpn=(!ivt!%%2^)
					if !tmpn! equ 0 (
						set /A iv+=1
						set tmp=%%j
						set "tvsscl[!iv!]=%%j\"
						set "tvsscd[!iv!]=!tmpv:~1,1!"
						set "tvsscf[!iv!]=vss-!tmp:~46!-!tmpv:~1,1!"
						set "tvssc[!iv!]=%TEMPIR%\vss-!tmp:~46!-!tmpv:~1,1!"
					) else (
						set tmpv=%%i
					)
				)
				set ltmp=
				for /F "delims=0123456789" %%i in ("!cvss-limit!") do set "ltmp=%%i"
				if defined ltmp set cvss-limit=3
				if !cvss-limit! lss 0 set cvss-limit=0
				if !cvss-limit! gtr !iv! set cvss-limit=!iv!
				set /A tmpn=!iv!-!cvss-limit!+1, ivt=0
				for /L %%i in (!iv!,-1,!tmpn!) do (
					set /A ivt+=1
					set "vsscl[!ivt!]=!tvsscl[%%i]!"
					set "vsscd[!ivt!]=!tvsscd[%%i]!"
					set "vsscf[!ivt!]=!tvsscf[%%i]!"
					set "vssc[!ivt!]=!tvssc[%%i]!"
					mklink /D !tvssc[%%i]! !tvsscl[%%i]! > NUL 2>&1
				)
				set /A iv=!ivt!
			)
		)

		for /F "skip=7 tokens=2" %%i in ('diskpart /S %TOOLS%\disk\diskpart-list.txt 2^>NUL') do (
			set "disk[!idi!]=\\.\PhysicalDrive%%i"
			set /A idi+=1, idii+=1
		)

		set dtmp=
		if !cdrives-limit! equ all set dtmp=true
		if !cdrives-limit! equ false set dtmp=true
		if dtmp equ true (
			for %%i in (C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
				if exist %%i: (
					set /A idr+=1
					set "drivesuc[!idr!]=%%i"
					set "driveslc[!idr!]=%%i"
					call:lower driveslc[!idr!]
				)
			)
		) else (
			for %%i in ("!cdrives-limit:,=" "!") do (
				if exist %%~i: (
					set /A idr+=1
					set "drivesuc[!idr!]=%%~i"
					set "driveslc[!idr!]=%%~i"
					call:lower driveslc[!idr!]
				)
			)
			if !idr! equ 0 (
				for %%i in (C D) do (
					if exist %%~i: (
						set /A idr+=1
						set "drivesuc[!idr!]=%%~i"
						set "driveslc[!idr!]=%%~i"
						call:lower driveslc[!idr!]
					)
				)
			)
		)

		set RUN=false
		call:activity
		call:activity-contd
		call:disk
		call:events
		call:filesystem
		call:filesystem-contd
		call:malware
		call:memory
		call:memory-contd
		call:malware-contd
		call:network
		call:network-contd
		call:registry
		call:system
		call:web

		call:sigcheck
		call:density
		call:iconsext
		call:yara
		set RUN=true
		echo. >> !SYSROOTT!
	)
	exit /B %f%

:end
	call:timestamp
	call:msg " compressing data and cleaning up..."
	call:msg " output: %coutpath%"
	call:screenshot

	:: delete Sysinternals registry keys?
	:: delete prefetch files?
	:: what other evidence pollutes the system?

	:: Microsoft SubInACL.exe
	:: icacls . /C /L /T /grant Everyone:"(OI)(CI)F" /inheritance:e > NUL 2>&1
	icacls . /grant Everyone:"(OI)(CI)F" /T > NUL 2>&1
	call:cmdl "%LOG%" "attrib -H .\set.txt.tmp"
	:: delete empty folders before compressing
	if %cweb% equ true (
		call:cleand %WEB%\cache-chrome %WEB%\cache-ie %WEB%\cache-mozilla
	)
	:: delete icon folders in bins to reduce processing?
	if %ciconsext% equ true (
		for /F %%i in ('dir /A:D /B /S %MAL%\icons 2^>^&1 ^| sort /R') do (
			set tmp=%%i
			set tmp=!tmp:%~dp0=!
			call:cleand !tmp!
		)
	)
	:: copy %SystemRoot%\Temp\ir-rescue-win.log
	call:cpfl "%LOG%" %SYSROOTT% %META%\%NAME%-global.log

	call:packf "zip" %MEM%\raw.mem
	call:packff %MEM%\pagefile*.sys %MEM%\pagefile.sys
	call:packff %MEM%\hiberfil*.sys %MEM%\hiberfil.sys
	call:packd "zip" %MEM%\Minidump-* %MEM%\Minidump
	call:packd "zip" %MEM%\CrashDumps-* %MEM%\CrashDumps
	call:packd "zip" %REG%\sys
	call:packd "zip" %REG%\user
	call:packd "zip" %REG%\txt
	call:packd "zip" %EVT%\evtx
	call:packd "zip" %EVT%\txt
	call:packff %FS%\boot-*.bin %FS%\boot
	call:packff %FS%\$MFT-*.bin %FS%\$MFT
	call:packff %FS%\$LogFile-*.bin %FS%\$LogFile
	call:packff %FS%\$UsnJrnl_$J-*.bin %FS%\$UsnJrnl_$J
	call:packd "zip" %MAL%\Prefetch-* %MAL%\Prefetch
	call:packd "zip" %MAL%\Tasks* %MAL%\Tasks
	call:packd "7z" %MAL%\Startup-* %MAL%\Startup
	call:packd "zip" %MAL%\icons
	call:packd "7z" %WEB%\cache-chrome
	call:packd "7z" %WEB%\cache-ie
	call:packd "7z" %WEB%\cache-mozilla

	if %crm-glog% equ true call:cleanf %SYSROOTT%
	call:cleanf .\set.txt.tmp
	call:cleandr %TEMPIR%
	call:cleanf %MEM%\raw.mem %MEM%\pagefile*.sys %MEM%\hiberfil*.sys
	call:cleandrr %MEM%\Minidump-*
	call:cleandrr %MEM%\CrashDumps-*
	call:cleandr %REG%\sys %REG%\user %REG%\txt
	call:cleandr %EVT%\evtx %EVT%\txt
	call:cleanf %FS%\boot-*.bin %FS%\$MFT-*.bin %FS%\$LogFile-*.bin %FS%\$UsnJrnl_$J-*.bin
	call:cleandrr %MAL%\Prefetch-*
	call:cleandrr %MAL%\Tasks*
	call:cleandrr %MAL%\Startup-*
	call:cleandr %WEB%\cache-chrome %WEB%\cache-ie %WEB%\cache-mozilla
	call:cleandr %MAL%\icons

	icacls . /grant Everyone:"(OI)(CI)F" /T > NUL 2>&1

	call:timestamp
	call:ascii
	call:msg "  finishing..."
	call:screenshot

	if %chash% equ true (
		call:cmdl "%META%\%SYSDATE%.md5" "%MD5% -l -r -s -z %DATA% | sort /+47"
	)

	if %czip% equ true (
		if not "%czpassword%" equ "" (
			%ZIP% a -t7z -xr"^!.*" -p"%czpassword%" -mhe -mmt=on %SYSTEM%.7z %ROOT% > NUL 2>&1
		) else (
			%ZIP% a -t7z -xr"^!.*" -mmt=on %SYSTEM%.7z %ROOT% > NUL 2>&1
		)
		if exist %SYSTEM%.7z call:cleandrn %DATA%
	)
	if %ckillself% equ true (
		call:cleandrn .\%TOOLS%
		if %csdel% equ true rmdir /Q /S .\%TOOLS% > NUL 2>&1
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
		call:cmdl "%LOG%" "%NIRC% savescreenshotfull %META%\screenshot-%is%.jpg"
	)
	goto:eof

:rconf <opt> <var> [all]
	if "%~3" equ "true" (
		set "%~2=true"
	) else (
		for /F "eol=# tokens=1,2* delims==" %%i in ('findstr /B /I /L "%~1=" %CONF%') DO (
			set "%~2=%%~j"
			if "%%~j" equ "" set "%~2=false"
		)
	)
	goto:eof

:rconff <opt> <var> [all] [mod] [vss]
	if "%~4" equ "false" (
		set "%~2=false"
	) else (
		if "%~5" equ "false" (
			set "%~2=false"
		) else call:rconf %*
	)
	goto:eof

:packf <alg> <srcf ...>
	for /F "tokens=1,* delims= " %%i in ("%*") do set ptmp=%%j
	for %%i in (!ptmp!) do (
		if exist %%i (
			if "%~1" equ "zip" (
				call:cmdl "%LOG%" "%ZIP% a -tzip -ssc %%i.zip %%i"
			) else (
				call:cmdl "%LOG%" "%ZIP% a -t7z -ssc -pinfected %%i.7z %%i"
			)
		)
	)
	goto:eof

:packff <srcf> <dstf>
	if exist "%~1" (
		call:cmdl "%LOG%" "%ZIP% a -tzip -ssc %~2.zip %~1"
	)
	goto:eof

:packd <alg> <srcd> [dstd]
	:: %ZIP% a -tzip -xr!.* ...
	if exist "%~2" (
		if "%~3" equ "" (set ptmp=%2) else (set ptmp=%3)
		if "%~1" equ "zip" (
			call:cmdl "%LOG%" "%ZIP% a -tzip -ssc -r !ptmp!.zip %~2"
		) else (
			call:cmdl "%LOG%" "%ZIP% a -t7z -ssc -r -pinfected !ptmp!.7z %~2"
		)
	)
	goto:eof

:unpackf <srcf> <dstd>
	if exist %%i (
		call:cmdl "%LOG%" "%ZIP% x %~1 -o%~2 -y"
	)
	goto:eof

:cleand <srcd ...>
	call:clean "%LOG%" "rmdir" "nonrecursive" %*
	goto:eof

:cleandrr <srcd ...>
	for /F %%i in ('dir /A /B /S %~1 2^>NUL') do (
		call:clean "%LOG%" "rmdir" "recursive" %%i
	)
	goto:eof

:cleandr <srcd ...>
	call:clean "%LOG%" "rmdir" "recursive" %*
	goto:eof

:cleandrn <srcd ...>
	call:clean "NUL" "rmdir" "recursive" %*
	goto:eof

:cleanf <srcf ...>
	call:clean "%LOG%" "del" "nonrecursive" %*
	goto:eof

:cleanfn <srcf ...>
	call:clean "NUL" "del" "nonrecursive" %*
	goto:eof

:clean <logf> <cmd> <recurse> <srcfd ...>
	for /F "tokens=3,* delims= " %%i in ("%*") do (
		for %%a in (%%j) do (
			if exist %%a call:rm %1 %2 %3 %%a
		)
	)
	goto:eof

:rm <logf> <cmd> <recurse> <srcfd>
	for /F "tokens=3,* delims= " %%i in ("%*") do set rtmp=%%j
	if %csdel% equ true (
		if "%~3" equ "recursive" (
			call:cmdl %1 "%SDEL% -accepteula -s !rtmp!"
		) else (
			call:cmdl %1 "%SDEL% -accepteula !rtmp!"
		)
	) else (
		if "%~3" equ "recursive" (
			call:cmdl %1 "%~2 /Q /S !rtmp!"
		) else (
			call:cmdl %1 "%~2 /Q !rtmp!"
		)
	)
	goto:eof

:len <var> <olen>
	set "str=!%~1!#"
	set /A len=0
	for %%i in (4096 2048 1024 512 256 128 64 32 16 8 4 2 1) do (
		if "!str:~%%i,1!" neq "" (
			set /A len+=%%i
			set "str=!str:~%%i!"
		)
	)
	set "%~2=%len%"
	goto:eof

:upper <var>
	for %%i in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do set %1=!%1:%%i=%%i!
	goto:eof

:lower <var>
	for %%i in (a b c d e f g h i j k l m n o p q r s t u v w x y z) do set %1=!%1:%%i=%%i!
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
	echo 'tools-win' under 'ir-rescue\tools-win\'.
	echo.
	echo Needs administrator rights to run.
	call:pause
	goto:eof

:notes
	:: del /A /S /Q *.DS_Store & ir-rescue\win\tools-win\fs\md5deep64.exe -l -r -s -z ir-rescue\ | sort /+47 > ir-rescue\ir-rescue.md5

	:: https://github.com/diogo-fernan/ir-rescue/issues/1
	:: use a GPG key to encrypt the resulting compressed archive
	:: ".\tools-win\cfg\..."
	:: 'gpg=true'
	:: http://security.stackexchange.com/questions/56167/why-is-gpg-file-encryption-so-much-slower-than-other-aes-implementations/56209#56209
	:: https://security.stackexchange.com/questions/86721/can-i-specific-a-public-key-name-instead-of-recipient-when-encrypt-with-gpg
	:: http://serverfault.com/questions/246593/encrypting-files-with-different-public-keys
	:: http://superuser.com/questions/576506/how-to-use-ssh-rsa-public-key-to-encrypt-a-text

	:: cat fls-* | cut -d $'\t' -f 2 | egrep ".+:.+" | grep -v Zone.Identifier > ads.txt

	:: Unicode RLO: rlo.exe
	:: skip known-good hash values from 'recursive.txt' and 'nonrecursive.txt'
	:: 'stream=true'
		:: 'netcat' data stream
		:: write to disk
		:: run from mapped drive, automatically data is streamed
		:: or outpath=\\hostname\data, needs read, write and delete permissions
	:: 'admin=true'
	:: 'prefix=ir_'
		:: prefix file names of tools to avoid overwriting prefetch files
	:: 'unc-dir=true'
		:: UNC browsing
		:: pushd \\unc\dir; dir; popd
	:: 'cookies=true'
		:: collect cookies --> NirSoft utilities
		:: or dump SQLite3 databases --> encryption? Think not, just the passwords database
		:: in that case, dump all databases instead of using NirSoft utilities for web collection

	:: timestomping
	:: Windows Error Reporting (WER)
		:: %ProgramData%\Microsoft\Windows\WER\
		:: %SystemDrive%\Users\%UserName%\AppData\Local\Microsoft\Windows\WER\

	:: Windows 10 supports ANSI escape sequences for coloring
	:: there are some workarounds for Windows 7, but they are not that great

	:: "grep" for "Image File Execution Options" and "Classes" in HKLM
	:: loadpoints
	:: and much more

	:: hidden partitions --> Windows recovery partition
	:: \\?\GLOBALROOT\Device\Harddisk0\Partition4\Recovery\WindowsRE --> NTFS (MFT)? FAT32?
	:: bcdboot

	:: load "winpmem" driver and run "strings" against "\\.\pmem"
	:: tools are unable to open the device

	:: xcopy, robocopy

	:: TZWorks pescan
	:: TZWorks LNK Parsing; *.lnk
	:: TZWorks ntfswalk, ntfscopy
	:: Redline Comprehensive Collector; WinAudit


	:: removed RegRipper
	:: # parse user registry hives ("%USERPROFILE%\NTUSER.dat") from all users
	:: # requires 'registry-user=true'
	:: # "rip.exe"
	:: registry-parse=true
	:: set RR=%TOOLS%\reg\RegRipper2.8\rip.exe
	:: if not exist %RR%	 (echo.&echo  ERROR: %RR% not found. & set /A f=1)
	:: call:rconff registry-parse creg-parse !creg-all! !creg!
	:: if %creg-parse% equ true (
	::	if %RUN% equ true (
	::		call:header "user registry hives" "parsing"
	::		call:unpackf "%TOOLS%\reg\RegRipper2.8\plugins.zip" ".\"
	::		:: call:cmdl %REG%\log.txt "xcopy %TOOLS%\reg\RegRipper2.8\plugins .\plugins /C /E /F /I /Y"
	::		for %%i in (%REG%\user\NTUSER*) do (
	::			call:cmd %REG%\user-rip "%RR% -r %%i -f ntuser"
	::		)
	::		call:cmdl %REG%\log.txt "rmdir /Q /S .\plugins"
	::	) else (set /A it+=1, itt+=!tmp!)
	:: )

	:: removed "LECmd.exe"
	:: set LEC=%TOOLS%\activ\LECmd.exe
	:: if not exist %LEC%	 (echo.&echo  ERROR: %LEC% not found. & set /A f=1)
	:: if %cactiv-lnk% equ true (
	::	if %RUN% equ true (
	::		call:header "LNK files" "parsing"
	::		for /L %%i in (1,1,%ip%) do (
	::			call:cmdn %ACTIV%\lnk\log "%LEC% --csv %ACTIV%\lnk\!usersp[%%i]! -d !uprofiles[%%i]!\AppData\Roaming\Microsoft\Windows\Recent -q"
	::			%LEC% --csv "%ACTIV%\lnk\!usersp[%%i]!" -d "!uprofiles[%%i]!\AppData\Roaming\Microsoft\Windows\Recent" -q >> %ACTIV%\lnk\log.txt 2>&1
	::			call:cmdn %ACTIV%\lnk\log "%LEC% --csv %ACTIV%\lnk\!usersp[%%i]! -d !ustartup[%%i]! -q"
	::			%LEC% --csv "%ACTIV%\lnk\!usersp[%%i]!" -d "!ustartup[%%i]!" -q >> %ACTIV%\lnk\log.txt 2>&1
	::		)
	::	) else (mkdir %ACTIV%\lnk & set /A it+=1, itt+=2*%ip%)
	::	if %cactiv-vss% equ true (
	::		for /L %%i in (1,1,%ip%) do (
	::			if %RUN% equ true (
	::				call:cmdn %ACTIV%\lnk\log "%LEC% --csv %ACTIV%\lnk\!usersp[%%i]!-vss* -d vss*!uprofiles[%%i]:~2!\AppData\Roaming\Microsoft\Windows\Recent -q"
	::				call:cmdn %ACTIV%\lnk\log "%LEC% --csv %ACTIV%\lnk\!usersp[%%i]!-vss* -d vss*!ustartup[%%i]:~2! -q"
	::			) else set /A itt+=2
	::			for /L %%a in (1,1,%iv%) do (
	::				if /I %UPROFILED% equ !vsscd[%%a]! (
	::					if %RUN% equ true (
	::						%LEC% --csv "%ACTIV%\lnk\!usersp[%%i]!-!vsscf[%%a]!" -d "!vssc[%%a]!!uprofiles[%%i]:~2!\AppData\Roaming\Microsoft\Windows\Recent" -q >> %ACTIV%\lnk\log.txt 2>&1
	::						%LEC% --csv "%ACTIV%\lnk\!usersp[%%i]!-!vsscf[%%a]!" -d "!vssc[%%a]!!uprofiles[%%i]:~2!" -q >> %ACTIV%\lnk\log.txt 2>&1
	::					)
	::				)
	::			)
	::		)
	::	)
	:: )
