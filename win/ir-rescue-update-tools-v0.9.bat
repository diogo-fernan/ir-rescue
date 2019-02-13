@echo off

set BASEDIR=%~dp0

:: DEFINE DESTINATION PATHS
set TOOLS=tools-win

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
set SHL=%TOOLS%\activ\SBECmd.exe  
set TCPV=%TOOLS%\net\tcpvcon.exe
set USB=%TOOLS%\activ\USBDeview.exe
set WPV=%TOOLS%\mal\WinPrefetchView.exe
set YAR=%TOOLS%\yara\yara32.exe

set AC64=%TOOLS%\sys\accesschk64.exe
set ADS64=%TOOLS%\fs\AlternateStreamView64.exe
set AR64=%TOOLS%\mal\Autoruns64.exe
set ARC64=%TOOLS%\mal\autorunsc64.exe
set BAV64=%TOOLS%\mal\BrowserAddonsView64.exe
set BHV64=%TOOLS%\web\BrowsingHistoryView64.exe
set DS64=%TOOLS%\mal\densityscout64.exe
set DV64=%TOOLS%\mal\DriverView64.exe
set EUJ64=%TOOLS%\fs\ExtractUsnJrnl64.exe
set MD564=%TOOLS%\fs\md5deep64.exe
set NIRC64=%TOOLS%\nircmdc64.exe
set NTFS64=%TOOLS%\fs\ntfsinfo64.exe
set OI64=%TOOLS%\mal\OfficeIns64.exe
set PSD64=%TOOLS%\mal\Listdlls64.exe
set PSF64=%TOOLS%\net\psfile64.exe
set PSG64=%TOOLS%\sys\PsGetsid64.exe
set PSH64=%TOOLS%\mal\handle64.exe
set PSI64=%TOOLS%\sys\PsInfo64.exe
set PSL64=%TOOLS%\sys\logonsessions64.exe
set PSLO64=%TOOLS%\sys\PsLoggedon64.exe
set PSP64=%TOOLS%\mal\pslist64.exe
set PSS64=%TOOLS%\mal\PsService64.exe
set RB64=%TOOLS%\activ\rifiuti-vista64.exe
set RCP64=%TOOLS%\fs\RawCopy64.exe
set SDEL64=%TOOLS%\sdelete64.exe
set SIG64=%TOOLS%\mal\sigcheck64.exe
set USB64=%TOOLS%\activ\USBDeview64.exe
set WPV64=%TOOLS%\mal\WinPrefetchView64.exe
set YAR64=%TOOLS%\yara\yara64.exe


:: SYSINTERNAL TOOLS
call:DOWNLOAD_FILE https://live.sysinternals.com/accesschk.exe %BASEDIR%\%AC%
call:DOWNLOAD_FILE https://live.sysinternals.com/accesschk64.exe %BASEDIR%\%AC64%
call:DOWNLOAD_FILE https://live.sysinternals.com/autoruns.exe %BASEDIR%\%AR%
call:DOWNLOAD_FILE https://live.sysinternals.com/autorunsc.exe %BASEDIR%\%ARC%
call:DOWNLOAD_FILE https://live.sysinternals.com/autoruns64.exe %BASEDIR%\%AR64%
call:DOWNLOAD_FILE https://live.sysinternals.com/autorunsc64.exe %BASEDIR%\%ARC64%
call:DOWNLOAD_FILE https://live.sysinternals.com/sdelete.exe %BASEDIR%\%SDEL%
call:DOWNLOAD_FILE https://live.sysinternals.com/sdelete64.exe %BASEDIR%\%SDEL64%
call:DOWNLOAD_FILE https://live.sysinternals.com/ntfsinfo.exe %BASEDIR%\%NTFS%
call:DOWNLOAD_FILE https://live.sysinternals.com/ntfsinfo64.exe %BASEDIR%\%NTFS64%
call:DOWNLOAD_FILE https://live.sysinternals.com/Listdlls.exe %BASEDIR%\%PSD%
call:DOWNLOAD_FILE https://live.sysinternals.com/Listdlls64.exe %BASEDIR%\%PSD64%
call:DOWNLOAD_FILE https://live.sysinternals.com/psfile.exe %BASEDIR%\%PSF%
call:DOWNLOAD_FILE https://live.sysinternals.com/psfile64.exe %BASEDIR%\%PSF64%
call:DOWNLOAD_FILE https://live.sysinternals.com/psgetsid.exe %BASEDIR%\%PSG%
call:DOWNLOAD_FILE https://live.sysinternals.com/psgetsid64.exe %BASEDIR%\%PSG64%
call:DOWNLOAD_FILE https://live.sysinternals.com/handle.exe %BASEDIR%\%PSH%
call:DOWNLOAD_FILE https://live.sysinternals.com/handle64.exe %BASEDIR%\%PSH64%
call:DOWNLOAD_FILE https://live.sysinternals.com/psinfo.exe %BASEDIR%\%PSI%
call:DOWNLOAD_FILE https://live.sysinternals.com/psinfo64.exe %BASEDIR%\%PSI64%
call:DOWNLOAD_FILE https://live.sysinternals.com/logonsessions.exe %BASEDIR%\%PSL%
call:DOWNLOAD_FILE https://live.sysinternals.com/logonsessions64.exe %BASEDIR%\%PSL64%
call:DOWNLOAD_FILE https://live.sysinternals.com/psloggedon.exe %BASEDIR%\%PSLO%
call:DOWNLOAD_FILE https://live.sysinternals.com/psloggedon64.exe %BASEDIR%\%PSLO64%
call:DOWNLOAD_FILE https://live.sysinternals.com/pslist.exe %BASEDIR%\%PSP%
call:DOWNLOAD_FILE https://live.sysinternals.com/pslist64.exe %BASEDIR%\%PSP64%
call:DOWNLOAD_FILE https://live.sysinternals.com/psservice.exe %BASEDIR%\%PSS%
call:DOWNLOAD_FILE https://live.sysinternals.com/psservice64.exe %BASEDIR%\%PSS64%
call:DOWNLOAD_FILE https://live.sysinternals.com/sigcheck.exe %BASEDIR%\%SIG%
call:DOWNLOAD_FILE https://live.sysinternals.com/sigcheck64.exe %BASEDIR%\%SIG64%
call:DOWNLOAD_FILE https://live.sysinternals.com/tcpvcon.exe %BASEDIR%\%TCPV%
call:DOWNLOAD_FILE https://live.sysinternals.com/psloglist.exe %BASEDIR%\%PLL%

:: NIRSOFT TOOLS
set TEMP=%BASEDIR%\%TOOLS%\temp
mkdir %TEMP%
call:DOWNLOAD_NIRSOFT http://www.nirsoft.net/utils/alternatestreamview.zip alternatestreamview %ADS%
call:DOWNLOAD_NIRSOFT http://www.nirsoft.net/utils/alternatestreamview-x64.zip alternatestreamview %ADS64%
call:DOWNLOAD_NIRSOFT http://www.nirsoft.net/utils/browseraddonsview.zip browseraddonsview %BAV%
call:DOWNLOAD_NIRSOFT http://www.nirsoft.net/utils/browseraddonsview-x64.zip browseraddonsview %BAV64%
call:DOWNLOAD_NIRSOFT http://www.nirsoft.net/utils/browsinghistoryview.zip browsinghistoryview %BHV%
call:DOWNLOAD_NIRSOFT http://www.nirsoft.net/utils/browsinghistoryview-x64.zip browsinghistoryview %BHV64%
call:DOWNLOAD_NIRSOFT http://www.nirsoft.net/utils/chromecacheview.zip chromecacheview %CCV%
call:DOWNLOAD_NIRSOFT http://www.nirsoft.net/utils/driverview.zip driverview %DV%
call:DOWNLOAD_NIRSOFT http://www.nirsoft.net/utils/driverview-x64.zip driverview %DV64%
call:DOWNLOAD_NIRSOFT http://www.nirsoft.net/utils/iconsext.zip iconsext %IE%
call:DOWNLOAD_NIRSOFT http://www.nirsoft.net/utils/iecacheview.zip iecacheview %IECV%
call:DOWNLOAD_NIRSOFT http://www.nirsoft.net/utils/lastactivityview.zip lastactivityview %LAV%
call:DOWNLOAD_NIRSOFT http://www.nirsoft.net/utils/mozillacacheview.zip mozillacacheview %MCV%
call:DOWNLOAD_NIRSOFT http://www.nirsoft.net/utils/nircmd.zip nircmd %NIRC%
call:DOWNLOAD_NIRSOFT http://www.nirsoft.net/utils/nircmd-x64.zip nircmd %NIRC64%
call:DOWNLOAD_NIRSOFT http://www.nirsoft.net/utils/officeins.zip officeins %OI%
call:DOWNLOAD_NIRSOFT http://www.nirsoft.net/utils/officeins-x64.zip officeins %OI64%
call:DOWNLOAD_NIRSOFT http://www.nirsoft.net/utils/usbdeview.zip usbdeview %USB%
call:DOWNLOAD_NIRSOFT http://www.nirsoft.net/utils/usbdeview-x64.zip usbdeview %USB64%
call:DOWNLOAD_NIRSOFT http://www.nirsoft.net/utils/winprefetchview.zip winprefetchview %WPV%
call:DOWNLOAD_NIRSOFT http://www.nirsoft.net/utils/winprefetchview-x64.zip winprefetchview %WPV64%

:: SLEUTH KIT
call:DOWNLOAD_SLEUTHKIT https://github.com/sleuthkit/sleuthkit/releases/download/sleuthkit-4.6.5/sleuthkit-4.6.5-win32.zip sleuthkit

:: DOWNLOAD md5deep
call:DOWNLOAD_MD5DEEP https://github.com/jessek/hashdeep/releases/download/v4.4/md5deep-4.4.zip md5deep-4.4

:: DOWNLOAD EXIFTOOL
call:DOWNLOAD_EXIF http://owl.phy.queensu.ca/~phil/exiftool/exiftool-11.26.zip exiftool-11.26

:: DOWNLOAD ERIC TOOLS
call:DOWNLOAD_ERIC https://f001.backblazeb2.com/file/EricZimmermanTools/JLECmd.zip JLECmd %BASEDIR%\%JLEC%
call:DOWNLOAD_ERIC https://f001.backblazeb2.com/file/EricZimmermanTools/ShellBagsExplorer.zip SBECmd %BASEDIR%\%SHL%

:: DOWNLOAD RawCopy
call:DOWNLOAD_FILE https://github.com/jschicht/RawCopy/raw/master/RawCopy64.exe %BASEDIR%\%RCP64%
call:DOWNLOAD_FILE https://github.com/jschicht/RawCopy/raw/master/RawCopy.exe %BASEDIR%\%RCP%

:: DOWNLOAD ExtractUsnJrnl
call:DOWNLOAD_FILE https://github.com/jschicht/ExtractUsnJrnl/raw/master/ExtractUsnJrnl64.exe %BASEDIR%\%EUJ64%
call:DOWNLOAD_FILE https://github.com/jschicht/ExtractUsnJrnl/raw/master/ExtractUsnJrnl.exe %BASEDIR%\%EUJ%

:: DOWNLOAD rifiuti-vista
call:DOWNLOAD_RIFI https://github.com/abelcheung/rifiuti2/releases/download/0.6.1/rifiuti2-0.6.1-win.zip

:: DOWNLOAD DENSITY
call:DOWNLOAD_DENSITY https://www.cert.at/static/downloads/software/densityscout/densityscout_build_45_windows.zip densityscout


rmdir /S /Q %TEMP%

echo ----------------------------------------------------------------------------------------------------------------------
echo THE FOLLOWING TOOLS NEED TO BE DOWNLOADED AND INSTALLED MANUALLY
echo 7zip: https://www.7-zip.org/
echo winpmem: https://github.com/google/rekall
echo EDD: https://www.magnetforensics.com/free-tool-encrypted-disk-detector
echo YARA: http://virustotal.github.io/yara/
echo CYGWIN: http://www.cygwin.com/
echo ----------------------------------------------------------------------------------------------------------------------
echo FOR THE FOLLOWING TOOLS MIGHT BE NEWER VERSIONS AVAILABLE THAN JUST DOWNLOADED. PLEASE CHECK!
echo sleuthkit-4.6.5
echo md5deep-4.4
echo exiftool-11.26
echo rifiuti2-0.6.1
echo densityscout_build_45
echo ----------------------------------------------------------------------------------------------------------------------

pause
	
:unzip <file> <output>
	(%ZIP% x -aoa -o"%2" %1 > NUL 2>&1)
	EXIT /B 0
	
:DOWNLOAD_FILE
    curl -L %1 --output %2 > NUL 2>&1
	echo %time% DOWNLOADED TO: %2
	EXIT /B 0

:DOWNLOAD_NIRSOFT
	call:DOWNLOAD_FILE %1 %TEMP%\%2.zip
	call:unzip %TEMP%\%2.zip %TEMP%\%2
	call:MOVE %TEMP%\%2\%2.exe %BASEDIR%\%3
	EXIT /B 0
	
:DOWNLOAD_SLEUTHKIT
	call:DOWNLOAD_FILE %1 %TEMP%\%2.zip
	call:unzip %TEMP%\%2.zip %TEMP%\%2
	call:MOVE %TEMP%\%2\sleuthkit-4.6.5-win32\bin\fls.exe %BASEDIR%\%FLS%
	call:MOVE %TEMP%\%2\sleuthkit-4.6.5-win32\bin\mmcat.exe %BASEDIR%\%MMCAT%
	call:MOVE %TEMP%\%2\sleuthkit-4.6.5-win32\bin\mmls.exe %BASEDIR%\%MMLS%
	EXIT /B 0
	
:DOWNLOAD_MD5DEEP
	call:DOWNLOAD_FILE %1 %TEMP%\%2.zip
	call:unzip %TEMP%\%2.zip %TEMP%\%2
	call:MOVE %TEMP%\%2\%2\md5deep.exe %BASEDIR%\%MD5%
	call:MOVE %TEMP%\%2\%2\md5deep64.exe %BASEDIR%\%MD564%
	EXIT /B 0
	
:DOWNLOAD_EXIF
	call:DOWNLOAD_FILE %1 %TEMP%\%2.zip
	call:unzip %TEMP%\%2.zip %TEMP%\%2
	call:MOVE %TEMP%\%2\exiftool(-k).exe %BASEDIR%\%EXIF%
	EXIT /B 0
	
:DOWNLOAD_ERIC
	call:DOWNLOAD_FILE %1 %TEMP%\%2.zip
	call:unzip %TEMP%\%2.zip %TEMP%\%2
	if "%~2"=="SBECmd" (
		call:MOVE %TEMP%\%2\ShellBagsExplorer\%2.exe %3
	) else (
		call:MOVE %TEMP%\%2\%2.exe %3
	)
	EXIT /B 0
	
:DOWNLOAD_RIFI
	call:DOWNLOAD_FILE %1 %TEMP%\%2.zip
	call:unzip %TEMP%\%2.zip %TEMP%\%2
	call:MOVE %TEMP%\x64\rifiuti-vista.exe %BASEDIR%\%RB64%
	call:MOVE %TEMP%\x86\rifiuti-vista.exe %BASEDIR%\%RB%
	EXIT /B 0
	
:DOWNLOAD_DENSITY
	call:DOWNLOAD_FILE %1 %TEMP%\%2.zip
	call:unzip %TEMP%\%2.zip %TEMP%\%2
	call:MOVE %TEMP%\%2\win32\%2.exe %BASEDIR%\%DS%
	call:MOVE %TEMP%\%2\win64\%2.exe %BASEDIR%\%DS64%
	EXIT /B 0
	
:MOVE
	move %1 %2 > NUL 2>&1
	echo %time% MOVED TO: %2
	EXIT /B 0
