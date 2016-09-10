# ir-rescue

*ir-rescue* is a Windows Batch script that collects a myriad of **forensic data** from 32-bit and 64-bit Windows systems while respecting the order of volatility. It is intended for **incident response** use at different stages in the analysis and investigation process. It can be set to perform comprehensive collections of data for triage purposes, as well as customized acquisitions of specific types of data. The tool represents an effort to streamline host data collection, regardless of investigation needs, and to rely less on on-site support when remote access or live analysis is unavailable.

*ir-rescue* makes use of built-in Windows commands and well-known third party utilities from Sysinternals and NirSoft, for instance, some being open-source. It is designed to group data collections according to data type. For example, all data that relates to networking, such as open file shares and TCP connections, is grouped together, while running processes, services and tasks are gathered under malware. The tool is also purposefully designed not to make use of PowerShell and WMI in order to make it transversally compatible. The acquisition of data types and other general options are specified in a simple **configuration file**. It should be noted that the tool launches a great number of commands and tools, thereby leaving a considerable **footprint** on the system. The runtime varies depending on the computation power and configurations set, though it usually finishes within a maximum of one hour if configured to run fully.

*ir-rescue* has been written for incident response and forensic analysts, as well as for security practitioners alike. It can thus be used for leveraging the already bundled tools and commands during forensic activities.

# Dependencies and Usage

*ir-rescue* relies on a number of third-party utilities for gathering specific data from hosts. The latest versions of the tools, as of this writing, are provided with the package as is. Their descriptions and organization in the **folder tree** structure are given below, with both 32-bit and 64-bit versions of the tools included adjacently, if applicable:

* `tools\`: third-party tools folder:
	* `ascii\`: text ASCII art files in `*.txt` format;
	* `cfg\`: configuration files:
		* `ir-rescue.conf`: main configuration file;
		* `c.txt`: `md5deep` interesting hashing locations of the `C:\` drive;
		* `sys.txt`: `md5deep` hashing locations of the `C:\Windows\system(32|64)` folders;
	* `cygwin\`: Cygwin tools and Dynamic Linked Libraries (DLLs):
		* `tr.exe`: used to cut out non-printable characters;
	* `evt\`: Windows events tools:
		* `psloglist.exe`;
	* `fs\`: filesystem tools:
		* `tsk\`: The Sleuth Kit (TSK) tools and DLLs:
			* `fls.exe`: walks the Master File Table (MFT);
		* `AlternateStreamView[64].exe`: lists Alternate Data Streams (ADSs);
		* `md5deep[64].exe`: computes Message Digest 5 (MD5) hash values;
		* `ntfsinfo[64].exe`: shows information about NTFS;
	* `mal\`: malware tools:
		* `autorunsc[64].exe`: lists autorun locations;
		* `densityscout[64].exe`: computes an entropy-based measure for detecting packers and encryptors;
		* `DriverView[64].exe`: lists loaded kernel drivers;
		* `handle[64].exe`: lists object handles;
		* `iconsext.exe`: extracts icons from Portable Executables (PEs);
		* `Listdlls[64].exe`: lists loaded DLLs;
		* `pslist[64].exe`: lists running processes;
		* `PsService[64].exe`: lists services;
		* `sigcheck[64].exe`: checks digital signatures within PEs;
		* `WinPrefetchView[64].exe`: displays the contents of prefetch files;
	* `mem\`: memory tools:
		* `winpmem_1.6.2.exe`: dumps the memory;
	* `misc\`: miscellaneous tools:
		* `LastActivityView.exe`: displays a timeline of recent system activity;
		* `OfficeIns[64].exe`: lists installed Microsoft Office add-ins;
		* `USBDeview[64].exe`: lists previously and currently connected USB devices;
	* `net\`: network tools:
		* `psfile[64].exe`: lists files opened remotely;
		* `tcpvcon.exe`: lists TCP connections and ports and UDP ports;
	* `sys\`: system tools:
		* `accesschk[64].exe`: lists user permissions of the specified locations;
		* `logonsessions[64].exe`: lists currently active logon sessions;
		* `PsGetsid[64].exe`: translates between Security Identifiers (SIDs) and user names and vice-versa;
		* `Psinfo[64].exe`: displays system software and hardware information;
		* `psloggedon[64].exe`: lists locally logged on users that have their profile in the registry;
	* `web\`: web tools:
		* `BrowsingHistoryView[64].exe`: lists browsing history from multiple browsers;
		* `ChromeCacheView.exe`: displays the Google Chrome cache;
		* `IECacheView.exe`: displays the Internet Explorer cache;
		* `MozillaCacheView.exe`: displays the Mozilla Firefox cache;
	* `yara\`: YARA tools and signatures:
		* `rules\`: `*.yar` rules folder;
		* `yara(32|64).exe`: YARA main executable;
		* `yarac(32|64).exe`: YARA rules compiler;
	* `7za.exe`: compresses files and folders;
	* `sdelete(32|64).exe`: securely deletes files and folders;
* `data\`: data folder created during runtime with the collected data:
	* `<HOSTNAME>-<DATE>\`: `<DATE>` follows the `YYYYMMDD` format:
		* `ir-rescue.log`: verbose log file of status messages;
		* folders named according to the data type set for collection.

`ir-rescue` needs to be run under a command line console with **administrator rights** and requires no arguments. It makes use of a configuration file to set desired options. As such, executing the script simply needs the issuing of the Batch file as follows:

* `ir-rescue.bat`

Some tools that perform recursive searches or scans are set only to recurse on specific folders. This makes the data collection more targeted while taking into account run time performance as the folders specified are likely locations for analysis due to extensive use by malware. The folders set for **recursive search** are the following:

* `C:\Users`;
* `C:\ProgramData`;
* `C:\Windows\Temp`.

In turn, the following folders are set for **non-recursive search**:

* `C:\Windows\system(32|64)`;
* `C:\Windows\system(32|64)\drivers`;

During runtime, all characters printed to the Standard Output (`STDOUT`) and Standard Error (`STDERR`) channels are logged to UTF-8 encoded text files. This means that the output of tools are stored in corresponding folders and text files. Status ASCII messages are still printed to the console in order to check the execution progress. After collection, data is compressed into a password-protected archive and is accordingly deleted afterwards, if set to do so. The password of the resulting encrypted archive is "infected" without quotes.

# Configuration File

The configuration file is composed of simple binary directives (`true` or `false`) for the general behaviour of the script, for which data types to collect and for which advanced tools to run. The supported general directives are explained as follows:

* `killself`: this option directs the script to delete the the `tools` and `data` folder upon finishing, as well as deleting the Batch script itself;
* `sdelete`: this option activates the use of `sdelete.exe` (secure delete) in favour of the Windows built-in `del` and `rmdir`;
* `zip`: this option sets the compression of the resulting data folder;
* `ascii`: this option sets the printing of fun ASCII art upon completion.

Data is grouped into the types given by the following directives:

* `memory`: this options sets the collection of the memory;
* `registry`: this option sets the export of all registry hives, including user hives listed in `HKU\`;
* `events`: this option sets the export of Windows event logs;
* `system`: this option sets the collection of system-related information;
* `network`: this option sets the collection of networking data;
* `filesystem`: this option sets the collection of data related with NTFS and files; 
* `malware`: this option sets the collection of system data that can be used to spot malware;
* `web`: this option sets the collection of browsing history and caches;
* `misc`: this option sets the collection of USB device usage and Microsoft Office add-ins.

On the one hand, the usage of advanced tools set by the `sigcheck`, `density`, `iconext` and `yara` options is independent of the configurations made to the collection of data types. On the other hand, directives under submodules are tied to their respective main options. For example, `filesystem-simple` instructs the tool to run a simpler filesystem analysis focused on file listing, skipping the MFT walk, the computation of MD5 values, and the listing of ADSs. This option is disregarded if `filesystem` is set to `false`.

Note that the `iconext` option is useful to look for binaries compiled with unusual frameworks that set PE icons (*e.g.*, Python). Moreover, YARA rules need to have a `*.yar` file extension and to be put in the `tools\yara\rules\` folder. The output of all advanced tools are stored under the `malware` resulting folder.

Below is a working example of the configuration file setting the collection of the memory, registry and Windows event logs, as well as the compression of the final data folder. 

```
# ir-rescue configuration file
# accepted values: 'true' or 'false' (exclusive)

# general
killself=false
sdelete=false
zip=true
ascii=false

# modules
memory=true
registry=true
events=true
system=false
network=false
filesystem=false
malware=false
web=false
misc=false

# submodules
filesystem-simple=false

# advanced
sigcheck=false
density=false
iconext=false
yara=false
```

# Third-Party Tool List and References

* **Sysinternals**: the [Sysinternals](https://technet.microsoft.com/en-us/sysinternals/ "Sysinternals Web Site") tools have been mostly developed by Mark Russinovich and are free to use under the [Sysinternals Software License Terms](https://technet.microsoft.com/en-us/sysinternals/bb469936.aspx "Sysinternals Software License Terms"). The full list of tools used by *ir-rescue* is `accesschk.exe`, `autorunsc.exe`, `handle.exe`, `Listdlls.exe`, `logonsessions.exe`, `ntfsinfo.exe`, `psfile.exe`, `PsGetsid.exe`, `Psinfo.exe`, `pslist.exe`, `psloggedon.exe`, `psloglist.exe`, `PsService.exe`, `sdelete.exe`, `sigcheck.exe`, and `tcpvcon.exe`.

* **NirSoft**: the [NirSoft](http://www.nirsoft.net/ "NirSoft Web Site") suite of tools are developed by Nir Sofer and are released as freeware utilities. The full list of tools used by *ir-rescue* is `AlternateStreamView.exe`, `BrowsingHistoryView.exe`, `ChromeCacheView.exe`, `DriverView.exe`, `iconsext.exe`, `IECacheView.exe`, `LastActivityView.exe`, `MozillaCacheView.exe`, `OfficeIns.exe`, `USBDeview.exe`, and `WinPrefetchView.exe`.

* **Cygwin**: the [Cygwin](http://www.cygwin.com/ "Cygwin Web Site") project is open-source and is used by *ir-rescue* only to cut out non-printable characters via the `tr.exe` utility.

* **The Sleuth Kit (TSK)**: the [TSK](http://www.sleuthkit.org/ "TSK Web Site") is an open-source forensic tool to analyze hard drives at the file system level, used by *ir-rescue* only to walk the MFT with `fls.exe`.

* **7za.exe**: [7-Zip](http://www.7-zip.org/) is an open-source compression utility developed by Igor Pavlov and release under the GNU LGPL license.

* **winpmem_1.6.2**: the [Pmem](https://github.com/google/rekall "Rekall GitHub Repository") suite is part of the open-source Recall memory analysis framework, used by *ir-rescue* to dump the memory.

* **md5deep.exe**: the [md5deep](http://md5deep.sourceforge.net/ "md5deep Web Site") utility is open-source and is maintained by Jesse Kornblum.

* **densityscout.exe**: the [DensityScout](https://www.cert.at/downloads/software/densityscout_en.html "DensityScout Web Site") utility was written by Christian Wojner and is released under the ISC license. 

* **YARA**: [YARA](http://virustotal.github.io/yara/ "Yara Web Site") is an open-source signature scheme for malware that can be used to perform scans of specific indicators.