# pe_sample

A malbook template for automated analysis of PE malware samples.

## Requirements

- Python 3.9
- [malbook](https://www.github.com/rdzhaafar/malbook)
- (Optional) VirtualBox 6.1

## Installation

Download this template from the releases page and install it
using [malbook](https://www.github.com/rdzhaafar/malbook):

```shell
$ malbook template load pe_sample.zip pe_sample
$ cd pe_sample
$ malbook run
```

## Usage

For example usage, see the [example notebook](./example.ipynb).

## Scan configuration

Scan configuration is done by passing an instance of `pe_sample.ScanConfig` to
the `scan()` function. This object has the following fields:

- `.hashes: List[str] = ['md5', 'sha1', 'sha256', 'imphash', 'spamsum', 'tlsh']`

List of checksums to calculate for the sample. Available algorithms
are all the hashing algorithms supported by Python's hashlib library
(except for shake_128 and shake_256), spamsum, tlsh, and imphash.

- `.malware_bazaar_lookup: bool = True`

Whether to lookup the sample by sha256, imphash, and tlsh on 
[Malware Bazaar](https://bazaar.abuse.ch/).

- `.virustotal_api_key: Optional[str] = None`

[VirusTotal](https://www.virustotal.com) API key. If set to `None`,
sample is not submitted to VirusTotal for analysis.

- `.virustotal_analysis_timeout: int = 30`

Timeout for getting the analysis back from
[VirusTotal](https://www.virustotal.com).

- `.output_path: Path = os.path.join(os.getcwd(), 'pe_sample_output')`

Folder where intermediary analysis output is stored (extracted malware samples,
Process Monitor log files, etc.)

- `.unzip: bool = True`

Whether the sample needs to be unzipped before proceeding.

- `.unzip_password: Optional[bytes] = b'infected'`

Password for the zip archive. If set to `None`, the archive is assumed
to have no password.

- `.strings: bool = True`

Whether to extract strings from the sample.

- `.strings_floss_exe: Path = os.path.join(os.getcwd(), 'bin', platform.system() + '-floss'`

[FLOSS](https://github.com/mandiant/flare-floss) executable path.

- `.strings_rank: bool = True`

Whether to rank strings extracted by [FLOSS](https://github.com/mandiant/flare-floss) with [StringSifter](https://github.com/mandiant/stringsifter).

- `.strings_min_length: int = 8`

The minimum string length to extract with [FLOSS](https://github.com/mandiant/flare-floss).

- `.strings_regex_rules: Dict[str, re.Pattern] = {
    'http': re.compile(r'http.*'),
    'ipv4': re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),
}`

Regex rules to apply to strings. The key is pattern name, and the value 
is the compiled instance of `re.Pattern`.

- `.yara: bool = True`

Whether to check for [Yara](https://github.com/VirusTotal/yara) rule matches.

- `.yara_rules_dir: Path = os.path.join(os.getcwd(), 'yara')`

The folder containing [Yara](https://github.com/VirusTotal/yara) rules files.

- `.peid: bool = True`

Whether to try and detect the packer/compiler with [PEiD](https://github.com/dhondta/peid)

- `.imports: bool = True`

Whether to extract the import table from the executable.

- `.imports_malapi: bool = True`

Whether to lookup attack type associated with a certain import
on [MalAPI](https://malapi.io/).

- `.procmon_vm_name: Optional[str] = None`

Name of the [VirtualBox](https://www.virtualbox.org/) virtual machine
to use for tracing the sample with 
[Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon).
[More](#preparing-the-virtual-machine-for-process-monitor-tracing) on preparing
the virtual machine. If set to `None` tracing is skipped.

- `.procmon_vm_connection_attempts: int = 3`

How many connection attempts to the virtual machine to make before giving up.

- `.procmon_trace_timeout: int = 20`

How many seconds to capture [Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)
for.

- `.compare_to: List[Path] = []`

What samples to compare the sample to using spamsum.

- `.cache_results: bool = True`

Whether to save scan results for consecutive analyses of the same
sample.

## Preparing the virtual machine for Process Monitor tracing

1. [Create](https://www.virtualbox.org/manual/ch01.html#gui-createvm) a new Windows 10 64-bit virtual machine.
2. [Disable](https://support.microsoft.com/en-us/windows/turn-microsoft-defender-firewall-on-or-off-ec0844f7-aebd-0583-67fe-601ecf5d774f#ID0EFD=Windows_10) the firewall and ensure that VM can accept incoming network connections
3. [Disable](https://support.microsoft.com/en-us/windows/turn-off-defender-antivirus-protection-in-windows-security-99e6004f-c54c-8509-773c-a4d776b77960#:~:text=Select%20the%20Windows%20Security%20app,scans%20will%20continue%20to%20run.) Windows Defender live scanning
4. [Install](https://www.python.org/downloads) Python
5. [Install](https://flask.palletsprojects.com/en/2.1.x/) Flask
6. [Download](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) Process Monitor and extract `Procmon64.exe` to `C:\Procmon64.exe`
7. [Download](./guest/guest.py) the guest script and save it in `C:\guest.py`
8. [Download](./guest/start.bat) the guest launch script save it in `C:\start.bat`
9. [Set up](https://www.virtualbox.org/manual/ch06.html#network_hostonly) host-only networking in VirtualBox.

The guest script placed at `C:\start.py` needs to be launched as administrator before the host component
can connect to the virtual machine. Do automate that, you can optionally add a task using
Windows Task Scheduler:

- Open Task Scheduler
- Click on **Create Task...**
- Go to **General** tab
- Tick **Run with highest privileges** checkbox under **Security Options**
- Select **Windows 10** under **Configure for:**
- Go to **Triggers** tab
- Click on **New...**
- Select **At log on** in **Begin the task:**
- Click on **OK**
- Go to **Actions** tab
- Select **Start a program** in **Action:**
- Click on **Browse**, go to `C:\` and select the `start.bat` script
- Click on **OK**
- Go to **Conditions** tab
- Make sure that **Start the task only if the computer is on AC power** checkbox is not ticked
- Click on **Apply**

Additionally, it's a good idea to [take](https://www.virtualbox.org/manual/ch01.html#snapshots-take-restore-delete) a
snapshot of the newly created virtual machine now, so that you can revert to it later if a malware sample damages it.

# Acknowledgements

This work would not be possible without the following programs/libraries/services:

- [VirtualBox](https://www.virtualbox.org/)
- [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/)
- [Yara](https://github.com/VirusTotal/yara)
- [Requests](https://docs.python-requests.org/en/latest/)
- [PEiD](https://github.com/dhondta/peid)
- [PySpamSum](https://github.com/freakboy3742/pyspamsum/)
- [pefile](https://github.com/erocarrera/pefile)
- [Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)
- [procmon-parser](https://github.com/eronnen/procmon-parser)
- [FLOSS](https://github.com/mandiant/flare-floss)
- [StringSifter](https://github.com/mandiant/stringsifter)
- [Malware Bazaar](https://bazaar.abuse.ch/)
- [VirusTotal](https://www.virustotal.com/)
- [Yara-Rules](https://github.com/Yara-Rules/rules)
- [MalAPI](https://malapi.io/)
