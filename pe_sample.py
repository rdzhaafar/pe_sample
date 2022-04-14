from typing import List, Optional, Dict
from pathlib import Path

import html
import zipfile
from os import path
import os
import hashlib
import json
import urllib.parse
import re
import functools
import io
import subprocess as sub
import time
import platform

import malbook

# NOTE: StringSifter breaks with lightgbm>=3.3.2
malbook.ensure_package('lightgbm==3.1.0')
malbook.ensure_package('stringsifter')

malbook.ensure_package('beautifulsoup4')
import bs4
malbook.ensure_package('yara-python')
import yara
malbook.ensure_package('requests')
import requests as req
malbook.ensure_package('peid')
import peid
malbook.ensure_package('pyspamsum')
import spamsum
malbook.ensure_package('pefile')
import pefile
malbook.ensure_package('py-tlsh')
import tlsh
malbook.ensure_package('procmon-parser')
import procmon_parser


class _Cache:

    def __init__(self, cache_file):
        try:
            with open(cache_file, 'rt') as f:
                self._cache = json.load(f)
        except:
            self._cache = {}

        self._cache_file = cache_file

        # Init common cache
        if 'common' not in self._cache:
            self._cache['common'] = {}

    def save(self):
        if self._cache_file is None:
            return
        with open(self._cache_file, 'wt') as f:
            json.dump(self._cache, f)

    def set_current_sample(self, sample):
        self._sample = sample
        if sample not in self._cache:
            self._cache[sample] = {}

    def get(self, key):
        if key in self._cache[self._sample]:
            return self._cache[self._sample][key]
        return None

    def set(self, key, value):
        self._cache[self._sample][key] = value

    def get_common(self, key):
        if key in self._cache['common']:
            return self._cache['common'][key]
        return None

    def set_common(self, key, value):
        self._cache['common'][key] = value


class ScanConfig:
    hashes: List[str] = ['md5', 'sha1', 'sha256', 'imphash', 'spamsum', 'tlsh']

    malware_bazaar_lookup: bool = True

    virustotal_api_key: Optional[str] = None
    virustotal_analysis_timeout: int = 30

    output_path: Path = path.join(os.getcwd(), 'pe_sample_output')

    unzip: bool = True
    unzip_password: Optional[bytes] = b'infected'

    strings: bool = True
    strings_floss_exe: Path = path.join(os.getcwd(), 'bin', platform.system() + '-floss')
    strings_rank: bool = True
    strings_min_length: int = 8
    strings_regex_rules: Dict[str, re.Pattern] = {
        'http': re.compile(r'http.*'),
        'ipv4': re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),
    }

    yara: bool = True
    yara_rules_dir: Path = path.join(os.getcwd(), 'yara')

    peid: bool = True

    imports: bool = True
    imports_malapi: bool = True

    procmon_vm: Optional[str] = None
    procmon_vm_connection_attempts: int = 3
    procmon_trace_timeout: int = 20

    compare_to: List[Path] = []

    cache_results: bool = True


def scan(sample: Path, config: ScanConfig) -> None:
    if config.cache_results:
        cache_path = path.join(config.output_path, 'cache.json')
        cache = _Cache(cache_path)
    else:
        # XXX: Create discardable cache not backed by a file
        cache = _Cache(None)
    if not path.exists(config.output_path):
        os.mkdir(config.output_path)
    # XXX: Spin up the virtual machine as early as possible
    vm = None

    if config.procmon_vm is not None:
        vm = _VirtualMachine(config.procmon_vm, config.procmon_vm_connection_attempts)

    if config.unzip:
        unzipped = _unzip(sample, config)
        for s in os.listdir(unzipped):
            sample_path = path.join(unzipped, s)
            _scan(sample_path, config, cache, vm)
    else:
        _scan(sample, config, cache, vm)

    cache.save()


def _scan(sample, config, cache, vm):
    _hdr('Report for ' + path.basename(sample), h=1)
    with open(sample, 'rb') as f:
        data = f.read()
    pe = _pe(data)
    _checksums(data, pe, config, cache)

    if config.malware_bazaar_lookup:
        _bazaar(cache)
    if config.virustotal_api_key is not None:
        _virustotal(data, config, cache)
    if config.strings:
        _strings(sample, config, cache)
    if config.yara:
        _yara(data, config, cache)
    if config.peid:
        _peid(sample, cache)
    if config.imports:
        _imports(pe, config, cache)
    if len(config.compare_to) != 0:
        _compare(data, config, cache)
    if vm is not None:
        _procmon(data, cache, vm, config)


def _virustotal(data, config, cache):
    virustotal_response = cache.get('virustotal_response')
    if virustotal_response is None:
        def check(resp: req.Response):
            if resp.ok:
                return
            code = resp.status_code
            if code == 401:
                raise malbook.Error('VirusTotal API key is incorrect')
            elif code == 429:
                raise malbook.Error('VirusTotal daily quota exceeded')
            else:
                raise malbook.Error('Cannot connect to VirusTotal')
        sha256 = cache.get('sha256')
        files = {'file': (sha256, io.BytesIO(data))}
        headers = {
            'x-apikey': config.virustotal_api_key,
            'Accept': 'application/json',
        }
        resp = req.post(
            'https://www.virustotal.com/api/v3/files',
            headers=headers,
            files=files,
        )
        check(resp)
        analysis_id = resp.json()['data']['id']
        url = 'https://www.virustotal.com/api/v3/analyses/' + analysis_id
        for _ in range(config.virustotal_analysis_timeout):
            time.sleep(5)
            resp = req.get(url, headers=headers)
            check(resp)
            status = resp.json()['data']['attributes']['status']
            if status == 'completed':
                virustotal_response = resp.json()
                cache.set('virustotal_response', virustotal_response)
                break

    if virustotal_response is None:
        raise malbook.Error('Cannot get analysis result back from VirusTotal')
    results = virustotal_response['data']['attributes']['results']
    lis = ''
    n = 0
    for engine, res in results.items():
        cat = res['category']
        if cat == 'suspicious' or cat == 'malicious':
            verdict = res['result']
            lis += f'<li><b>{engine}</b> [{cat}]'
            if verdict is not None:
                lis += f'- {verdict}'
            lis += '</li>'
            n += 1

    if n == 0:
        malbook.output('<h3>No malware engines detected a threat</h3>')
    else:
        _hdr(f'{n} malware engines detected a threat')
        _ul(lis, n)


def _bazaar(cache):
    def make_request(query):
        response = req.post('https://mb-api.abuse.ch/api/v1/', data=query)
        if not response.ok:
            raise malbook.Error("Can't access Malware Bazaar")
        return response.json()

    lis = ''
    sha256 = cache.get('sha256')
    tlsh_ = cache.get('tlsh')
    imphash = cache.get('imphash')

    resp = cache.get('sha256_malwarebazaar_response')
    if resp is None:
        resp = cache.get('sha256_malwarebazaar_response') or make_request({
            'query': 'get_info',
            'hash': sha256,
        })
        cache.set('sha256_malwarebazaar_response', resp)
    if resp['query_status'] == 'hash_not_found':
        lis += '<li>No sample with this sha256 found</li>'
    else:
        lis += f'<li><a href="https://bazaar.abuse.ch/sample/{sha256}">Sample page</a></li>'

    if imphash is not None:
        resp = cache.get('imphash_malwarebazaar_response')
        if resp is None:
            resp = make_request({
                'query': 'get_imphash',
                'imphash': imphash,
                'limit': 100,
            })
            cache.set('imphash_malwarebazaar_response', resp)
        if resp['query_status'] == 'no_results':
            lis += '<li>No samples with matching imphash found</li>'
        else:
            n = len(resp['data'])
            link = f'https://bazaar.abuse.ch/browse.php?search=imphash:{imphash}'
            lis += f'<li><a href="{link}">{n} samples</a> with matching imphash</li>'

    if tlsh_ is not None:
        resp = cache.get('tlsh_malwarebazaar_response')
        if resp is None:
            # XXX: Malware Bazaar errors out when it receives
            # TLSH with the version prefix (T1...), which is especially
            # strange, considering that they provide the TLSH _with_
            # the version prefix on the website.
            tlsh_ = tlsh_[2:]
            resp = make_request({
                'query': 'get_tlsh',
                'tlsh': tlsh_,
                'limit': 100,
            })
            cache.set('tlsh_malwarebazaar_response', resp)
        if resp['query_status'] == 'no_results':
            lis += '<li>No samples with matching tlsh found</li>'
        else:
            n = len(resp['data'])
            link = f'https://bazaar.abuse.ch/browse.php?search=tlsh:{tlsh_}'
            lis += f'<li><a href="{link}">{n} samples</a> with matching tlsh</li>'

    _hdr('Malware Bazaar lookup')
    _ul(lis, 3)


def _pe(data):
    try:
        pe = pefile.PE(data=data)
        pe.parse_data_directories()
        return pe
    except pefile.PEFormatError:
        raise malbook.Error('Sample is not a portable executable')


def _unzip(zip_path, config):
    with open(zip_path, 'rb') as f:
        data = f.read()

    sha256 = _csum(hashlib.sha256, data)
    zip_out = path.join(config.output_path, sha256)

    if path.exists(zip_out):
        return zip_out

    os.mkdir(zip_out)
    with zipfile.ZipFile(zip_path, 'r') as z:
        z.extractall(zip_out, pwd=config.unzip_password)

    return zip_out


def _imports(pe, config, cache):
    imports = cache.get('imports')
    if imports is None:
        imports = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if hasattr(imp, 'name') and imp.name is not None:
                    name = imp.name.decode()
                    imports.append(name)
        cache.set('imports', imports)

    lis = []
    for imp in imports:
        quoted = urllib.parse.quote(imp)
        malapi_link = f'https://malapi.io/winapi/{quoted}'
        google_link = f'https://google.com/search?q={quoted}'

        if config.imports_malapi:
            cat = cache.get_common(imp)
            if cat is None:
                page = req.get(malapi_link)
                if not page.ok:
                    raise malbook.Error('Cannot connect to MalAPI')
                soup = bs4.BeautifulSoup(page.content, 'html.parser')
                found = soup.find_all('span', class_='attack-container')
                if len(found) != 0:
                    cat = found[0].text.strip()
                else:
                    cat = 'none'
                cache.set_common(imp, cat)

            if cat == 'none':
                lis.append(f'<li>{_hesc(imp)} [<a href={_hesc(google_link)}>Google</a>]</li>')
            else:
                lis.append(f'<li>{_hesc(imp)} - <b>{_hesc(cat)}</b> [<a href={_hesc(google_link)}>Google</a>] [<a href={_hesc(malapi_link)}>MalAPI</a>]')

        else:
            lis.append(f'<li>{_hesc(imp)} [<a href={_hesc(google_link)}>Google</a>]</li>')

    def cmp_imports(i0, i1):
        # XXX: Make imports found on MalAPI appear
        # first and also make helpers appear at the
        # bottom of those.
        ini0 = 'MalAPI' in i0
        ini1 = 'MalAPI' in i1
        if ini0 and ini1 and 'Helper' in i0:
            ini0 = False
        elif ini0 and ini1 and 'Helper' in i1:
            ini1 = False
        if ini0 and not ini1:
            return -1
        elif ini1 and not ini0:
            return 1
        else:
            return 0
    lis.sort(key=functools.cmp_to_key(cmp_imports))
    lis = ''.join(lis)

    _hdr('Portable executable imports')
    _ul(lis, len(imports))


def _peid(sample, cache):
    packer = cache.get('packer')
    if packer is None:
        try:
            packer = peid.identify_packer(sample)[0][1][0]
        except:
            packer = None
        cache.set('packer', packer)

    if packer is not None:
        _hdr('PEiD detected packer/compiler')
        malbook.output(f'<p>{packer}</p>')
    else:
        malbook.output('<h3>PEiD did not detect a packer/compiler</h3>')


def _yara(data, config, cache):
    rules = os.listdir(config.yara_rules_dir)

    if cache.get('yara') is None:
        cache.set('yara', [])

    matches = []
    for r in rules:
        if r in cache.get('yara'):
            matches.append(r)
        else:
            rule_path = path.join(config.yara_rules_dir, r)
            with open(rule_path, 'rt') as f:
                src = f.read()
            rule = yara.compile(source=src)
            rms = rule.match(data=data)
            if len(rms) != 0:
                matches.append(r)
                cache.get('yara').append(r)

    lis = ''
    for m in matches:
        lis += f'<li>{_hesc(m)}</li>'

    n = len(matches)
    if n == 0:
        malbook.output('<h3>There are no matching Yara rules</h3>')
    else:
        _hdr(f'{n} matching Yara rules')
        _ul(lis, n)


def _strings(sample, config, cache):
    strings = cache.get('strings')
    if strings is None:
        floss_exe = config.strings_floss_exe
        out = sub.run(
            [floss_exe, '-n', str(config.strings_min_length), '-q', sample],
            capture_output=True,
        )
        if out.returncode != 0:
            raise malbook.Error(f'FLOSS returned non-zero exit code:\n{out.stderr.decode()}')

        strings = out.stdout.decode().split('\n')
        cache.set('strings', strings)

    if config.strings_rank:
        ranked_strings = cache.get('ranked_strings')
        if ranked_strings is None:
            strs = '\n'.join(strings)
            ranked = sub.run(
                ['rank_strings'],
                capture_output=True, input=strs, encoding='utf-8'
            )
            if ranked.returncode != 0:
                raise malbook.Error('rank_strings returned non-zero exit code', ranked.stderr.decode())
            ranked_strings = ranked.stdout.split('\n')
            cache.set('ranked_strings', ranked_strings)
        strings = ranked_strings

    results = {}
    for s in strings:
        results[s] = []
        for name, rule in config.strings_regex_rules.items():
            if rule.match(s) is not None:
                results[s].append(name)

    # Format output
    lis = ''
    for s, rules in results.items():
        if len(rules) == 0:
            lis += f'<li>{_hesc(s)}</li>'
        else:
            lis += f'<li>{_hesc(s)}<ul>'
            for r in rules:
                lis += f'<li>{_hesc(r)}</li>'
            lis += '</ul></li>'

    _hdr('Strings')
    _ul(lis, len(results))


def _checksums(data, pe, config, cache):
    sha256 = _csum(hashlib.sha256, data)
    cache.set_current_sample(sha256)
    cache.set('sha256', sha256)

    lis = ''
    for h in config.hashes:
        sum = ''
        if hasattr(hashlib, h) and not h.startswith('shake'):
            sum = cache.get(h)
            if sum is None:
                alg = getattr(hashlib, h)
                sum = _csum(alg, data)
        elif h == 'imphash':
            sum = cache.get(h) or pe.get_imphash()
        elif h == 'spamsum':
            sum = cache.get(h) or spamsum.spamsum(data)
        elif h == 'tlsh':
            sum = cache.get(h) or tlsh.hash(data)
        else:
            if h == 'shake_128' or h == 'shake_256':
                raise malbook.Error('shake_128 and shake_256 are not supported')
            else:
                raise malbook.Error(f'Unknown hash algorithm {h}')
        cache.set(h, sum)
        lis += f'<li><b>{h}</b> - {sum}</li>'

    _hdr('Checksums')
    _ul(lis, len(config.hashes))


def _compare(data, config, cache):
    sample_sum = cache.get('spamsum')
    if sample_sum is None:
        sample_sum = spamsum.spamsum(data)
        cache.set('spamsum', sample_sum)
    lis = ''
    n = 0
    for fpath in config.compare_to:
        with open(fpath, 'rb') as f:
            fdata = f.read()
        f_sum = spamsum.spamsum(fdata)
        match = spamsum.match(sample_sum, f_sum)
        lis += f'<li>{match}% - {fpath}</li>'
        n += 1
    _hdr('Similarity scores')
    _ul(lis, n)


class _VirtualMachine:

    def __init__(self, name, connection_attempts):
        self.name = name
        self.connection_attempts = connection_attempts

        # Check vboxmanage
        ok, _ = self._cmd(['--version'])
        if not ok:
            raise malbook.Error("'vboxmanage' command not found. Is VirtualBox installed?")

        # Check guest OS type
        ok, out = self._cmd(['showvminfo', name, '--machinereadable'])
        if not ok:
            raise malbook.Error(f'Virtual machine "{name}" not found')
        for line in out.split('\n'):
            split = line.split('=')
            if len(split) != 2:
                continue
            key = split[0]
            val = split[1]
            if key == 'GuestOSType' and val != '"Windows10_64"':
                raise malbook.Error(f'OS "{val}" is not supported')

        # Get guest IP
        ok, out = self._cmd(['guestproperty', 'get', name, '/VirtualBox/GuestInfo/Net/0/V4/IP'])
        if not ok or not out.startswith('Value: '):
            raise malbook.Error('Virtual machine IP address not found. Is it running?')
        ip = out[len('Value: '):-1]
        url = 'http://' + ip + ':5000'
        self.url = url

        # Connect
        self._req('GET', '/status')

    def trace(self, config, cache, sample_bytes):
        sha256 = cache.get('sha256')
        resp = self._req('POST', '/submit', {
            'sample': list(sample_bytes),
            'sha256': sha256,
            'timeout': config.procmon_trace_timeout,
        })
        time.sleep(config.procmon_trace_timeout)
        resp = self._req('GET', '/get_log', {'sha256': sha256})
        pml_file = path.join(config.output_path, sha256 + '.pml')
        with open(pml_file, 'wb') as f:
            f.write(bytes(resp['log']))

        cache.set('pml_file', pml_file)
        cache.set('sample_pid', resp['pid'])

    def _req(self, method, endpoint, data=None):
        resp = None
        for _ in range(self.connection_attempts):
            try:
                url = self.url + endpoint
                resp = req.request(method, url, json=data, timeout=(1.0, 180))
                break
            except:
                time.sleep(1)
        if resp is None:
            raise malbook.Error(f"Can't connect to the virtual machine at '{self.url}'")
        resp = resp.json()
        if resp['status'] != 'ok':
            err = resp['error']
            raise malbook.Error(f'Virtual machine error: {err}')
        return resp

    def _cmd(self, cmd):
        full = ['vboxmanage']
        full.extend(cmd)
        out = sub.run(full, capture_output=True)
        if out.returncode == 0:
            return True, out.stdout.decode('utf-8')
        else:
            return False, out.stderr.decode('utf-8')


def _procmon(data, cache, vm, config):
    pml_file = cache.get('pml_file')
    sample_pid = cache.get('sample_pid')
    err = None
    if pml_file is None:
        try:
            vm.trace(config, cache, data)
            pml_file = cache.get('pml_file')
            sample_pid = cache.get('sample_pid')
        except Exception as e:
            err = str(e)
    if err is not None:
        malbook.output(f"<h3>Couldn't trace sample: {err}</h3>")
        return

    # XXX: Sometimes a ransomware corrupts the log file before it's transited
    # to the host
    try:
        pml_fd = open(pml_file, 'rb')
        reader = procmon_parser.ProcmonLogsReader(pml_fd)
        lis = ''
        n = 0
        for event in reader:
            if event.process.pid == sample_pid:
                lis += f'<li>{_hesc(str(event))}</li>'
                n += 1
        pml_fd.close()
    except procmon_parser.PMLError:
        pml_fd.close()
        malbook.output('<h3>Process Monitor log file is corrupt</h3>')
        return

    _hdr('Events recorded by Process Monitor')
    _ul(lis, n)


def _csum(algorithm, data):
    h = algorithm()
    h.update(data)
    return h.hexdigest()


def _hesc(text):
    return html.escape(text)


def _hdr(text, h=3):
    malbook.output(f'<h{h}>{text}:</h{h}>')


def _ul(lis, n, hide=10):
    if n == 0:
        malbook.output('<p><b>None</b></p>')
    elif n <= hide:
        malbook.output(f'<p><ul>{lis}</ul></p>')
    else:
        malbook.output(f'''
        <p>
            <details>
                <summary>
                    Click here to show all {n}
                </summary>
                <ul>
                    {lis}
                </ul>
            </details>
        </p>
        ''')
