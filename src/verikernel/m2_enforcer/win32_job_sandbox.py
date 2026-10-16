"""Kernel-enforced resource limits and signed accounting; O(B) captured output space."""
from __future__ import annotations
import ctypes
from ctypes import wintypes as w
import hashlib
import hmac
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[3]
MEMORY_LIMIT = 16*1024*1024
JOB_FLAGS = 0x8 | 0x100 | 0x400 | 0x2000


class BasicLimits(ctypes.Structure):
    """Native JOBOBJECT_BASIC_LIMIT_INFORMATION; O(1) layout."""
    _fields_ = [('process_time',ctypes.c_int64),('job_time',ctypes.c_int64),('flags',w.DWORD),
                ('minimum_working_set',ctypes.c_size_t),('maximum_working_set',ctypes.c_size_t),
                ('active_process_limit',w.DWORD),('affinity',ctypes.c_size_t),('priority',w.DWORD),('scheduling',w.DWORD)]


class IoCounters(ctypes.Structure):
    """Native six-counter IO_COUNTERS; O(1) layout."""
    _fields_ = [(name,ctypes.c_uint64) for name in ['read_operations','write_operations','other_operations','read_bytes','write_bytes','other_bytes']]


class ExtendedLimits(ctypes.Structure):
    """Native extended job limits; O(1) fixed layout."""
    _fields_ = [('basic',BasicLimits),('io',IoCounters),('process_memory',ctypes.c_size_t),
                ('job_memory',ctypes.c_size_t),('peak_process_memory',ctypes.c_size_t),('peak_job_memory',ctypes.c_size_t)]


class Accounting(ctypes.Structure):
    """Kernel job accounting with 100ns CPU counters; O(1) layout."""
    _fields_ = [('user_time',ctypes.c_int64),('kernel_time',ctypes.c_int64),('period_user',ctypes.c_int64),('period_kernel',ctypes.c_int64),
                ('page_faults',w.DWORD),('total_processes',w.DWORD),('active_processes',w.DWORD),('terminated_processes',w.DWORD)]


class Startup(ctypes.Structure):
    """Win32 STARTUPINFOW; O(1) layout."""
    _fields_ = [('cb',w.DWORD),('reserved',w.LPWSTR),('desktop',w.LPWSTR),('title',w.LPWSTR),
                ('x',w.DWORD),('y',w.DWORD),('xsize',w.DWORD),('ysize',w.DWORD),('xcount',w.DWORD),('ycount',w.DWORD),
                ('fill',w.DWORD),('flags',w.DWORD),('show',w.WORD),('reserved_size',w.WORD),('reserved_bytes',ctypes.c_void_p),
                ('stdin',w.HANDLE),('stdout',w.HANDLE),('stderr',w.HANDLE)]


class StartupExtended(ctypes.Structure):
    """Explicit inherited-handle allowlist; O(1) layout."""
    _fields_ = [('startup',Startup),('attributes',ctypes.c_void_p)]


class ProcessInformation(ctypes.Structure):
    """Process and primary thread handles; O(1) layout."""
    _fields_ = [('process',w.HANDLE),('thread',w.HANDLE),('pid',w.DWORD),('tid',w.DWORD)]


class Win32JobSandbox:
    """Configure before launch, assign while suspended, then resume; O(1) state."""
    def __init__(self, memory_limit: int = MEMORY_LIMIT) -> None:
        """Bind checked kernel APIs; O(1) time and space."""
        if sys.platform != 'win32':
            raise OSError('NT Job Objects require Windows')
        if memory_limit < 1024*1024:
            raise ValueError('memory cap is too small for process startup')
        self.memory_limit = memory_limit
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        signatures = {
            'CreateJobObjectW':([ctypes.c_void_p,w.LPCWSTR],w.HANDLE),
            'SetInformationJobObject':([w.HANDLE,ctypes.c_int,ctypes.c_void_p,w.DWORD],w.BOOL),
            'AssignProcessToJobObject':([w.HANDLE,w.HANDLE],w.BOOL),
            'QueryInformationJobObject':([w.HANDLE,ctypes.c_int,ctypes.c_void_p,w.DWORD,ctypes.c_void_p],w.BOOL),
            'TerminateJobObject':([w.HANDLE,w.UINT],w.BOOL),
            'TerminateProcess':([w.HANDLE,w.UINT],w.BOOL),
            'CreateProcessW':([w.LPCWSTR,w.LPWSTR,ctypes.c_void_p,ctypes.c_void_p,w.BOOL,w.DWORD,ctypes.c_void_p,w.LPCWSTR,ctypes.c_void_p,ctypes.c_void_p],w.BOOL),
            'ResumeThread':([w.HANDLE],w.DWORD),'WaitForSingleObject':([w.HANDLE,w.DWORD],w.DWORD),
            'GetExitCodeProcess':([w.HANDLE,ctypes.POINTER(w.DWORD)],w.BOOL),'CloseHandle':([w.HANDLE],w.BOOL),
            'InitializeProcThreadAttributeList':([ctypes.c_void_p,w.DWORD,w.DWORD,ctypes.POINTER(ctypes.c_size_t)],w.BOOL),
            'UpdateProcThreadAttribute':([ctypes.c_void_p,w.DWORD,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_void_p],w.BOOL),
            'DeleteProcThreadAttributeList':([ctypes.c_void_p],None)}
        for name,(arguments,result) in signatures.items():
            function = getattr(self.kernel,name)
            function.argtypes, function.restype = arguments,result

    def _check(self, result: int) -> None:
        """Raise the exact last Win32 error; O(1) time and space."""
        if not result:
            raise ctypes.WinError(ctypes.get_last_error())

    def run(self, binary: str | Path, arguments: list[str], timeout: float = 20) -> dict[str, object]:
        """Run with a suspended-launch race barrier; O(B) output time/space."""
        import msvcrt
        job = self.kernel.CreateJobObjectW(None,None)
        self._check(job)
        information = ProcessInformation()
        attributes = None
        initialized = False
        started = time.perf_counter()
        with tempfile.TemporaryDirectory(dir=ROOT/'.tmp',prefix='nt_job_') as directory:
            try:
                limits = ExtendedLimits()
                limits.basic.flags, limits.basic.active_process_limit = JOB_FLAGS,1
                limits.process_memory = self.memory_limit
                self._check(self.kernel.SetInformationJobObject(job,9,ctypes.byref(limits),ctypes.sizeof(limits)))
                with open(Path(directory)/'output.log','w+b') as output, open(os.devnull,'rb') as input_stream:
                    inherited = [msvcrt.get_osfhandle(output.fileno()),msvcrt.get_osfhandle(input_stream.fileno())]
                    for handle in inherited:
                        os.set_handle_inheritable(handle,True)
                    size = ctypes.c_size_t()
                    self.kernel.InitializeProcThreadAttributeList(None,1,0,ctypes.byref(size))
                    attributes = ctypes.create_string_buffer(size.value)
                    self._check(self.kernel.InitializeProcThreadAttributeList(attributes,1,0,ctypes.byref(size)))
                    initialized = True
                    handles = (w.HANDLE*2)(*inherited)
                    self._check(self.kernel.UpdateProcThreadAttribute(attributes,0,0x20002,handles,ctypes.sizeof(handles),None,None))
                    startup = StartupExtended()
                    startup.startup.cb = ctypes.sizeof(startup)
                    startup.startup.flags = 0x100
                    startup.startup.stdin, startup.startup.stdout, startup.startup.stderr = inherited[1],inherited[0],inherited[0]
                    startup.attributes = ctypes.cast(attributes,ctypes.c_void_p)
                    command = ctypes.create_unicode_buffer(subprocess.list2cmdline([str(Path(binary).resolve()),*arguments]))
                    self._check(self.kernel.CreateProcessW(str(Path(binary).resolve()),command,None,None,True,0x4|0x08000000|0x80000,None,str(Path(directory)),ctypes.byref(startup),ctypes.byref(information)))
                    self._check(self.kernel.AssignProcessToJobObject(job,information.process))
                    if self.kernel.ResumeThread(information.thread) == 0xffffffff:
                        raise ctypes.WinError(ctypes.get_last_error())
                    waiting = self.kernel.WaitForSingleObject(information.process,int(timeout*1000))
                    if waiting == 258:
                        self._check(self.kernel.TerminateJobObject(job,124))
                        self.kernel.WaitForSingleObject(information.process,5000)
                        raise TimeoutError('job runtime exceeded the limit')
                    if waiting != 0:
                        raise ctypes.WinError(ctypes.get_last_error())
                    code = w.DWORD()
                    self._check(self.kernel.GetExitCodeProcess(information.process,ctypes.byref(code)))
                    accounting = Accounting()
                    self._check(self.kernel.QueryInformationJobObject(job,1,ctypes.byref(accounting),ctypes.sizeof(accounting),None))
                    self._check(self.kernel.QueryInformationJobObject(job,9,ctypes.byref(limits),ctypes.sizeof(limits),None))
                    output.seek(0)
                    text = output.read(65536).decode('utf-8',errors='replace')
                    decoded = [json.loads(line) for line in text.splitlines() if line.startswith('{')]
                    evidence = decoded[-1] if decoded else {}
                    return {**evidence,'returncode':code.value,'pid':information.pid,'tid':information.tid,
                            'assigned_before_resume':True,'memory_limit_bytes':self.memory_limit,
                            'peak_process_memory_bytes':limits.peak_process_memory,
                            'accounting':{name:int(getattr(accounting,name)) for name,_ in Accounting._fields_},
                            'elapsed_seconds':time.perf_counter()-started,'output':text,'backend':'windows-nt-job'}
            finally:
                if information.process:
                    self.kernel.TerminateJobObject(job,125)
                    self.kernel.TerminateProcess(information.process,125)
                for handle in [information.thread,information.process,job]:
                    if handle:
                        self.kernel.CloseHandle(handle)
                if initialized:
                    self.kernel.DeleteProcThreadAttributeList(attributes)


def seal_accounting(result: dict[str, object], ledger_dir: str | Path) -> None:
    """Bind actual accounting JSON to a signed ledger leaf; O(B) time and space."""
    from verikernel.m4_attest.ledger_store import ChainedTransparencyLedger
    from verikernel.schemas import KernelTelemetryEvent
    directory = Path(ledger_dir)
    directory.mkdir(parents=True,exist_ok=True)
    payload = json.dumps(result,sort_keys=True,separators=(',',':')).encode()
    event = KernelTelemetryEvent(timestamp_ns=time.monotonic_ns(),pid=os.getpid(),syscall_nr=1,target_digest=hashlib.sha256(payload).digest())
    ChainedTransparencyLedger(directory).append([event])
    (directory/'kernel_accounting.json').write_bytes(payload)


def verify_kernel_accounting(ledger_dir: str | Path, trusted_public_key: bytes | None = None) -> dict[str, object]:
    """Verify the ledger and exact bound accounting bytes; O(B) time and space."""
    from verikernel.m4_attest.ledger_store import load_history, verify_ledger_history
    from verikernel.schemas import KernelTelemetryEvent
    directory = Path(ledger_dir)
    verified = verify_ledger_history(directory,trusted_public_key=trusted_public_key)
    history = load_history(directory)
    if len(history['epochs']) != 1 or len(history['epochs'][0]['leaves']) != 1:
        raise ValueError('kernel accounting profile requires one epoch and one aggregate leaf')
    event = KernelTelemetryEvent.from_bytes(bytes.fromhex(history['epochs'][0]['leaves'][0]))
    payload = (directory/'kernel_accounting.json').read_bytes()
    if not hmac.compare_digest(event.target_digest,hashlib.sha256(payload).digest()):
        raise ValueError('kernel accounting payload differs from its signed digest')
    return {**verified,'accounting_bound':True,'kernel_accounting':json.loads(payload)}


def run_resource_confinement(ledger_dir: str | Path) -> dict[str, object]:
    """Compare unconstrained controls with real kernel denials; O(128 MB) control space."""
    from .native_supervisor import target_binary
    binary = target_binary()
    temporary = ROOT/'.tmp'
    with tempfile.TemporaryDirectory(dir=temporary,prefix='resource_probe_') as name:
        marker = Path(name)/'child.marker'
        controls = []
        for arguments in [['--uncooperative-spawn','--marker',str(marker)],['--uncooperative-memory-hog']]:
            completed = subprocess.run([str(binary),*arguments],capture_output=True,text=True,check=True,timeout=30)
            controls.append(json.loads(completed.stdout.splitlines()[-1]))
        if not marker.exists():
            raise ValueError('unrestricted child did not execute')
        marker.unlink()
        if sys.platform == 'win32':
            sandbox = Win32JobSandbox()
            spawn = sandbox.run(binary,['--uncooperative-spawn','--marker',str(marker)])
            memory = sandbox.run(binary,['--uncooperative-memory-hog'])
        else:
            launcher = binary.parent/'verikernel-sandbox-exec'
            measured = []
            for arguments in [['--uncooperative-spawn','--marker',str(marker)],['--uncooperative-memory-hog']]:
                completed = subprocess.run([str(launcher),'--memory-bytes',str(MEMORY_LIMIT),'--',str(binary),*arguments],capture_output=True,text=True,timeout=30)
                lines = [json.loads(line) for line in completed.stdout.splitlines() if line.startswith('{')]
                if not lines:
                    raise ValueError('restricted native target emitted no result')
                measured.append({**lines[-1],'returncode':completed.returncode,'backend':'linux-preexec'})
            spawn,memory = measured
        if marker.exists() or not spawn.get('denied') or not memory.get('denied'):
            raise ValueError('kernel resource confinement did not deny the attack')
        result = {'spawn':spawn,'memory':memory,'controls':{'spawn_succeeded':not controls[0]['denied'],'memory_succeeded':not controls[1]['denied']}}
        seal_accounting(result,ledger_dir)
        return result
