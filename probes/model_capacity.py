"""Public model, synthetic inputs only. Capacity estimate, NOT a security boundary."""
import ctypes, hashlib, json, os, shutil, socket, subprocess, sys, tempfile, threading, time, urllib.request, zipfile
from ctypes import wintypes
from pathlib import Path
MODEL_URL='https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct-GGUF/resolve/13fb94bfda8c8cf22497dc57b78f391a9acb426a/qwen2.5-coder-7b-instruct-q4_k_m.gguf'
MODEL_HASH='509287f78cb4d4cf6b3843734733b914b2c158e43e22a7f4bf5e963800894d3c'
ARCHIVE_URL='https://github.com/ggml-org/llama.cpp/releases/download/b10809/llama-b10809-bin-win-cpu-x64.zip'
ARCHIVE_HASH='9df3158ed228a641a4b127942d7f459f24c9e13f04682659d05c00c80099b6b5'
EXE_HASH='cb29f66008d4d73cce17cab2c2569ab318eb244b0b2ca2a15024b44d90dfcd3f'
TREE_HASH='bb475cebe58bca1c48b25938888a94fefa50e2234ecbe4e3ed50cd7ec13e7db6'
def fingerprint(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()
def download(url,p,expected):
    start=time.monotonic()
    with urllib.request.urlopen(url,timeout=60) as r,p.open('wb') as f:
        while True:
            if time.monotonic()-start>600: raise RuntimeError('DOWNLOAD_TIME_BOUND')
            b=r.read(1024*1024)
            if not b: break
            f.write(b)
    if fingerprint(p)!=expected: raise RuntimeError('DOWNLOAD_HASH_MISMATCH')
    return {'bytes':p.stat().st_size,'seconds':time.monotonic()-start,'sha256':expected}
def runtime_hash(root):
    h=hashlib.sha256()
    for name in sorted(p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()):
        b=name.encode();h.update(len(b).to_bytes(4,'big'));h.update(b);h.update(bytes.fromhex(fingerprint(root/name)))
    return h.hexdigest()
class Memory(ctypes.Structure):
    _fields_=[('cb',wintypes.DWORD),('faults',wintypes.DWORD)]+[(n,ctypes.c_size_t) for n in ('peak','working','qpp','qp','qnp','qn','commit','peakCommit','private')]
class GlobalMemory(ctypes.Structure):
    _fields_=[('length',wintypes.DWORD),('load',wintypes.DWORD)]+[(n,ctypes.c_ulonglong) for n in ('total','available','pageTotal','pageAvailable','virtualTotal','virtualAvailable','extended')]
def main():
    if os.name!='nt': raise RuntimeError('WINDOWS_REQUIRED')
    if os.environ.get('PUBLIC_SYNTHETIC_MODEL_PROBE')!='1': raise RuntimeError('EXPLICIT_PUBLIC_PROBE_REQUIRED')
    root=Path(tempfile.mkdtemp(prefix='public-model-',dir=os.environ['RUNNER_TEMP']))
    proc=None; stop=threading.Event(); monitor=None; handle=None
    result={'schema':1,'syntheticOnly':True,'privateRunnerProven':False,'isolationProven':False,'fullBuildProven':False,'configuredContext':24576,'maxOutputTokens':4096,'threads':12,'gpuLayers':0,'cpuAffinityLogicalProcessors':2,'memoryCapEnforced':False,'privateMemoryTargetBytes':8*1024**3,'status':'STARTED'}
    started=time.monotonic();k=ctypes.WinDLL('kernel32',use_last_error=True);ps=ctypes.WinDLL('psapi',use_last_error=True)
    k.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD];k.OpenProcess.restype=wintypes.HANDLE
    k.SetProcessAffinityMask.argtypes=[wintypes.HANDLE,ctypes.c_size_t];k.SetProcessAffinityMask.restype=wintypes.BOOL
    k.GetProcessAffinityMask.argtypes=[wintypes.HANDLE,ctypes.POINTER(ctypes.c_size_t),ctypes.POINTER(ctypes.c_size_t)]
    k.CloseHandle.argtypes=[wintypes.HANDLE]
    ps.GetProcessMemoryInfo.argtypes=[wintypes.HANDLE,ctypes.POINTER(Memory),wintypes.DWORD]
    k.GetProcessTimes.argtypes=[wintypes.HANDLE]+[ctypes.POINTER(wintypes.FILETIME)]*4
    k.GlobalMemoryStatusEx.argtypes=[ctypes.POINTER(GlobalMemory)]
    def mem():
        m=GlobalMemory();m.length=ctypes.sizeof(m)
        if not k.GlobalMemoryStatusEx(ctypes.byref(m)): raise RuntimeError('SYSTEM_MEMORY_READ')
        return m
    def sample():
        m=Memory();m.cb=ctypes.sizeof(m)
        if not ps.GetProcessMemoryInfo(handle,ctypes.byref(m),m.cb): raise RuntimeError('PROCESS_MEMORY_READ')
        for key,value in [('peakWorkingSetBytes',m.peak),('peakCommitBytes',m.peakCommit),('peakPrivateBytes',m.private)]: result[key]=max(result.get(key,0),value)
        result['minSystemAvailableBytes']=min(result.get('minSystemAvailableBytes',2**64),mem().available)
        a,b,c,d=(wintypes.FILETIME() for _ in range(4))
        if not k.GetProcessTimes(handle,*[ctypes.byref(x) for x in (a,b,c,d)]): raise RuntimeError('CPU_TIME_READ')
        result['processCpuSeconds']=((c.dwHighDateTime<<32)+c.dwLowDateTime+(d.dwHighDateTime<<32)+d.dwLowDateTime)/1e7
    def watch():
        try:
            while not stop.wait(1):
                if proc.poll() is not None: break
                sample()
        except Exception: result['measurementFailure']=True
    try:
        result['hostTotalMemoryBytes']=mem().total;result['hostCpuCount']=os.cpu_count();result['diskFreeBeforeBytes']=shutil.disk_usage(root).free
        result['modelDownload']=download(MODEL_URL,root/'model.gguf',MODEL_HASH)
        result['backendDownload']=download(ARCHIVE_URL,root/'backend.zip',ARCHIVE_HASH)
        with zipfile.ZipFile(root/'backend.zip') as z:
            for n in z.namelist():
                p=Path(n)
                if p.is_absolute() or '..' in p.parts or ':' in n: raise RuntimeError('ARCHIVE_PATH')
            z.extractall(root/'backend')
        exes=list((root/'backend').rglob('llama-server.exe'))
        if len(exes)!=1 or fingerprint(exes[0])!=EXE_HASH: raise RuntimeError('EXECUTABLE_IDENTITY')
        exe=exes[0]
        if runtime_hash(exe.parent)!=TREE_HASH: raise RuntimeError('RUNTIME_TREE_IDENTITY')
        result['runtimeVerified']=True
        result['provisionedDiskBytes']=sum(p.stat().st_size for p in root.rglob('*') if p.is_file())
        with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        env={key:os.environ[key] for key in ('SystemRoot','WINDIR','TEMP','TMP','PATH') if key in os.environ}
        boot=time.monotonic()
        proc=subprocess.Popen([str(exe),'-m',str(root/'model.gguf'),'--host','127.0.0.1','--port',str(port),'-c','24576','-t','12','-ngl','0','--no-webui'],cwd=exe.parent,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        handle=k.OpenProcess(0x100|0x400|0x10,False,proc.pid)
        if not handle or not k.SetProcessAffinityMask(handle,3): raise RuntimeError('AFFINITY_FAILED')
        mask=ctypes.c_size_t();sysmask=ctypes.c_size_t()
        if not k.GetProcessAffinityMask(handle,ctypes.byref(mask),ctypes.byref(sysmask)) or mask.value!=3: raise RuntimeError('AFFINITY_NOT_VERIFIED')
        monitor=threading.Thread(target=watch,daemon=True);monitor.start()
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        while True:
            if proc.poll() is not None: raise RuntimeError('BACKEND_EXIT_BEFORE_READY')
            if time.monotonic()-boot>420: raise RuntimeError('HEALTH_420_SECONDS_EXCEEDED')
            try:
                with opener.open(f'http://127.0.0.1:{port}/health',timeout=2) as r:
                    if r.status==200: break
            except Exception: time.sleep(1)
        result['readySeconds']=time.monotonic()-boot
        prompt='Synthetic fixture only. Read the following invented records and return JSON containing their count and the sum of Value. No tools.\n'+'\n'.join(f'record {i}: Value = {i%10};' for i in range(1000))
        request=urllib.request.Request(f'http://127.0.0.1:{port}/v1/chat/completions',data=json.dumps({'messages':[{'role':'user','content':prompt}],'max_tokens':4096,'temperature':0,'stream':True,'stream_options':{'include_usage':True}}).encode(),headers={'Content-Type':'application/json'})
        generation=time.monotonic();first=None;last=None;chunks=0
        with opener.open(request,timeout=300) as response:
            for line in response:
                now=time.monotonic()
                if now-generation>1200: raise RuntimeError('PROBE_TIME_LIMIT_NOT_PRODUCT_FAILURE')
                if not line.startswith(b'data: '):continue
                raw=line[6:].strip()
                if raw==b'[DONE]':break
                value=json.loads(raw)
                if value.get('usage'):result['usage']={x:y for x,y in value['usage'].items() if isinstance(y,(int,float))}
                for choice in value.get('choices',[]):
                    if choice.get('delta',{}).get('content'):
                        if first is None:first=now;result['firstTokenSeconds']=now-generation
                        last=now;chunks+=1
        result['generationSeconds']=time.monotonic()-generation;result['contentChunks']=chunks
        if not chunks:raise RuntimeError('NO_COMPLETION_CONTENT')
        sample();result['status']='SYNTHETIC_INFERENCE_COMPLETED'
        result['cpuUtilizationOfTwoLogicalCpusPercent']=100*result.get('processCpuSeconds',0)/(2*(time.monotonic()-boot))
        result['workingSetExceedsEntirePrivateRam']=result['peakWorkingSetBytes']>8*1024**3
        result['headroomForPrivateOsAndBuildUnproven']=True
    except Exception as e:
        result['status']='PROBE_STOPPED';result['failureType']=type(e).__name__
        result['failureCode']=str(e) if type(e) is RuntimeError else 'TRANSPORT_OR_PLATFORM_FAILURE'
    finally:
        stop.set()
        if monitor:monitor.join(3)
        if proc and proc.poll() is None:
            proc.terminate()
            try:proc.wait(10)
            except subprocess.TimeoutExpired:proc.kill();proc.wait(10)
        if handle:k.CloseHandle(handle)
        result['totalSeconds']=time.monotonic()-started
        result['diskFreeAfterProbeBytes']=shutil.disk_usage(root).free
        shutil.rmtree(root);result['temporaryFilesRemoved']=not root.exists()
        print(json.dumps(result,sort_keys=True),flush=True)
    if result['status']!='SYNTHETIC_INFERENCE_COMPLETED' or result.get('measurementFailure'):raise SystemExit(1)
if __name__=='__main__':main()
