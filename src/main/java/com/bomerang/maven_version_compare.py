"""Maven 3.9.9 ComparableVersion adapter. Requires Java 17+; no network."""
import atexit,base64,os,queue,re,subprocess,threading
from functools import lru_cache,total_ordering
from pathlib import Path
_process=None
_messages=None
_lock=threading.Lock()
def close():
    global _process,_messages
    if _process is not None:
        if _process.poll() is None:
            _process.terminate()
            try:_process.wait(timeout=2)
            except subprocess.TimeoutExpired:_process.kill();_process.wait(timeout=2)
        for stream in (_process.stdin,_process.stdout):
            if stream:stream.close()
    _process=None;_messages=None
atexit.register(close)
def start():
    global _process,_messages
    if _process is not None and _process.poll() is None:return
    close();root=Path(__file__).resolve().parent
    classpath=os.pathsep.join([str(root/'bridge'),str(root/'lib'/'maven-artifact-3.9.9.jar')])
    try:_process=subprocess.Popen([os.getenv('BOMERANG_JAVA','java'),'-cp',classpath,'MavenComparisonServer'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,encoding='utf-8',bufsize=1)
    except OSError as exc:raise ValueError('Java 17+ unavailable: '+str(exc))
    messages=queue.Queue();_messages=messages;process=_process
    def read():
        try:
            for line in process.stdout:messages.put(line.strip())
        finally:messages.put('EOF')
    threading.Thread(target=read,daemon=True).start()
def validate(v):
    if not isinstance(v,str) or len(v)>512 or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+\-]*',v):raise ValueError('Invalid Maven version token')
    if v.lower() in {'unknown','null','none','latest','release'}:raise ValueError('Unresolved Maven version')
@lru_cache(maxsize=16384)
def compare(a,b):
    validate(a);validate(b)
    with _lock:
        start()
        data='\t'.join(base64.b64encode(x.encode()).decode() for x in (a,b))+'\n'
        try:
            _process.stdin.write(data);_process.stdin.flush();reply=_messages.get(timeout=10)
        except (OSError,queue.Empty) as exc:
            close();raise ValueError('Maven comparator unavailable: '+str(exc))
        if reply not in {'-1','0','1'}:
            close();raise ValueError('Maven comparator failed; verify Java 17+ and bridge/lib files')
        return int(reply)
@total_ordering
class MavenVersionKey:
    def __init__(self,value):validate(value);self.value=value
    def __eq__(self,other):
        if not isinstance(other,MavenVersionKey):return NotImplemented
        return compare(self.value,other.value)==0
    def __lt__(self,other):
        if not isinstance(other,MavenVersionKey):return NotImplemented
        return compare(self.value,other.value)<0
    # Equivalent spellings (1/1.0/1-ga) must have identical hashes.
    def __hash__(self):return 0
