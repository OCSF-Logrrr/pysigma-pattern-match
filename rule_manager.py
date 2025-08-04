from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch import LuceneBackend
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pathlib import Path
import threading

class RuleManager(FileSystemEventHandler):
    def __init__(self, root: Path): 
        super().__init__()
        self.root = root    #rules 디렉토리의 최상위 폴더로 초기화
        self.backend = LuceneBackend()  #Lucene 쿼리 변환 객체
        self.rules = {}  #rules 디렉토리 안의 파일들의 경로를 key, rule의 제목, 변환된 lucene 쿼리, rule 객체를 담은 튜플을 value로 할 딕셔너리
        self.lock = threading.Lock()    #멀티 스레드 환경에서 하나의 스레드만 접근 가능하도록
        self._load_all()    #모든 rules 로드
        ob = Observer(); ob.schedule(self, str(root), recursive=True); ob.start() #rules 디렉토리 안에 변경이 발생하면 실시간 적용
        self.observer = ob

    def _compile(self, yml: str): #rules 파일들을 읽어서 SigmaCollection로 파싱
        coll = SigmaCollection.from_yaml(Path(yml).read_text())
        title = coll[0].title
        lucene = self.backend.convert(coll)[0]
        return title, lucene, coll[0]

    def _load_all(self): #모든 rules 파일을 딕셔너리에 저장
        for p in self.root.rglob("*.yml"):
            if ".bak" in p.parts: continue
            try: self.rules[str(p)] = self._compile(str(p))
            except Exception as e: print(f"[RULE] load error {p}: {e}")

    def _reload(self, e):
        if e.is_directory or not e.src_path.endswith(".yml") or ".bak" in e.src_path: #ruels 디렉토리 안에 변경사항이 없다면
            return
        try: #rules 디렉토리의 변경 사항이 생기면
            self.rules[e.src_path] = self._compile(e.src_path) #다시 디렉토리 내부를 읽어와 딕셔너리에 저장
            print(f"[RULE] reloaded {e.src_path}")
        except Exception as ex: #에러 디버깅
            print(f"[RULE] reload error {e.src_path}: {ex}")

    on_created = on_modified = on_moved = _reload
    def on_deleted(self, e): #삭제된 rules는 딕셔너리에서도 삭제
        if e.src_path.endswith(".yml"):
            self.rules.pop(e.src_path, None)
            print(f"[RULE] removed {e.src_path}")

    def snapshot(self):
        with self.lock:
            return list(self.rules.values()) #rules들의 딕셔너리를 반환