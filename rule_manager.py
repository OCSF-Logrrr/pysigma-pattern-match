from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch import LuceneBackend
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pathlib import Path
import threading

class RuleManager(FileSystemEventHandler):
    def __init__(self, root: Path):
        super().__init__()
        self.root = root
        self.backend = LuceneBackend()
        self.rules = {}  # path → (title, lucene, rule_obj)
        self.lock = threading.Lock()
        self._load_all()
        ob = Observer(); ob.schedule(self, str(root), recursive=True); ob.start()
        self.observer = ob

    def _compile(self, yml: str):
        coll = SigmaCollection.from_yaml(Path(yml).read_text())
        title = coll[0].title
        lucene = self.backend.convert(coll)[0]
        return title, lucene, coll[0]

    def _load_all(self):
        for p in self.root.rglob("*.yml"):
            if ".bak" in p.parts: continue
            try: self.rules[str(p)] = self._compile(str(p))
            except Exception as e: print(f"[RULE] load error {p}: {e}")

    def _reload(self, e):
        if e.is_directory or not e.src_path.endswith(".yml") or ".bak" in e.src_path:
            return
        try:
            self.rules[e.src_path] = self._compile(e.src_path)
            print(f"[RULE] reloaded {e.src_path}")
        except Exception as ex:
            print(f"[RULE] reload error {e.src_path}: {ex}")

    on_created = on_modified = on_moved = _reload
    def on_deleted(self, e):
        if e.src_path.endswith(".yml"):
            self.rules.pop(e.src_path, None)
            print(f"[RULE] removed {e.src_path}")

    def snapshot(self):
        with self.lock:
            return list(self.rules.values())