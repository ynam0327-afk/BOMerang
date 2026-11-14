"""Compatibility entrypoint using the repository's canonical integrated parser."""
import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
_spec = importlib.util.spec_from_file_location("_bomerang_integrated_parser", ROOT / "integrated_parser.py")
_parser = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_parser)

analyze = _parser.analyze
main = _parser.main
if __name__ == "__main__":
    main()
