import json
import tempfile
import unittest
from pathlib import Path

try:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
except ImportError:  # app dependencies are not installed in every environment
    FastAPI = None


@unittest.skipIf(FastAPI is None, "fastapi not installed")
class ExperimentsApiTests(unittest.TestCase):
    def setUp(self):
        import app.experiments as ex
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        (root / "labs/ch01/activity_01_demo").mkdir(parents=True)
        (root / "labs/ch01/README.md").write_text("# Chapter 1: Demo\n")
        (root / "labs/ch01/exercise.py").write_text("def main(run): pass\n")
        (root / "labs/ch01/activity_01_demo/run.py").write_text("print('hi')\n")
        run_dir = root / "results/ch01/20260101T000000000000Z"
        run_dir.mkdir(parents=True)
        (run_dir / "result.json").write_text(json.dumps({"status": "passed", "mode": "quick", "events": [{"name": "x"}]}))
        (root / "results/ch01/launcher-20260101T000000Z.log").write_text("\x1b[1mok\x1b[0m\n")
        (root / "secret.txt").write_text("nope")
        self.ex, self.old = ex, (ex.LABS, ex.RESULTS)
        ex.LABS, ex.RESULTS = (root / "labs").resolve(), (root / "results").resolve()
        app = FastAPI(); app.include_router(ex.router)
        self.client = TestClient(app)

    def tearDown(self):
        self.ex.LABS, self.ex.RESULTS = self.old
        self.tmp.cleanup()

    def test_list_and_detail(self):
        chapters = self.client.get("/api/experiments").json()
        self.assertEqual(len(chapters), 18)
        self.assertEqual(chapters[0]["title"], "Chapter 1: Demo")
        self.assertEqual(chapters[0]["latest"]["status"], "passed")
        detail = self.client.get("/api/experiments/ch01").json()
        self.assertEqual(detail["activities"][0]["files"], ["activity_01_demo/run.py"])
        self.assertEqual(detail["logs"], ["launcher-20260101T000000Z.log"])

    def test_source_run_and_log(self):
        self.assertIn("print", self.client.get("/api/experiments/ch01/source", params={"path": "activity_01_demo/run.py"}).json()["content"])
        self.assertEqual(self.client.get("/api/experiments/ch01/runs/20260101T000000000000Z").json()["result"]["status"], "passed")
        self.assertEqual(self.client.get("/api/experiments/ch01/logs/launcher-20260101T000000Z.log").json()["content"], "ok\n")

    def test_rejects_paths_outside_chapter(self):
        for path in ("../../secret.txt", "../ch02/README.md", "/etc/passwd"):
            self.assertEqual(self.client.get("/api/experiments/ch01/source", params={"path": path}).status_code, 404, path)
        self.assertEqual(self.client.get("/api/experiments/ch19").status_code, 404)
        self.assertEqual(self.client.get("/api/experiments/ch01/runs/..%2F..").status_code, 404)


if __name__ == "__main__":
    unittest.main()
