#!/usr/bin/env python3
"""Fails if CI would leave out a sim that a change could affect, as a sim left out passes unseen."""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "ci"))

import shards  # noqa: E402

# A sim folder in small: `shared` is imported by two sims, one of them through `helper`, `script.sh` is
# read by one, `runner` starts another as a program, `guided` reads a connector's guide from adapters/,
# `walker` follows a doc, `borrower` imports both of those for their helpers and reads neither guide,
# `connectors` isn't a sim and reads a guide for `connects`, and `alone` touches nothing.
FILES = {
    "shared.py": "",
    "helper.py": "import shared\n",
    "first.py": "from helper import thing\n",
    "second.py": "import shared\n",
    "reader.py": 'SCRIPT = HERE / "script.sh"\n',
    "runner.py": 'subprocess.run([sys.executable, str(HERE / "alone.py")])\n',
    "guided.py": 'GUIDES = ("skill/SKILL.md",)\n',
    "walker.py": 'DOC = ROOT / "docs" / "getting-started.md"\n',
    "borrower.py": "from walker import Person\nfrom guided import GUIDES\n",
    "connectors.py": 'SERVERS = ADAPTERS / "cursor" / "mcp.json"\n',
    "connects.py": "import connectors\n",
    "alone.py": '"""Says shared.py and script.sh in its docstring, and runs neither."""\n',
    "script.sh": "",
}
EVERY = ["first", "second", "reader", "runner", "guided", "walker", "borrower", "connects", "alone"]
SIMS = tuple(f"python3 sim/{name}.py" for name in EVERY)


class WhichSimsAChangeNeeds(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.kept = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.kept.cleanup)
        for name, source in FILES.items():
            (Path(cls.kept.name) / name).write_text(source)

    def needed(self, *changed: str) -> list[str]:
        return [shards.name_of(sim) for sim in shards.sims_for(list(changed), SIMS, Path(self.kept.name))]

    def test_product_code_and_ci_itself_run_every_sim(self) -> None:
        # Bug caught: a change to product code, or to what picks the sims, running only some of them.
        for path in ("packages/host/src/main.rs", "spec/vectors/requests.json", "deploy/install.sh", "adapters/mcp/src/a.ts",
                     "adapters/http/watch.sh", "make/core.mk", "Makefile", "tools/ci/shards.py",
                     ".github/workflows/check.yml", "sim/load/load.py"):
            self.assertEqual(self.needed(path), EVERY, path)

    def test_a_sim_file_runs_every_sim_that_could_run_it(self) -> None:
        # Bug caught: a change to a file sims share running none of them, or only the ones importing it directly.
        self.assertEqual(self.needed("sim/shared.py"), ["first", "second"])
        self.assertEqual(self.needed("sim/helper.py"), ["first"])
        self.assertEqual(self.needed("sim/script.sh"), ["reader"])
        self.assertEqual(self.needed("sim/alone.py"), ["runner", "alone"])
        self.assertEqual(self.needed("sim/first.py", "README.md"), ["first"])

    def test_what_a_runtime_reads_to_connect_runs_the_sims_that_read_it(self) -> None:
        # Bug caught: a change to a connector's guide, which no program here runs, running every sim, or
        # every sim importing the one that reads it for its helpers, or none though a helper reads it.
        self.assertEqual(self.needed("adapters/skill/SKILL.md"), ["guided"])
        self.assertEqual(self.needed("adapters/claude-code/skills/splint/SKILL.md"), ["guided"])
        self.assertEqual(self.needed("adapters/cursor/mcp.json"), ["connects"])
        self.assertEqual(self.needed("adapters/claude-code/.claude-plugin/plugin.json"), [])

    def test_a_doc_runs_only_the_sims_that_read_it(self) -> None:
        # Bug caught: a change to a doc running every sim, or every sim importing the one that follows it
        # for its helpers. The sim that follows it still runs, as it runs the doc's commands as written.
        self.assertEqual(self.needed("docs/getting-started.md"), ["walker"])
        self.assertEqual(self.needed("docs/getting-started.md", "adapters/skill/SKILL.md"), ["guided", "walker"])
        self.assertEqual(self.needed("sim/walker.py"), ["walker", "borrower"])
        self.assertEqual(self.needed("sim/guided.py"), ["guided", "borrower"])

    def test_product_code_beside_a_sim_still_runs_every_sim(self) -> None:
        # Bug caught: one sim file in a change narrowing what the product code in it needs.
        self.assertEqual(len(self.needed("sim/first.py", "packages/signet/src/main.rs")), len(SIMS))

    def test_what_no_sim_runs_needs_none(self) -> None:
        self.assertEqual(self.needed("README.md", "docs/how-it-works.md", ".github/workflows/release.yml"), [])

    def test_as_few_shards_as_hold_the_sims(self) -> None:
        # Bug caught: one changed sim spread over nine machines, or every sim given to one.
        every = shards.classify(shards.make_commands()).sims
        self.assertEqual(shards.count_for(every[:1], 2), 1)
        self.assertGreater(shards.count_for(every, 1), shards.count_for(every, 4))
        self.assertLessEqual(shards.count_for(every, 1), shards.SHARD_COUNT)


if __name__ == "__main__":
    unittest.main()
