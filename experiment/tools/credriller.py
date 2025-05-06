import io
import logging
import os
import subprocess
import sys
from typing import Set, Tuple, AnyStr, Generator

from credsweeper import CredSweeper
from credsweeper.common.constants import DiffRowType, Severity
from credsweeper.file_handler.patches_provider import PatchesProvider
from credsweeper.utils import Util

logging.basicConfig(level="INFO", format="%(asctime)s | %(levelname)s | %(filename)s:%(lineno)s | %(message)s")
logger = logging.getLogger(__file__)


class GitRepo:

    def __init__(self, git_repo, diffs: Set[str]):
        self._ancestors_descendants: Set[Tuple[str, str]] = set()
        self.nproc = os.cpu_count()
        self.repo = git_repo
        self.diffs: Set[str] = diffs or set()
        self._descendants: Set[str] = set()
        self.scanner = CredSweeper(color=True, pool_count=16, severity=Severity.LOW, subtext=True, thrifty=True)

    def git(self, args) -> Tuple[bytes, bytes]:
        with subprocess.Popen(args=["git", *args], cwd=self.repo, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE) as proc:
            _stdout, _stderr = proc.communicate()

        def transform(x: AnyStr) -> bytes:
            if isinstance(x, bytes):
                return x
            elif isinstance(x, str):
                return x.encode(encoding="utf_8")
            else:
                raise ValueError(f"Unknown type: {type(x)}")

        return transform(_stdout), transform(_stderr)

    def get_ancestors_descendants(self, commit: str) -> Set[Tuple[str, str]]:
        ancestors_descendants = []
        _out, _err = self.git(["log", "--pretty=%P", "-n", "1", commit])
        for ancestor in _out.decode().split(' '):
            ancestor = ancestor.strip()
            if ancestor and 40 == len(ancestor):
                ancestors_descendants.append((ancestor, commit))
        return set(ancestors_descendants)

    def walk(self, commit) -> Generator[Tuple[str, str], None, None]:
        """
        Yields tuple: (ancestor, descendant)
        """
        descendants_ancestors = self.get_ancestors_descendants(commit)
        self._ancestors_descendants.update(descendants_ancestors)
        while self._ancestors_descendants:
            if ancestor_descendant := self._ancestors_descendants.pop():
                if ancestor_descendant[0] in self._descendants:
                    continue
                self._descendants.add(ancestor_descendant[0])
                self._ancestors_descendants.update(self.get_ancestors_descendants(ancestor_descendant[1]))
                yield ancestor_descendant

    def drill(self, commit: str):
        for ancestor, descendant in self.walk(commit):
            diff_name = f"{ancestor}_{descendant}"
            if diff_name in self.diffs:
                logger.info(f"skip {diff_name}")
                continue
            logger.info(self.git(["log", "-n", "1", descendant])[0].decode())
            _out, _err = self.git(["diff", ancestor, descendant])
            data = io.BytesIO(_out)
            content_provider = PatchesProvider([data], change_type=DiffRowType.ADDED)
            self.scanner.credential_manager.clear_credentials()
            self.scanner.run(content_provider=content_provider)
            if credentials := self.scanner.credential_manager.get_credentials():
                Util.json_dump([x.to_json(hashed=False, subtext=True) for x in credentials], f"{diff_name}.added.json")
            self.diffs.add(diff_name)
            with open(".diffs", 'a') as f:
                f.write(f"\n{diff_name}")
            logger.info(f"done:{diff_name}")
        else:
            logger.info(f"finish:{commit}")


def main() -> int:
    if 1 < len(sys.argv):
        os.chdir(sys.argv[1])
    logger.info(os.getcwd())
    if os.path.exists(".diffs"):
        with open(".diffs", 'r') as f:
            diffs = set(f.read().split('\n'))
        logger.info(f"read {len(diffs)} diffs")
    else:
        logger.info(".diffs does not exist")
        diffs = set()
    repo = GitRepo(os.getcwd(), diffs)
    _out, _err = repo.git(["for-each-ref", "--format=%(objectname)"])
    if not _out:
        logger.error(_err.decode())
        return 1
    for commit in _out.decode().splitlines():
        commit = commit.strip()
        logger.info(f">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>{commit}")
        logger.info(repo.git(["log", "-n", "1", commit])[0].decode())
        repo.drill(commit)
        logger.info(f"<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<{commit}")
    return 0


# PYTHONPATH=. python experiment/tools/credriller.py <a_git_repo_path> 2>&1 | tee creddriller.log
if __name__ == "__main__":
    sys.exit(main())
