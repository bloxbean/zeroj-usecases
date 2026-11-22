#!/usr/bin/env python3
"""Discover independent Gradle builds and reject silently skipped DevKit tests."""

import json
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET


def tracked_files():
    return [Path(name) for name in subprocess.check_output(
        ["git", "ls-files", "-z"], text=True
    ).split("\0") if name]


def yaci_tests(project, files):
    return [path for path in files
            if path.is_relative_to(project)
            and "/src/test/java/" in path.as_posix()
            and path.name.endswith(("YaciE2ETest.java", "DevKitE2ETest.java"))]


def matrix():
    files = tracked_files()
    projects = sorted({path.parent for path in files
                       if path.name in ("settings.gradle", "settings.gradle.kts")
                       and path.parent != Path(".")})
    if not projects:
        raise SystemExit("No usecase builds found")
    print(json.dumps({"include": [
        {"path": project.as_posix(), "name": project.as_posix().replace("/", "-"),
         "yaci": bool(yaci_tests(project, files))}
        for project in projects
    ]}, separators=(",", ":")))


def check_e2e(project):
    sources = yaci_tests(project, tracked_files())
    if not sources:
        raise SystemExit(f"No Yaci E2E test sources found in {project}")
    for source in sources:
        class_name = source.as_posix().split("/src/test/java/", 1)[1][:-5].replace("/", ".")
        reports = list(project.glob(f"**/build/test-results/test/TEST-{class_name}.xml"))
        if len(reports) != 1:
            raise SystemExit(f"Expected one test report for {class_name}, found {len(reports)}")
        suite = ET.parse(reports[0]).getroot()
        tests = suite.findall("testcase")
        if not tests or any(case.find(tag) is not None
                            for case in tests for tag in ("skipped", "failure", "error")):
            raise SystemExit(f"Yaci E2E tests did not all run and pass: {class_name}")
        print(f"{class_name}: {len(tests)} test(s) ran and passed")


if __name__ == "__main__":
    if sys.argv[1:] == ["matrix"]:
        matrix()
    elif len(sys.argv) == 3 and sys.argv[1] == "check-e2e":
        check_e2e(Path(sys.argv[2]))
    else:
        raise SystemExit("Usage: usecase-ci.py matrix | check-e2e PROJECT")
