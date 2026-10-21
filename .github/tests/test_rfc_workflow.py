"""Offline fixtures exercise the Python gate embedded in the reusable workflow.

Only the existing checklist CLI is compiled. Race/fuzz command execution is
recorded, not run; their actual proof remains in the reusable GitHub job.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/rfc-verification.yml'
SOURCE = textwrap.dedent(WORKFLOW.read_text().split('# BEGIN RFC PROOF\n', 1)[1]
                         .split('          # END RFC PROOF', 1)[0])
PROOF = {'__name__': 'rfc_proof_fixture'}
exec(compile(SOURCE, str(WORKFLOW), 'exec'), PROOF)


def configuration(packages=None, dirs=None, targets=None):
    return {
        'RFC_PACKAGES': json.dumps(['./...'] if packages is None else packages),
        'RFC_CHECKLIST_DIRS': json.dumps(['.'] if dirs is None else dirs),
        'RFC_FUZZ_TARGETS': json.dumps(
            [{'package': '.', 'target': 'FuzzParseRecord'}] if targets is None else targets),
    }


class GateFixtures(unittest.TestCase):
    def test_readme_coverage_badge_matches_enforced_minimum(self):
        readme = (ROOT / 'README.md').read_text()
        self.assertIn(
            '[![Coverage gate: >=95%]'
            '(https://img.shields.io/badge/coverage%20gate-%3E%3D95%25-brightgreen)]'
            '(COVERAGE.md)', readme)
        # Exercise the actual workflow helper, so a changed gate cannot leave
        # the documented minimum stale. No coverage or race suite is run here.
        with contextlib.redirect_stdout(io.StringIO()):
            PROOF['coverage_total']('total: (statements) 95.0%\n')
        with self.assertRaises(ValueError):
            PROOF['coverage_total']('total: (statements) 94.99%\n')

    def test_coverage_accepts_boundary_and_higher(self):
        for total in ['95', '95.0', '95.01', '99.9', '100.0']:
            with self.subTest(total=total), contextlib.redirect_stdout(io.StringIO()):
                PROOF['coverage_total']('file.go:1: Test 50.0%\ntotal: (statements) ' + total + '%\n')

    def test_coverage_refuses_bad_or_missing_totals(self):
        for report in ['', 'file.go:1: Test 100.0%', 'total: (statements) 94.99%',
                       'total: (statements) 0%', 'total: (statements) 100.1%',
                       'total: (statements) NaN%', 'total: (statements) inf%',
                       'total: (statements) -95%', 'total: (statements) 95junk%',
                       'total: (statements) 95', 'total: 95%',
                       'total: (statements) 100%\ntotal: (statements) 100%']:
            with self.subTest(report=report), self.assertRaises(ValueError):
                PROOF['coverage_total'](report)

    def test_local_package_selection(self):
        env = configuration(packages=['.', './parser', './internal/parser/...'],
                            dirs=['.', './parser'],
                            targets=[{'package': './parser', 'target': 'FuzzParse_Record'}])
        packages, dirs, targets = PROOF['configuration'](env)
        self.assertEqual(packages, ['.', './parser', './internal/parser/...'])
        self.assertEqual(dirs, ['.', './parser'])
        self.assertEqual(targets[0]['package'], './parser')

    def test_package_argument_refusals_before_execution(self):
        for bad in ['', '-exec=bad', './x;touch pwned', '$(touch pwned)', './x\ny',
                    '../other', '/tmp/x', './a/../b', './a/./b', './a//b',
                    'github.com/other/pkg', './a/*', 1, None]:
            for key in ['packages', 'dirs']:
                with self.subTest(bad=bad, key=key), patch.dict(PROOF, go=unittest.mock.Mock()):
                    with self.assertRaises(ValueError):
                        PROOF['verify'](configuration(**{key: [bad]}))
                    PROOF['go'].assert_not_called()
        with self.assertRaises(ValueError):
            PROOF['configuration'](configuration(dirs=['./...']))

    def test_json_shape_refusals(self):
        for field in configuration():
            for raw in ['', 'not json', '[]', '{}', 'null', 'true', '"."', '42']:
                env = configuration()
                env[field] = raw
                with self.subTest(field=field, raw=raw), self.assertRaises(ValueError):
                    PROOF['configuration'](env)

    def test_fuzz_argument_refusals(self):
        for item in [{}, {'package': '.'}, {'package': '.', 'target': 'FuzzA', 'command': 'sh'},
                     {'package': '../other', 'target': 'FuzzA'},
                     {'package': './...', 'target': 'FuzzA'},
                     *[{'package': '.', 'target': name} for name in
                       ['FuzzA|FuzzB', 'Fuzz.*', '^FuzzA$', 'FuzzA;id', '-run=.', 'TestA', 'Fuzz', '', 1]],
                     'FuzzA', None]:
            with self.subTest(item=item), self.assertRaises(ValueError):
                PROOF['configuration'](configuration(targets=[item]))
        item = {'package': '.', 'target': 'FuzzA'}
        with self.assertRaises(ValueError):
            PROOF['configuration'](configuration(targets=[item, item]))

    def test_go_invocation_uses_arguments_and_propagates_failure(self):
        result = subprocess.CompletedProcess([], 0, 'output')
        with patch.object(subprocess, 'run', return_value=result) as run:
            self.assertEqual(PROOF['go']('test', '-list=^Fuzz', '.', capture=True), 'output')
            run.assert_called_once_with(['go', 'test', '-list=^Fuzz', '.'], check=True,
                                        text=True, stdout=subprocess.PIPE)
        with patch.object(subprocess, 'run', side_effect=subprocess.CalledProcessError(1, ['go'])):
            with self.assertRaises(subprocess.CalledProcessError):
                PROOF['go']('test', '.')

    def test_exact_fuzz_selection_and_retained_race_commands(self):
        calls = []

        def go(*args, **kwargs):
            calls.append((args, kwargs))
            if args[0:2] == ('test', '-list=^Fuzz'):
                return 'FuzzParseRecord\nFuzzParseRecordExtra\n'
            if args[:2] == ('tool', 'cover'):
                return 'total: (statements) 95.0%\n'

        with patch.dict(PROOF, go=go), contextlib.redirect_stdout(io.StringIO()):
            PROOF['verify'](configuration())
        self.assertEqual(calls, [
            (('test', '-list=^Fuzz', '.'), {'capture': True}),
            (('test', '-race', '-count=1', '-covermode=atomic', '-coverprofile=coverage.out', './...'), {}),
            (('tool', 'cover', '-func=coverage.out'), {'capture': True}),
            (('run', './internal/checklist', '-file', 'CHECKLIST.md', '.'), {}),
            (('test', '-run=^$', '-fuzz=^FuzzParseRecord$', '-fuzztime=30s', '.'), {}),
        ])

    def test_absent_fuzz_target_refuses_prefix_match(self):
        go = unittest.mock.Mock(return_value='FuzzParseRecordExtra\n')
        with patch.dict(PROOF, go=go), self.assertRaisesRegex(ValueError, 'fuzz target not found'):
            PROOF['verify'](configuration())
        self.assertEqual(go.call_count, 1)

    def test_coverage_failure_prevents_checklist_and_fuzz(self):
        go = unittest.mock.Mock(side_effect=['FuzzParseRecord\n', None, 'total: (statements) 94.9%'])
        with patch.dict(PROOF, go=go), self.assertRaises(ValueError):
            PROOF['verify'](configuration())
        self.assertEqual(go.call_count, 3)

    def test_required_verdict_fails_closed(self):
        caller = (ROOT / '.github/workflows/ci.yml').read_text()
        command = next(line.strip().removeprefix('run: ') for line in caller.splitlines()
                       if line.strip().startswith('run: test '))
        for rfc in ['success', 'failure', 'cancelled', 'skipped', '']:
            for fixtures in ['success', 'failure', 'cancelled', 'skipped', '']:
                result = subprocess.run(['sh', '-c', command], env={
                    **os.environ, 'RFC_RESULT': rfc, 'FIXTURE_RESULT': fixtures,
                }, check=False)
                with self.subTest(rfc=rfc, fixtures=fixtures):
                    self.assertEqual(result.returncode == 0, rfc == fixtures == 'success')


class ChecklistFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix='rfc-workflow-checklist-')
        cls.binary = str(Path(cls.scratch.name) / 'checklist')
        subprocess.run(['nice', '-n', '10', 'go', 'build', '-p', '1', '-o', cls.binary,
                        './internal/checklist'], cwd=ROOT, check=True,
                       env={**os.environ, 'GOMAXPROCS': '1'})

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    def test_shared_checklist_invocation_on_real_cli_fixtures(self):
        header = '| ID | Section | Level | Requirement | Tests |\n|----|----|----|----|----|\n'
        row = '| RFC-01 | 1 | MUST | Do it. | TestProof |\n'
        for name, table, annotation, success in [
            ('valid', header + row, 'RFC-01', True),
            ('missing item', header, 'RFC-01', False),
            ('unknown ID', header + row, 'RFC-99', False),
            ('missing mapping', header + row.replace('TestProof', ''), 'RFC-01', False),
        ]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                path = Path(directory)
                (path / 'CHECKLIST.md').write_text(table)
                (path / 'proof_test.go').write_text(
                    'package fixture\n// checklist: ' + annotation + '\nfunc TestProof(t *testing.T) {}\n')
                calls = []

                def go(*args, **kwargs):
                    calls.append(args)
                    if args[:2] == ('test', '-list=^Fuzz'):
                        return 'FuzzParseRecord\n'
                    if args[:2] == ('tool', 'cover'):
                        return 'total: (statements) 100.0%\n'
                    if args[0] == 'run':
                        # Exercise exactly the shared gate's CLI arguments.
                        return subprocess.run([self.binary, *args[2:]], cwd=path, check=True,
                                              text=True, stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE).stdout

                with patch.dict(PROOF, go=go), contextlib.redirect_stdout(io.StringIO()):
                    if success:
                        PROOF['verify'](configuration())
                        self.assertEqual(calls[-1][2], '-fuzz=^FuzzParseRecord$')
                    else:
                        with self.assertRaises(subprocess.CalledProcessError) as caught:
                            PROOF['verify'](configuration())
                        self.assertIn('problem(s)', caught.exception.stderr)
                        self.assertEqual(calls[-1][0], 'run')


if __name__ == '__main__':
    unittest.main()
