"""Script-building tests for jobs.py that need neither tmux nor SSH.

test_jobs.py skips entirely when tmux is absent, so without this file the
cd-rendering in build_job_script would have no coverage on a machine that
lacks tmux -- which is how defect C survived in ssh.py's twin. See
procedures/003-onboard-agent-account.md.
"""

import shlex

import pytest

from nervus.jobs import build_job_script


def _inner(cwd: str) -> str:
    """Recover the script build_job_script hands to `bash -c` inside tmux.

    build_job_script returns the *outer* script, which embeds the inner one
    shlex.quote()d as the last argument of the tmux line. shlex.split
    reverses that, so these tests assert against what bash will actually
    run rather than against escaping artefacts.
    """
    script, _handle = build_job_script("job-1", cwd, "echo hi")
    # Not splitlines(): the quoted inner script contains literal newlines, so
    # the tmux command spans several physical lines.
    return shlex.split(script[script.index("tmux ") :])[-1]


def test_job_script_does_not_quote_a_bare_tilde():
    # `cd '~'` looks for a literal directory named ~ and exits 97 having
    # run nothing. exec_bg defaults to cwd="~", so this is the default path.
    inner = _inner("~")
    assert "cd '~'" not in inner
    assert "cd ~ ||" in inner


def test_job_script_keeps_the_tilde_slash_unquoted():
    inner = _inner("~/work dir")
    assert "cd ~/'work dir'" in inner
    assert "cd '~/work dir'" not in inner


def test_job_script_passes_absolute_paths_through_shlex_quote():
    assert "cd /tmp ||" in _inner("/tmp")
    assert "cd '/var/tmp/a b'" in _inner("/var/tmp/a b")


def test_job_script_reports_an_unusable_cwd_rather_than_failing_silently():
    inner = _inner("/definitely/not/a/directory")
    assert "cannot change to working directory" in inner
    assert "exit 97" in inner


def test_job_script_names_its_tmux_session_after_the_job_id():
    # The kill switch in ADR-0003 depends on this: a job's tmux session name
    # is the only thing tying work on a shared agent account back to the
    # token that started it, via the audit log.
    script, handle = build_job_script("abc-123", "/tmp", "echo hi")
    assert handle.session_name == "nervus-abc-123"
    assert "nervus-abc-123" in script


@pytest.mark.parametrize("bad", [
    "x; rm -rf ~", "../../escape", "a b", "x$(id)", "back`tick`", "a/b", "", "a" * 65, "x\ny",
])
def test_a_job_id_outside_its_known_shape_is_refused(bad):
    # A client may supply job_id; it is interpolated into the target's shell paths, so
    # it must match a safe shape even though the caller already has exec (procedure 056,
    # C6).
    from nervus.jobs import build_job_script, JobError
    with pytest.raises(JobError):
        build_job_script(bad, "~", "echo hi")


def test_a_normal_job_id_is_accepted():
    from nervus.jobs import build_job_script
    _, handle = build_job_script("abc-123_DEF", "~", "echo hi")
    assert handle.job_id == "abc-123_DEF"
