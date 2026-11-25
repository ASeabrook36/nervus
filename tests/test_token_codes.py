"""The one-time codes that hand a token to its laptop (ADR-0032 question 5 a): a token issued with
one has no value until the code is used; the code works once, within 15 minutes; only hashes are
kept; a token handed over never gets another code, and one revoked hands over nothing."""

import threading

import pytest

from nervus.auth import Tokens
from nervus.database import Database, TokenRefused
from nervus.token_codes import CODE_SECONDS, CodeRefused, TokenCodes

T0 = 1_800_000_000.0


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "nervus.db")
    database.open()
    return database


@pytest.fixture
def codes(db):
    return TokenCodes(db)


def _issue(codes, token_id="laptop", kind="claude-code", client=None, now=T0, **more):
    return codes.issue(token_id, kind, client or kind, "laptop", ["node-a"], now=now, **more)


def test_a_token_issued_with_a_code_lets_no_one_in_until_its_code_is_used(db, codes):
    value, code = _issue(codes)
    [issued] = db.issued_tokens()
    assert (issued.token.id, issued.token.client, code.token_id, code.client) == ("laptop", "claude-code",
                                                                                 "laptop", "claude-code")
    # Kept under the hash of a value nobody has: no value lets it in, the code's own included.
    assert db.token(value) is None
    token_value, used = codes.hand_over(value, "192.0.2.7", now=T0 + 60)
    assert db.token(token_value).id == "laptop"
    assert (used.used_at, used.used_from) == (T0 + 60, "192.0.2.7")


def test_only_hashes_are_kept_never_the_code_or_the_token(db, codes, tmp_path):
    value, _ = _issue(codes)
    token_value, _ = codes.hand_over(value, "192.0.2.7", now=T0 + 1)
    kept = b"".join(p.read_bytes() for p in tmp_path.glob("nervus.db*"))
    assert value.encode() not in kept and token_value.encode() not in kept


def test_a_code_works_once(codes):
    value, _ = _issue(codes)
    codes.hand_over(value, "192.0.2.7", now=T0 + 1)
    with pytest.raises(CodeRefused) as refused:
        codes.hand_over(value, "192.0.2.8", now=T0 + 2)
    assert refused.value.reason == "used" and "revoke the token" in refused.value.message
    assert codes.find(value, now=T0 + 2) is None


def test_a_code_works_within_15_minutes_and_not_after(codes, db):
    value, code = _issue(codes)
    assert code.expires_at == T0 + CODE_SECONDS == T0 + 15 * 60
    assert codes.find(value, now=T0 + CODE_SECONDS - 1) is not None
    with pytest.raises(CodeRefused) as refused:
        codes.hand_over(value, "192.0.2.7", now=T0 + CODE_SECONDS)
    assert refused.value.reason == "expired"
    assert codes.find(value, now=T0 + CODE_SECONDS) is None
    # Nothing handed over: the token still lets no one in.
    with db.transaction(write=False) as raw:
        assert raw.execute("SELECT used_at FROM token_code").fetchall() == [(None,)]


def test_an_unknown_code_hands_over_nothing(codes):
    with pytest.raises(CodeRefused) as refused:
        codes.hand_over("not-a-code", "192.0.2.7")
    assert refused.value.reason == "unknown"


def test_a_token_revoked_before_its_code_is_used_hands_over_nothing_its_codes_gone_with_it(codes, db):
    value, _ = _issue(codes)
    db.revoke_token("laptop")
    with pytest.raises(CodeRefused) as refused:
        codes.hand_over(value, "192.0.2.7", now=T0 + 1)
    assert refused.value.reason == "unknown" and db.issued_tokens() == [] and codes.of_tokens() == {}


def test_a_code_outliving_its_token_never_hands_over_a_later_token_of_the_same_id(codes, db):
    # Step 5's review: line A of a revoked `laptop`, used after `laptop` is issued again and handed over by line
    # B, would take B's client's value away. Revoking takes A with it, and issuing again clears what was left.
    first, _ = _issue(codes)
    with db.transaction() as raw:  # as if a revoke had left its code behind
        raw.execute("DELETE FROM issued_token WHERE id = 'laptop'")
    second, _ = _issue(codes, now=T0 + 5)
    value, _ = codes.hand_over(second, "192.0.2.7", now=T0 + 6)
    with pytest.raises(CodeRefused) as refused:
        codes.hand_over(first, "192.0.2.66", now=T0 + 7)
    assert refused.value.reason == "unknown" and db.token(value).id == "laptop"


def test_a_token_is_handed_over_once_whatever_codes_it_has(codes, db):
    first, code = _issue(codes)
    with db.transaction() as raw:  # a second code beside the first, as no path here makes one
        raw.execute("INSERT INTO token_code (id, hash, token_id, client, made_at, expires_at) VALUES "
                    "('other', ?, 'laptop', 'claude-code', ?, ?)",
                    (__import__("hashlib").sha256(b"second").hexdigest(), T0, T0 + 900))
    value, _ = codes.hand_over(first, "192.0.2.7", now=T0 + 1)
    with pytest.raises(CodeRefused) as refused:
        codes.hand_over("second", "192.0.2.66", now=T0 + 2)
    assert refused.value.reason == "used" and db.token(value).id == "laptop"


def test_of_two_runs_at_once_one_is_handed_the_token(codes, db):
    value, _ = _issue(codes)
    got, refused = [], []

    def run():
        try:
            got.append(codes.hand_over(value, "192.0.2.7")[0])
        except CodeRefused as exc:
            refused.append(exc.reason)
    threads = [threading.Thread(target=run) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(got) == 1 and refused == ["used"] * 7 and db.token(got[0]).id == "laptop"


def test_a_token_whose_line_expired_unused_gets_a_new_one_and_only_then(codes, db):
    value, first = _issue(codes)
    with pytest.raises(ValueError, match="still works"):
        codes.again("laptop", now=T0 + 60)
    again, second = codes.again("laptop", now=T0 + CODE_SECONDS + 1)
    assert second.client == first.client and second.id != first.id and again != value
    token_value, _ = codes.hand_over(again, "192.0.2.7", now=T0 + CODE_SECONDS + 2)
    assert db.token(token_value).id == "laptop"
    with pytest.raises(ValueError, match="handed over already"):
        codes.again("laptop", now=T0 + 10 * CODE_SECONDS)


def test_a_token_issued_without_a_code_never_gets_one(codes, db):
    # One issued as before, its value shown, is in use somewhere: a code for it would hand another its value.
    value = db.issue_token("old-style", "codex", "p", ["node-a"])
    with pytest.raises(ValueError, match="not a token issued here to wait"):
        codes.again("old-style")
    assert db.token(value).id == "old-style"


def test_issuing_refuses_what_the_database_refuses_and_keeps_no_code(codes, db):
    with pytest.raises(TokenRefused):
        codes.issue("laptop", "codex", "codex", "p", [], now=T0)
    with pytest.raises(TokenRefused):
        codes.issue("codex-anywhere", "codex", "codex", "p", ["node-a"], taken={"codex-anywhere"}, now=T0)
    assert db.issued_tokens() == [] and codes.of_tokens() == {}


def test_a_client_not_on_the_list_is_refused(codes, db):
    with pytest.raises(ValueError):
        codes.issue("laptop", "cursor", "cursor", "p", ["node-a"], now=T0)
    assert db.issued_tokens() == []


def test_read_only_on_a_host_waits_as_the_rest_do(codes, db):
    value, _ = _issue(codes, readonly=["node-a"])
    token_value, _ = codes.hand_over(value, "192.0.2.7", now=T0 + 1)
    token = Tokens({}, db.token).get(token_value)
    assert token.readonly == frozenset({"node-a"})


def test_revoking_a_token_takes_its_codes_in_the_same_transaction(codes, db):
    _issue(codes)
    assert set(codes.of_tokens()) == {"laptop"}
    db.revoke_token("laptop")
    assert codes.of_tokens() == {}


def test_a_code_cancelled_expires_now(codes):
    value, code = _issue(codes)
    codes.cancel(code.id, now=T0 + 5)
    assert codes.find(value, now=T0 + 6) is None
