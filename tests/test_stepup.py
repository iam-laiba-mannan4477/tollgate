"""Phase 3c: step-up approval. A stolen logged-in approver session alone must not be
able to approve a payment. Mock mode, fake TOTP secret, injected clocks, no network."""
import json
import secrets
import threading

import pytest
from hypothesis import given, settings, strategies as st

from tollgate.agent import scenarios
from tollgate.agent.loop import Agent
from tollgate.agent.model import CustomerMessage, ScriptedModel, ToolCall
from tollgate.agent.tools import Directory
from tollgate.approval.accounts import AccountError, ApproverAccount, Role, Session
from tollgate.approval.policy import ApprovalPolicy
from tollgate.approval.service import ApprovalItem, Grant, Status
from tollgate.approval.totp import (MOCK_TOTP_SECRET_B32, TotpChecker, code_at,
                                    decode_secret, hotp)
from tollgate.config import Mode
from tollgate.gate.audit import AuditLog, verify
from tollgate.gate.models import Decision, Request, Verdict
from tollgate.gate.stamps import StampError
from tests.stepup_support import OWNER, PASSWORD, SECRET, TestApprover
from tests.test_agent import World

BIG = 1_500_000          # $15,000: over the $10,000 delay tier
MID = 150_000            # $1,500: over $1,000, needs the factor, no delay if known


@pytest.fixture
def world(tmp_path):
    return World(tmp_path)


_seq = iter(range(1, 10_000))


def propose(world, amount, recipient):
    """The agent proposes one payment; returns the proposal id (HOLD expected)."""
    n = next(_seq)
    model = ScriptedModel({f"s{n}": [ToolCall("propose_payment", {
        "amount_cents": amount, "recipient": recipient, "reason": f"invoice {n}"})]})
    agent = Agent(model, world.drafter, Directory(), world.audit, clock=world.clock)
    [out] = agent.handle(CustomerMessage(f"m{n}", "ops", "pay please", f"s{n}"))
    assert out.verdict is Verdict.HOLD, out.reason
    return out.proposal_id


def unchanged(world):
    return world.backend.balance_cents == world.seed_balance


def bad_code(a):
    good = a.code()
    return f"{(int(good) + 1) % 1_000_000:06d}"


# ---- TOTP itself (RFC 6238 test vectors, SHA-1, 8 digits) ------------------------------
@pytest.mark.parametrize("t,expected", [(59, "94287082"), (1_111_111_109, "07081804"),
                                        (1_111_111_111, "14050471"),
                                        (1_234_567_890, "89005924"),
                                        (2_000_000_000, "69279037"),
                                        (20_000_000_000, "65353130")])
def test_totp_matches_rfc6238_vectors(t, expected):
    assert code_at(b"12345678901234567890", t, digits=8) == expected


def test_each_code_works_once_and_old_steps_are_refused():
    checker, now = TotpChecker(SECRET), 1_700_000_000.0
    code = code_at(SECRET, now)
    assert checker.check(code, now) is True
    assert checker.check(code, now) is False                       # replay
    assert checker.check(code_at(SECRET, now - 30), now) is False  # older step after newer
    assert checker.check(code_at(SECRET, now + 30), now + 30) is True


@pytest.mark.parametrize("code", [None, "", "12345", "1234567", "abcdef", "１２３４５６", 123456])
def test_malformed_codes_fail_closed(code):
    assert TotpChecker(SECRET).check(code, 1_700_000_000.0) is False


def test_expired_code_is_refused():
    now = 1_700_000_000.0
    assert TotpChecker(SECRET).check(code_at(SECRET, now - 90), now) is False


@settings(max_examples=200, deadline=None)
@given(st.text(alphabet="0123456789", min_size=6, max_size=6))
def test_random_codes_pass_only_if_they_are_the_right_one(code):
    now = 1_700_000_000.0
    valid = {hotp(SECRET, (int(now) // 30) + d) for d in (-1, 0, 1)}
    assert TotpChecker(SECRET).check(code, now) is (code in valid)


# ---- identity: a stolen session is not enough; the agent can never approve --------------
@pytest.mark.parametrize("code", [None, "", "000000"])
def test_stolen_session_without_second_factor_cannot_approve(world, code):
    pid = propose(world, BIG, "acct_evil")
    res = world.reviewer.approve(pid, world.approver.session, code)
    assert res.verdict is Verdict.BLOCK and not res.executed
    assert "second factor failed" in res.reason
    assert [p.id for p in world.reviewer.pending()] == [pid]       # still held for a person
    assert world.approver.service.waiting() == [] and unchanged(world)


def test_agent_role_is_rejected_at_the_approval_step(world):
    pid = propose(world, MID, "cust_1")
    a = world.approver
    for session in (Session(a.session.token, "alice", Role.AGENT),    # right token, agent role
                    Session(secrets.token_urlsafe(32), "alice", Role.APPROVER),   # forged
                    Session(a.session.token, "agent", Role.APPROVER)):
        res = world.reviewer.approve(pid, session, a.code())
        assert res.verdict is Verdict.BLOCK and "not an approver session" in res.reason
    assert unchanged(world)


@pytest.mark.parametrize("name", ["agent", "AI", " bot ", "assistant", ""])
def test_agent_names_cannot_enroll_as_approver(name):
    with pytest.raises(AccountError):
        ApproverAccount(Mode.MOCK, iterations=1_000).enroll(name, PASSWORD, OWNER)


def test_wrong_password_gives_no_session():
    acct = ApproverAccount(Mode.MOCK, iterations=1_000)
    acct.enroll("alice", PASSWORD, OWNER, MOCK_TOTP_SECRET_B32)
    with pytest.raises(AccountError):
        acct.login("alice", PASSWORD + "x")
    with pytest.raises(AccountError):
        acct.login("mallory", PASSWORD)


def test_wrong_replayed_and_expired_codes_are_rejected_in_the_flow(world):
    a = world.approver
    pid = propose(world, MID, "cust_1")
    used = a.code()
    assert world.reviewer.approve(pid, a.session, used).executed            # good once
    pid2 = propose(world, MID + 1, "acct_supplier_1")
    replay = world.reviewer.approve(pid2, a.session, used)
    assert replay.verdict is Verdict.BLOCK and "second factor failed" in replay.reason
    expired = code_at(SECRET, a.wall.t - 120)
    assert "second factor failed" in world.reviewer.approve(pid2, a.session, expired).reason
    assert world.reviewer.approve(pid2, a.session, a.code()).executed      # fresh code works


def test_mock_secret_is_refused_outside_mock_mode():
    with pytest.raises(AccountError):
        ApproverAccount(Mode.SANDBOX, iterations=1_000).enroll(
            "alice", PASSWORD, OWNER, MOCK_TOTP_SECRET_B32)


def test_setup_cannot_be_rerun_once_enrolled():
    acct = ApproverAccount(Mode.MOCK, iterations=1_000)
    acct.enroll("alice", PASSWORD, OWNER, MOCK_TOTP_SECRET_B32)
    with pytest.raises(AccountError):
        acct.enroll("alice", "attacker-new-password", "evil@example.test")
    with pytest.raises(AccountError):
        acct.enroll("mallory", "attacker-new-password", "evil@example.test")


# ---- tiers: small sends at once, big waits -----------------------------------------------
def test_below_the_delay_tier_sends_at_once_after_the_factor(world):
    a = world.approver
    pid = propose(world, MID, "cust_1")                  # known recipient, $1,500
    res = world.reviewer.approve(pid, a.session, a.code())
    assert res.executed and world.backend.balance_cents == world.seed_balance + MID


def test_new_recipient_over_1000_always_waits(world):
    a = world.approver
    pid = propose(world, MID, "acct_new")                # $1,500, but a new recipient
    res = world.reviewer.approve(pid, a.session, a.code())
    assert res.verdict is Verdict.HOLD and not res.executed and "cooling-off" in res.reason
    assert unchanged(world)


def test_new_recipient_under_1000_does_not_wait(world):
    a = world.approver
    pid = propose(world, 50_000, "acct_new")
    assert world.reviewer.approve(pid, a.session, a.code()).executed


def test_big_payment_waits_then_releases_after_the_delay(world):
    a = world.approver
    pid = propose(world, BIG, "acct_supplier_1")
    res = world.reviewer.approve(pid, a.session, a.code())
    assert res.verdict is Verdict.HOLD and "cooling-off" in res.reason
    world.clock.t += 899
    assert world.reviewer.release_due() == [] and unchanged(world)
    world.clock.t += 1
    [(item_id, out)] = world.reviewer.release_due()
    assert item_id == pid and out.executed
    assert world.backend.balance_cents == world.seed_balance + BIG
    assert world.reviewer.release_due() == []           # released once only


def test_no_usable_stamp_exists_before_the_delay_ends(world):
    a = world.approver
    pid = propose(world, BIG, "acct_supplier_1")
    world.reviewer.approve(pid, a.session, a.code())
    req = Request(id=pid, type="pay", amount_cents=BIG, recipient="acct_supplier_1",
                  via_agent=True, created_at=0.0)
    assert world.executor.execute(req).verdict is Verdict.HOLD             # no stamp
    forged = Grant(secrets.token_urlsafe(32), pid, BIG, "acct_supplier_1", "alice")
    with pytest.raises(StampError):
        world.executor.approve(req, forged)
    with pytest.raises(StampError):
        world.executor.approve(req, "alice")                               # a name is not enough
    assert unchanged(world)


def test_owner_cancel_during_the_delay_kills_the_approval(world):
    a = world.approver
    pid = propose(world, BIG, "acct_supplier_1")
    world.reviewer.approve(pid, a.session, a.code())
    assert world.reviewer.cancel(pid, "owner") is True
    assert world.reviewer.cancel(pid, "owner") is False
    world.clock.t += 10_000
    assert world.reviewer.release_due() == [] and unchanged(world)
    kinds = [n["kind"] for n in a.service._outbox.read()]
    assert kinds.count("approval_waiting") == 1 and kinds.count("approval_cancelled") == 1


def test_the_agent_name_cannot_cancel_or_reject(world):
    a = world.approver
    pid = propose(world, BIG, "acct_supplier_1")
    world.reviewer.approve(pid, a.session, a.code())
    with pytest.raises(AccountError):
        world.reviewer.cancel(pid, "agent")


# ---- the rolling daily cap -------------------------------------------------------------
def test_daily_cap_exceeded_is_block(world):
    a = world.approver
    first = propose(world, 1_200_000, "acct_supplier_1")
    second = propose(world, 1_200_000, "cust_1")
    third = propose(world, 200_000, "acct_x")
    assert world.reviewer.approve(first, a.session, a.code()).verdict is Verdict.HOLD
    assert world.reviewer.approve(second, a.session, a.code()).verdict is Verdict.HOLD
    res = world.reviewer.approve(third, a.session, a.code())
    assert res.verdict is Verdict.BLOCK and "daily approval cap" in res.reason
    assert third not in [p.id for p in world.reviewer.pending()]           # final, dropped


def test_waiting_approvals_together_cannot_exceed_the_cap(world):
    a = world.approver
    ids = [propose(world, 900_000, f"acct_n{i}") for i in range(3)]       # 3 x $9,000, new
    results = [world.reviewer.approve(i, a.session, a.code()) for i in ids]
    assert [r.verdict for r in results] == [Verdict.HOLD, Verdict.HOLD, Verdict.BLOCK]
    assert "daily approval cap" in results[2].reason
    assert len(a.service.waiting()) == 2                    # none released yet, still counted
    assert a.service.committed_cents() <= a.service.policy.daily_cap_cents


def test_cap_window_rolls_after_24_hours(world):
    a = world.approver
    world.reviewer.approve(propose(world, 2_000_000, "acct_supplier_1"), a.session, a.code())
    world.clock.t += 900
    world.reviewer.release_due()
    late = propose(world, 900_000, "cust_1")
    assert world.reviewer.approve(late, a.session, a.code()).verdict is Verdict.BLOCK
    world.clock.t += 86_400
    again = propose(world, 900_000, "cust_1")             # known, under $10,000: no delay
    assert world.reviewer.approve(again, a.session, a.code()).executed


@settings(max_examples=40, deadline=None)
@given(st.lists(st.integers(min_value=1, max_value=2_000_000), min_size=1, max_size=12))
def test_property_committed_value_never_exceeds_the_cap(tmp_path_factory, amounts):
    clock = type("C", (), {"t": 1000.0, "__call__": lambda self: self.t})()
    rig = TestApprover(tmp_path_factory.mktemp("cap"), clock,
                       ApprovalPolicy(approvals_per_hour=10_000))
    for n, cents in enumerate(amounts):
        req = Request(id=f"p{n}", type="pay", amount_cents=cents, recipient=f"r{n}",
                      via_agent=True, created_at=0.0)
        rig.service.authorize(rig.session, rig.code(), ApprovalItem(f"p{n}", req, True),
                              lambda g: None)
        clock.t += 60
        assert rig.service.committed_cents() <= rig.service.policy.daily_cap_cents


# ---- abuse limits ----------------------------------------------------------------------
def test_three_bad_codes_lock_approvals_and_trip_the_breaker(world):
    a = world.approver
    pid = propose(world, MID, "cust_1")
    for _ in range(3):
        res = world.reviewer.approve(pid, a.session, bad_code(a))
        assert res.verdict is Verdict.BLOCK
    assert a.service.locked and world.executor.breaker_open and world.desk.breaker_open
    after = world.reviewer.approve(pid, a.session, a.code())
    assert not after.executed and "circuit breaker open" in after.reason   # Gate blocks first
    direct = a.service.authorize(a.session, a.code(), ApprovalItem(
        "x", Request(id="x", type="pay", amount_cents=500, recipient="r", via_agent=True,
                     created_at=0.0), False), lambda g: None)
    assert direct.status is Status.REFUSED and "approvals locked" in direct.reason
    assert not a.account.is_approver_session(a.session)            # sessions ended
    lines = [json.loads(l) for l in world.audit.read_text(encoding="utf-8").splitlines()]
    assert sum(l["decision"] == "FACTORFAIL" for l in lines) == 3
    assert sum(l["decision"] == "LOOKUP" for l in lines) == 0
    assert any(l["decision"] == "LOCKOUT" for l in lines) and verify(world.audit)
    assert any(n["kind"] == "lockout" for n in a.service._outbox.read())
    assert unchanged(world)


def test_a_good_code_resets_the_failure_count(world):
    a = world.approver
    pid = propose(world, MID, "cust_1")
    world.reviewer.approve(pid, a.session, bad_code(a))
    world.reviewer.approve(pid, a.session, bad_code(a))
    assert world.reviewer.approve(pid, a.session, a.code()).executed
    pid2 = propose(world, MID, "acct_supplier_1")
    world.reviewer.approve(pid2, a.session, bad_code(a))
    assert not a.service.locked


def test_approvals_are_rate_limited_per_hour(tmp_path):
    clock = type("C", (), {"t": 1000.0, "__call__": lambda self: self.t})()
    rig = TestApprover(tmp_path, clock, ApprovalPolicy(approvals_per_hour=2))

    def ask(n):
        req = Request(id=f"p{n}", type="pay", amount_cents=500, recipient=f"r{n}",
                      via_agent=True, created_at=0.0)
        return rig.service.authorize(rig.session, rig.code(), ApprovalItem(f"p{n}", req, False),
                                     lambda g: None)

    assert [ask(1).status, ask(2).status] == [Status.GRANTED, Status.GRANTED]
    third = ask(3)
    assert third.status is Status.REFUSED and "rate limit" in third.reason
    clock.t += 3601
    assert ask(4).status is Status.GRANTED


def test_velocity_counts_waiting_approvals(world):
    a = world.approver
    ids = [propose(world, BIG + i, "acct_supplier_1") for i in range(2)]
    world.clock.t += 1
    assert world.reviewer.approve(ids[0], a.session, a.code()).verdict is Verdict.HOLD
    res = world.reviewer.approve(ids[1], a.session, a.code())
    # seed payment + 1 waiting approval already reach the limit of 2 in 10 minutes
    assert res.verdict is Verdict.BLOCK and "velocity" in res.reason


# ---- release re-checks -------------------------------------------------------------------
def test_breaker_open_at_release_blocks(world):
    a = world.approver
    pid = propose(world, BIG, "acct_supplier_1")
    world.reviewer.approve(pid, a.session, a.code())
    world.executor.trip_breaker()
    world.clock.t += 900
    [(_, out)] = world.reviewer.release_due()
    assert out.verdict is Verdict.BLOCK and not out.executed and "breaker" in out.reason
    assert unchanged(world)


def test_gate_change_at_release_blocks(world, monkeypatch):
    a = world.approver
    pid = propose(world, BIG, "acct_supplier_1")
    world.reviewer.approve(pid, a.session, a.code())
    monkeypatch.setattr(world.executor, "preview",
                        lambda *a, **k: Decision(Verdict.HOLD, "something else now"))
    world.clock.t += 900
    [(_, out)] = world.reviewer.release_due()
    assert out.verdict is Verdict.BLOCK and "changed since approval" in out.reason
    assert unchanged(world)


def test_lockout_during_the_delay_blocks_the_release(world):
    a = world.approver
    pid = propose(world, BIG, "acct_supplier_1")
    world.reviewer.approve(pid, a.session, a.code())
    other = propose(world, MID, "cust_1")
    for _ in range(3):
        world.reviewer.approve(other, a.session, bad_code(a))
    world.clock.t += 900
    [(_, out)] = world.reviewer.release_due()
    assert out.verdict is Verdict.BLOCK and unchanged(world)


# ---- clock tampering ---------------------------------------------------------------------
def test_wall_clock_or_request_time_cannot_skip_the_delay(world):
    a = world.approver
    pid = propose(world, BIG, "acct_supplier_1")
    world.reviewer.approve(pid, a.session, a.code())
    a.wall.t += 10 ** 7                  # move the wall clock far forward
    assert world.reviewer.release_due() == [] and unchanged(world)


def test_clock_going_backwards_locks_approvals(world):
    a = world.approver
    pid = propose(world, BIG, "acct_supplier_1")
    world.reviewer.approve(pid, a.session, a.code())
    world.clock.t -= 5_000               # tamper: rewind the monotonic clock
    assert world.reviewer.release_due() == []
    assert a.service.locked and world.executor.breaker_open
    world.clock.t += 10_000
    [(_, out)] = world.reviewer.release_due()
    assert out.verdict is Verdict.BLOCK and unchanged(world)


# ---- guarded settings changes ------------------------------------------------------------
@pytest.mark.parametrize("kind,value,field", [("password", "a-brand-new-passphrase", None),
                                              ("alert_destination", "new@example.test", None),
                                              ("authenticator", None, None),
                                              ("policy", 5_000_000, "daily_cap_cents")])
def test_settings_change_needs_a_fresh_code(world, kind, value, field):
    a = world.approver
    svc = a.service
    assert svc.request_change(a.session, None, kind, value, field).change_id is None
    assert svc.request_change(a.session, bad_code(a), kind, value, field).change_id is None
    fake = Session(secrets.token_urlsafe(32), "alice", Role.APPROVER)
    assert svc.request_change(fake, a.code(), kind, value, field).change_id is None
    res = svc.request_change(a.session, a.code(), kind, value, field)
    assert res.change_id and not res.applied_now and res.release_at is not None
    assert any(n["kind"] == "settings_change" for n in svc._outbox.read())


def test_password_change_waits_then_ends_old_sessions(world):
    a = world.approver
    svc = a.service
    res = svc.request_change(a.session, a.code(), "password", "a-brand-new-passphrase")
    world.clock.t += 899
    assert svc.apply_due_changes() == []
    a.account.login("alice", PASSWORD)                    # old password still works
    world.clock.t += 1
    assert svc.apply_due_changes() == [res.change_id]
    with pytest.raises(AccountError):
        a.account.login("alice", PASSWORD)
    assert not a.account.is_approver_session(a.session)
    assert a.account.login("alice", "a-brand-new-passphrase")


def test_reenrolling_the_authenticator_waits_and_can_be_cancelled(world):
    a = world.approver
    svc = a.service
    res = svc.request_change(a.session, a.code(), "authenticator")
    new_secret = decode_secret(res.new_secret_b32)
    assert svc.cancel_change(res.change_id, "owner") is True
    world.clock.t += 1_000
    assert svc.apply_due_changes() == []
    assert a.account.check_code(a.code(), a.wall.t)        # old device still the one
    res2 = svc.request_change(a.session, a.code(), "authenticator")
    world.clock.t += 900
    assert svc.apply_due_changes() == [res2.change_id]
    a.wall.t += 30
    assert not a.account.check_code(code_at(SECRET, a.wall.t), a.wall.t)
    assert not a.account.check_code(code_at(new_secret, a.wall.t), a.wall.t)   # cancelled one
    assert a.account.check_code(code_at(decode_secret(res2.new_secret_b32), a.wall.t + 30),
                                a.wall.t + 30)


def test_alert_destination_change_tells_old_and_new_destination(world):
    a = world.approver
    a.service.request_change(a.session, a.code(), "alert_destination", "new@example.test")
    to = {n["to"] for n in a.service._outbox.read() if n["kind"] == "settings_change"}
    assert to == {OWNER, "new@example.test"}
    assert a.account.alert_destination == OWNER               # not changed yet


def test_raising_a_limit_waits_but_lowering_applies_now(world):
    a = world.approver
    svc = a.service
    up = svc.request_change(a.session, a.code(), "policy", 5_000_000, "daily_cap_cents")
    assert not up.applied_now and svc.policy.daily_cap_cents == 2_500_000
    down = svc.request_change(a.session, a.code(), "policy", 1_000_000, "daily_cap_cents")
    assert down.applied_now and svc.policy.daily_cap_cents == 1_000_000
    world.clock.t += 900
    svc.apply_due_changes()
    assert svc.policy.daily_cap_cents == 5_000_000           # the raise applied after waiting
    assert svc.tighten("cooling_off_seconds", 60, "sentinel") is False   # shorter = looser
    assert svc.tighten("approvals_per_hour", 5, "sentinel") is True
    assert svc.tighten("approvals_per_hour", 50, "sentinel") is False


# ---- audit: shared file, many threads; nothing secret ------------------------------------
def test_audit_log_is_safe_for_several_writers_and_threads(tmp_path):
    path = tmp_path / "shared.jsonl"
    writers = [AuditLog(path) for _ in range(4)]

    def work(w, n):
        for i in range(25):
            w.append(f"t{n}-{i}", "ALLOW", "concurrency test", 1, "r")

    threads = [threading.Thread(target=work, args=(writers[n % 4], n)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(path.read_text(encoding="utf-8").splitlines()) == 200 and verify(path)


def test_no_code_secret_password_grant_or_session_token_is_logged(world):
    a = world.approver
    used = []

    def code():
        used.append(a.code())
        return used[-1]

    pid = propose(world, BIG, "acct_supplier_1")
    world.reviewer.approve(pid, a.session, code())
    world.clock.t += 900
    world.reviewer.release_due()
    world.reviewer.approve(propose(world, MID, "cust_1"), a.session, code())
    res = a.service.request_change(a.session, code(), "authenticator")
    a.service.request_change(a.session, code(), "password", "a-brand-new-passphrase")
    text = world.audit.read_text(encoding="utf-8") + a.outbox_path.read_text(encoding="utf-8")
    for secret_value in [*used, PASSWORD, "a-brand-new-passphrase", MOCK_TOTP_SECRET_B32,
                         res.new_secret_b32, a.session.token]:
        assert secret_value not in text
    assert "[redacted]" not in text                   # reasons are readable, not blanked
    assert "approved by alice" in text and verify(world.audit)
    for obj in (a.account, a.session, a.service._account._checker):
        assert a.session.token not in repr(obj) and MOCK_TOTP_SECRET_B32 not in repr(obj)


def test_grant_is_single_use_and_bound_to_the_request(tmp_path):
    clock = type("C", (), {"t": 1000.0, "__call__": lambda self: self.t})()
    rig = TestApprover(tmp_path, clock)
    req = Request(id="p1", type="pay", amount_cents=500, recipient="r1", via_agent=True,
                  created_at=0.0)
    g = rig.grant(req)
    other = Request(id="p1", type="pay", amount_cents=501, recipient="r1", via_agent=True,
                    created_at=0.0)
    assert rig.service.redeem(g, other) is None                # mismatch burns it
    assert rig.service.redeem(g, req) is None
    g2 = rig.grant(Request(id="p2", type="pay", amount_cents=500, recipient="r2",
                           via_agent=True, created_at=0.0))
    clock.t += 61
    assert rig.service.redeem(g2, Request(id="p2", type="pay", amount_cents=500,
                                          recipient="r2", via_agent=True,
                                          created_at=0.0)) is None      # expired


# ---- the attack-suite scenario -------------------------------------------------------------
def test_attack_stolen_approver_session(world):
    """The attacker has the approver's logged-in session but not the authenticator."""
    [scenario] = [s for s in scenarios.ATTACKS if s.name == "stolen_approver_session"]
    [out] = world.run(scenario)
    assert out.verdict is Verdict.HOLD
    stolen = world.approver.session
    guesses = ["000000", "123456", "999999"]
    results = [world.reviewer.approve(out.proposal_id, stolen, g) for g in guesses]
    assert all(r.verdict is Verdict.BLOCK and not r.executed for r in results)
    assert world.approver.service.locked and world.executor.breaker_open
    assert not world.approver.account.is_approver_session(stolen)
    later = world.reviewer.approve(out.proposal_id, stolen, world.approver.code())
    assert not later.executed                       # even a right code is refused now
    assert unchanged(world)
