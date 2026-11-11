"""Recorder behaviour and evidence-pack edge cases."""

from __future__ import annotations

import json

from agentproof.capture import Recorder, iter_trace, read_trace
from agentproof.capture.events import AgentEvent, EventKind
from agentproof.core.chain import Chain
from agentproof.core.receipt import Decision
from agentproof.evidence import build_aibom, build_evidence_pack


def _event(kind=EventKind.TOOL_CALL, action="x", agent="a", inputs=None):
    return AgentEvent(
        kind=kind,
        ts=AgentEvent.now_ts(),
        agent=agent,
        action=action,
        inputs=inputs or {},
    )


# ----------------------------------------------------------------------
# recorder
# ----------------------------------------------------------------------
def test_recorder_writes_jsonl(tmp_path):
    path = tmp_path / "trace.jsonl"
    with Recorder(path) as recorder:
        recorder.record(_event())
        recorder.record(_event(action="y"))

    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["action"] == "x"


def test_recorder_keeps_events_in_memory(tmp_path):
    with Recorder(tmp_path / "t.jsonl") as recorder:
        recorder.record(_event())
        assert len(recorder.events) == 1


def test_recorder_can_skip_memory(tmp_path):
    with Recorder(tmp_path / "t.jsonl", keep_in_memory=False) as recorder:
        recorder.record(_event())
        assert recorder.events == []
    assert len((tmp_path / "t.jsonl").read_text(encoding="utf-8").strip()) > 0


def test_recorder_note(tmp_path):
    with Recorder(tmp_path / "t.jsonl") as recorder:
        event = recorder.note("checkpoint reached", stage="mid")
        assert event.kind is EventKind.NOTE
        assert event.payload["text"] == "checkpoint reached"
        assert event.tags == ["stage"]


def test_recorder_save_writes_a_separate_file(tmp_path):
    recorder = Recorder(None)
    recorder.record(_event())
    out = recorder.save(tmp_path / "saved.jsonl")
    assert out.exists()
    assert len(read_trace(out)) == 1


def test_read_trace_skips_blank_lines(tmp_path):
    path = tmp_path / "t.jsonl"
    path.write_text(
        json.dumps(_event().to_dict()) + "\n\n" + json.dumps(_event().to_dict()) + "\n",
        encoding="utf-8",
    )
    assert len(read_trace(path)) == 2


def test_iter_trace_streams(tmp_path):
    path = tmp_path / "t.jsonl"
    path.write_text(
        "\n".join(json.dumps(_event(action=str(i)).to_dict()) for i in range(3)),
        encoding="utf-8",
    )
    assert len(list(iter_trace(path))) == 3


# ----------------------------------------------------------------------
# aibom
# ----------------------------------------------------------------------
def test_aibom_counts_assets():
    events = [
        _event(action="kb.search", agent="agent-a"),
        _event(action="kb.search", agent="agent-a"),
        _event(action="db.write", agent="agent-b"),
        AgentEvent(kind=EventKind.LLM_CALL, ts=AgentEvent.now_ts(), agent="agent-a"),
        AgentEvent(kind=EventKind.ERROR, ts=AgentEvent.now_ts(), agent="agent-a"),
    ]
    aibom = build_aibom(events, subject="s")

    assert aibom.summary["tool_count"] == 2
    assert aibom.summary["agent_count"] == 2
    assert aibom.summary["error_events"] == 1
    assert aibom.summary["total_events"] == 5


def test_aibom_records_sample_inputs():
    aibom = build_aibom([_event(action="kb.search", inputs={"q": "x"})])
    tool = aibom.tools[0]
    assert tool["sample_inputs"] == {"q": "x"}
    assert len(tool["input_digests"]) == 1


def test_aibom_handles_an_empty_trace():
    aibom = build_aibom([])
    assert aibom.summary["tool_count"] == 0
    assert aibom.summary["total_events"] == 0


def test_aibom_writes_both_formats(tmp_path):
    aibom = build_aibom([_event()], subject="s")
    json_path = aibom.save_json(tmp_path / "aibom.json")
    md_path = aibom.save_markdown(tmp_path / "aibom.md")
    assert "AI Bill of Materials" in md_path.read_text(encoding="utf-8")
    assert json.loads(json_path.read_text(encoding="utf-8"))["subject"] == "s"


# ----------------------------------------------------------------------
# evidence pack
# ----------------------------------------------------------------------
def test_evidence_pack_summarizes_decisions(populated_chain):
    pack = build_evidence_pack(populated_chain)

    assert pack.summary["total_decisions"] == 3
    assert pack.summary["by_decision"]["ALLOW"] == 2
    assert pack.summary["by_decision"]["DENY"] == 1
    assert pack.summary["denied_actions"] == ["db.write"]
    assert pack.summary["chain_sealed"] is False


def test_unsealed_pack_warns_about_rewrite_detection(populated_chain):
    pack = build_evidence_pack(populated_chain)
    assert any("not sealed" in limitation for limitation in pack.limitations)


def test_sealed_pack_has_no_seal_warning(populated_chain):
    populated_chain.seal_chain()
    pack = build_evidence_pack(populated_chain)
    assert not any("not sealed" in limitation for limitation in pack.limitations)


def test_pack_always_states_its_limitations(populated_chain):
    pack = build_evidence_pack(populated_chain)
    assert len(pack.limitations) >= 4
    assert any("not a legal opinion" in limitation for limitation in pack.limitations)


def test_pack_maps_requested_frameworks(populated_chain):
    pack = build_evidence_pack(
        populated_chain, frameworks=["eu-ai-act-article-26", "iso-42001-2023"]
    )
    assert "eu-ai-act-article-26" in pack.control_map
    assert "iso-42001-2023" in pack.control_map


def test_pack_ignores_unknown_frameworks(populated_chain):
    pack = build_evidence_pack(populated_chain, frameworks=["not-a-framework"])
    assert pack.control_map == {}


def test_pack_writes_both_formats(populated_chain, tmp_path):
    populated_chain.seal_chain()
    pack = build_evidence_pack(populated_chain)

    json_path = pack.save_json(tmp_path / "pack.json")
    md_path = pack.save_markdown(tmp_path / "pack.md")

    assert json.loads(json_path.read_text(encoding="utf-8"))["verification"]["ok"]
    markdown = md_path.read_text(encoding="utf-8")
    assert "Deployer evidence pack" in markdown
    assert "## Limitations" in markdown


def test_empty_chain_produces_an_empty_but_valid_pack(keypair):
    private, _ = keypair
    chain = Chain(private, subject="empty")
    pack = build_evidence_pack(chain)

    assert pack.summary["total_decisions"] == 0
    assert pack.decisions == []
    assert pack.verification["ok"] is True
