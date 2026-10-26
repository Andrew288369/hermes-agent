"""Local model server detection: real loopback HTTP servers on ephemeral ports stand in for
Ollama / LM Studio / vLLM; the pickers, the switch path and ``hermes model`` read them for real."""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from hermes_cli import models_local_detect as detect


class _Server:
    """One loopback server. ``routes`` maps a GET path to ``(status, body, headers)``."""

    def __init__(self, routes: dict, *, hang: bool = False):
        self.requests: list[tuple[str, str | None]] = []
        self.release = threading.Event()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_a):
                pass

            def do_GET(self):
                outer.requests.append((self.path, self.headers.get("Authorization")))
                if hang:
                    outer.release.wait(10)
                status, body, headers = routes.get(self.path, (404, b"{}", {}))
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.release.set()
        self.httpd.shutdown()
        self.httpd.server_close()


def _models(ids, owner):
    return (200, json.dumps({"object": "list", "data": [{"id": i, "owned_by": owner} for i in ids]}).encode(), {})


@pytest.fixture
def servers(monkeypatch):
    started: list[_Server] = []

    def start(kind: str, routes: dict, **kw) -> _Server:
        srv = _Server(routes, **kw)
        started.append(srv)
        label = {"ollama": "Ollama", "lmstudio": "LM Studio", "vllm": "vLLM"}[kind]
        known = [k for k in detect.KNOWN_SERVERS if k.kind != kind] + [detect._Kind(kind, label, srv.port)]
        monkeypatch.setattr(detect, "KNOWN_SERVERS", tuple(known))
        monkeypatch.setattr(detect, "_KIND_BY_NAME", {k.kind: k for k in known})
        return srv

    # Point every default port at a closed one first, so nothing on the host can answer.
    closed = _Server({})
    closed_port = closed.port
    closed.close()
    blank = tuple(detect._Kind(k.kind, k.label, closed_port) for k in detect.KNOWN_SERVERS)
    monkeypatch.setattr(detect, "KNOWN_SERVERS", blank)
    monkeypatch.setattr(detect, "_KIND_BY_NAME", {k.kind: k for k in blank})
    monkeypatch.setattr(detect, "_cache", None)
    yield start
    for srv in started:
        srv.close()


def test_detects_servers_from_their_own_model_lists_without_sending_a_key(servers):
    ollama = servers("ollama", {"/v1/models": _models(["llama3.2:3b", "qwen2.5:7b"], "library")})
    vllm = servers("vllm", {"/v1/models": _models(["meta-llama/Llama-3.1-8B-Instruct"], "vllm")})

    found = {s.kind: s for s in detect.detect_local_servers(refresh=True)}

    assert found["ollama"].models == ("llama3.2:3b", "qwen2.5:7b")
    assert found["ollama"].base_url == f"http://127.0.0.1:{ollama.port}/v1"
    assert found["ollama"].row_label == "Detected: Ollama (2 models)"
    assert found["vllm"].models == ("meta-llama/Llama-3.1-8B-Instruct",)
    assert "lmstudio" not in found
    assert all(auth is None for srv in (ollama, vllm) for _path, auth in srv.requests)


def test_ollama_native_tag_list_is_the_fallback(servers):
    servers("ollama", {"/api/tags": (200, json.dumps({"models": [{"name": "mistral:latest"}]}).encode(), {})})
    (server,) = detect.detect_local_servers(refresh=True)
    assert (server.kind, server.models) == ("ollama", ("mistral:latest",))


@pytest.mark.parametrize("routes", [
    {"/v1/models": (200, b"<html>dev server</html>", {})},
    {"/v1/models": (200, json.dumps({"data": []}).encode(), {})},
    {"/v1/models": (401, b"{}", {})},
    {"/v1/models": (302, b"", {"Location": "/elsewhere"}),
     "/elsewhere": _models(["redirected"], "vllm")},
    {"/v1/models": (200, b'{"data": [' + b'{"id": "x"},' * 200_000 + b'{"id": "y"}]}', {})},
])
def test_a_port_that_is_not_a_model_server_yields_no_row(servers, routes):
    servers("vllm", routes)
    assert detect.detect_local_servers(refresh=True) == []


def test_a_hanging_port_cannot_stall_the_scan(servers):
    servers("vllm", {"/v1/models": _models(["slow"], "vllm")}, hang=True)
    servers("ollama", {"/v1/models": _models(["fast"], "library")})
    started = time.monotonic()
    found = detect.detect_local_servers(refresh=True, timeout=0.3)
    assert time.monotonic() - started < 2
    assert [s.kind for s in found] == ["ollama"]


def test_only_an_opened_picker_probes_and_other_reads_reuse_its_rows(servers):
    from hermes_cli.inventory import ConfigContext, build_models_payload

    srv = servers("ollama", {"/v1/models": _models(["llama3.2:3b"], "library")})
    ctx = ConfigContext("openrouter", "x", "", {}, [])

    def detected(mode):
        rows = build_models_payload(ctx, for_picker=True, local_detection=mode)["providers"]
        return [r for r in rows if r.get("source") == "detected"]

    assert detected("off") == [] and detected("cached") == []
    assert srv.requests == []
    (row,) = detected("probe")
    assert (row["slug"], row["name"], row["models"]) == ("local-ollama", "Detected: Ollama", ["llama3.2:3b"])
    probes = len(srv.requests)
    assert [r["slug"] for r in detected("cached")] == ["local-ollama"]
    assert len(srv.requests) == probes


def test_saved_server_is_not_offered_again(servers):
    from hermes_cli.inventory import ConfigContext, build_models_payload

    srv = servers("ollama", {"/v1/models": _models(["llama3.2:3b"], "library")})
    saved = {"my-ollama": {"name": "Box", "base_url": f"http://localhost:{srv.port}/v1"}}
    ctx = ConfigContext("openrouter", "x", "", saved, [])
    rows = build_models_payload(ctx, for_picker=True, local_detection="probe")["providers"]
    assert not [r for r in rows if r.get("source") == "detected"]


def test_picking_a_detected_row_saves_a_provider_and_switches(servers):
    from hermes_cli.config import load_config
    from hermes_cli.model_switch import switch_model

    srv = servers("ollama", {"/v1/models": _models(["llama3.2:3b", "qwen2.5:7b"], "library")})
    detect.detect_local_servers(refresh=True)

    result = switch_model("qwen2.5:7b", "openrouter", "x", explicit_provider="local-ollama",
                          user_providers={}, custom_providers=[])

    assert result.success, result.error_message
    assert (result.target_provider, result.new_model) == ("local-ollama", "qwen2.5:7b")
    assert result.base_url == f"http://127.0.0.1:{srv.port}/v1"
    entry = load_config()["providers"]["local-ollama"]
    assert entry == {"name": "Ollama (local)", "base_url": f"http://127.0.0.1:{srv.port}/v1"}


def test_unknown_local_slug_writes_nothing(servers):
    from hermes_cli.config import load_config
    from hermes_cli.model_switch import switch_model

    result = switch_model("m", "openrouter", "x", explicit_provider="local-ollama",
                          user_providers={}, custom_providers=[])
    assert not result.success
    assert "local-ollama" not in (load_config().get("providers") or {})


def test_hermes_model_offers_detected_row_and_pick_saves_named_provider(servers):
    from hermes_cli.config import load_config
    from hermes_cli.main_provider_setup import (
        _adopt_detected_pick, _build_provider_picker_rows, _named_custom_provider_map)

    srv = servers("lmstudio", {"/v1/models": _models(["qwen/qwen3-4b"], "organization_owner")})
    rows, _ = _build_provider_picker_rows(load_config(), "", {}, {})
    (key, label, _members), = [r for r in rows if r[0].startswith("detected:")]
    assert label.startswith("Detected: LM Studio (1 model)")
    assert key == "detected:local-lmstudio"

    slug = _adopt_detected_pick(key)

    assert slug == "custom:local-lmstudio"
    assert _named_custom_provider_map(load_config())[slug]["base_url"] == f"http://127.0.0.1:{srv.port}/v1"
    assert _adopt_detected_pick("openrouter") == "openrouter"
