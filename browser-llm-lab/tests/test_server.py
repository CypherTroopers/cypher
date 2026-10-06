"""Standard-library-only route regression tests. No SearXNG service is needed."""
import importlib.util
import io
import json
import sys
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qs
from urllib.request import Request, urlopen
from unittest.mock import patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("browser_llm_test_server", Path(__file__).resolve().parents[1] / "server.py")
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)


class ServerRoutes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.base = "http://127.0.0.1:%d" % cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join()

    def request(self, path, body=None, method=None, headers=None):
        req = Request(self.base + path, data=body, method=method, headers=headers or {})
        try:
            with urlopen(req, timeout=3) as response:
                return response.status, dict(response.headers), response.read()
        except HTTPError as error:
            with error:
                return error.code, dict(error.headers), error.read()

    def test_new_javascript_route(self):
        status, headers, body = self.request("/models.js?v=models-v1")
        self.assertEqual(status, 200)
        self.assertIn("text/javascript", headers["Content-Type"])
        self.assertIn(b"export const MODELS", body)
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_new_css_route(self):
        self.assertEqual(self.request("/models.css?v=models-v1")[0], 200)

    def test_memory_and_chat_policy_modules_are_served(self):
        for path in ["/local-memory.js?v=cypher-v4", "/chat-policy.js?v=cypher-v4"]:
            with self.subTest(path=path):
                status, headers, body = self.request(path)
                self.assertEqual(status, 200)
                self.assertIn("text/javascript", headers["Content-Type"])
                self.assertIn(b"export", body)
                self.assertEqual(headers["Cache-Control"], "no-store")

    def test_workspace_assets_are_served_with_correct_types(self):
        for path, content_type, marker in [
            ("/workspace.css?v=openclaw-v1", "text/css", b".app-shell"),
            ("/openclaw-install.js?v=openclaw-v1", "text/javascript", b"recommendOpenClaw"),
            ("/openclaw-client.js?v=openclaw-v1", "text/javascript", b"OpenClawClient"),
            ("/mesh-controller.js?v=mesh-v1", "text/javascript", b"MeshController"),
            ("/mesh-worker.js?v=mesh-v1", "text/javascript", b"MeshEngine"),
            ("/mesh-protocol.js", "text/javascript", b"cypher-browser-mesh/1"),
            ("/relay-controller.js", "text/javascript", b"RelayController"),
            ("/relay-worker.js", "text/javascript", b"RelayEngine"),
            ("/relay-protocol.js", "text/javascript", b"verifyManifest"),
            ("/relay-ui.js", "text/javascript", b"setupRelayUI"),
            ("/relay-map.js?v=mesh-map-v2", "text/javascript", b"RelayMap"),
            ("/relay.css", "text/css", b"relay-panel"),
            ("/assets/earth-land.json", "application/json", b"Natural Earth"),
            ("/assets/cypher-horizon.png", "image/png", b"\x89PNG\r\n\x1a\n"),
        ]:
            with self.subTest(path=path):
                status, headers, body = self.request(path)
                self.assertEqual(status, 200)
                self.assertIn(content_type, headers["Content-Type"])
                self.assertIn(marker, body)
                self.assertEqual(headers["Cache-Control"], "no-store")

    def test_head_has_no_body(self):
        status, headers, body = self.request("/models.js", method="HEAD")
        self.assertEqual(status, 200)
        self.assertGreater(int(headers["Content-Length"]), 0)
        self.assertEqual(body, b"")

    def test_health_has_new_release_marker(self):
        status, _, body = self.request("/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["version"], "models-v1")
        self.assertEqual(json.loads(body)["inference"], "browser")
        self.assertEqual(json.loads(body)["workspace"], "cypher-v5")

    def test_unlisted_files_are_not_exposed(self):
        for path in ["/server.py", "/tests/models.test.mjs", "/package.json", "/../server.py", "/relay/config.json", "/.runtime/relay-source/signing-key.pem", "/.runtime/mesh-a/source.json", "/.runtime/mesh-b/node.ipc", "/relay/source-config", "/relay/v1/source-config"]:
            self.assertEqual(self.request(path)[0], 404)

    def test_search_cross_origin_still_rejected(self):
        status, _, _ = self.request("/api/search", b'{"q":"test"}',
                                    headers={"Content-Type": "application/json", "Origin": "https://untrusted.invalid"})
        self.assertEqual(status, 403)

    def test_search_input_validation_unchanged(self):
        for body in [b'{"q":""}', b'{"q":12}', b'{"q":"test","time_range":"invalid"}']:
            self.assertEqual(self.request("/api/search", body, headers={"Content-Type": "application/json"})[0], 400)

    def test_search_proxy_still_handles_valid_query(self):
        original = server.search_web
        try:
            server.search_web = lambda query, time_range, language="en": {"ok": True, "query": query, "time_range": time_range, "language": language, "results": []}
            status, _, body = self.request("/api/search", b'{"q":"test","time_range":"day"}', headers={"Content-Type": "application/json"})
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["query"], "test")
        finally:
            server.search_web = original

    def test_search_language_is_selected_or_inferred_before_upstream(self):
        cases = [
            ({"q": "Latest browser features"}, "en"),
            ({"q": "最近のブラウザー機能"}, "ja"),
            ({"q": "東京 天気"}, "ja"),
            ({"q": "Tokyo weather", "language": "ja"}, "ja"),
            ({"q": "東京の天気", "language": "en"}, "en"),
        ]
        for request_body, language in cases:
            with self.subTest(request_body=request_body), patch.object(server, "search_web", return_value={"ok": True, "results": []}) as search:
                status, _, _ = self.request("/api/search", json.dumps(request_body).encode(), headers={"Content-Type": "application/json"})
                self.assertEqual(status, 200)
                search.assert_called_once_with(request_body["q"], "", language)

    def test_invalid_search_language_never_reaches_upstream(self):
        for language in ["auto", "fr", "JA", "", None, 1, [], {}]:
            with self.subTest(language=language), patch.object(server, "search_web") as search:
                body = json.dumps({"q": "test", "language": language}).encode()
                status, _, result = self.request("/api/search", body, headers={"Content-Type": "application/json"})
                self.assertEqual(status, 400)
                self.assertIn("language", json.loads(result)["error"])
                search.assert_not_called()

    def test_search_language_reaches_searxng_form(self):
        for language in ["ja", "en"]:
            with self.subTest(language=language), patch.object(server.UPSTREAM, "open", return_value=io.BytesIO(b'{"results": []}')) as upstream:
                result = server.search_web("東京の天気", "day", language)
                request = upstream.call_args.args[0]
                self.assertEqual(request.full_url, server.SEARXNG_URL + "/search")
                self.assertEqual(parse_qs(request.data.decode()), {
                    "q": ["東京の天気"], "format": ["json"], "categories": ["general"],
                    "language": [language], "safesearch": ["1"], "pageno": ["1"], "time_range": ["day"],
                })
                self.assertEqual(result["language"], language)

    def test_no_model_inference_post_endpoint_added(self):
        self.assertEqual(self.request("/api/chat", b"{}", headers={"Content-Type": "application/json"})[0], 404)


if __name__ == "__main__":
    unittest.main()
