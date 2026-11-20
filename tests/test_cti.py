import unittest

try:
    import app.cti as cti
except ImportError:  # httpx/fastapi are not installed in every environment
    cti = None


@unittest.skipIf(cti is None, "app dependencies not installed")
class CtiTests(unittest.TestCase):
    def test_normalize_handles_defanged_and_rejects_garbage(self):
        n = cti.normalize("hxxp://Bad[.]Example.org/Login.php?x=1")
        self.assertEqual((n["kind"], n["host"], n["match_url"]), ("url", "bad.example.org", "bad.example.org/login.php?x=1"))
        self.assertEqual(cti.normalize("ttp://124.222.137.114:9999/3yZR")["url"], "http://124.222.137.114:9999/3yZR")
        self.assertEqual(cti.normalize("hxxps[://]evil[.]example/a")["url"], "https://evil.example/a")
        self.assertEqual(cti.normalize("8.8.8.8")["kind"], "ip")
        self.assertEqual(cti.normalize("https://a.com:443/")["match_url"], "a.com")
        for bad in ("not a url", "localhost", "", "http://"):
            self.assertIsNone(cti.normalize(bad), bad)

    def test_same_url_in_two_feeds_and_cve_alias_are_merged(self):
        feeds = [
            {"source": "URLhaus", "matches": [{"match": "exact URL", "value": "http://evil.example/x", "tags": ["CVE-2024-1111"]}]},
            {"source": "Botvrij.eu", "matches": [{"match": "exact URL", "value": "https://EVIL.example/x/"}], "related_cves": ["CVE-2024-1111"]},
        ]
        gcve = {"vulnerabilities": [{"id": "CVE-2024-1111", "aliases": ["GHSA-AAAA"]}, {"id": "GHSA-AAAA"}]}
        findings, raw = cti.merge_findings(feeds, gcve)
        self.assertEqual(raw, 6)
        self.assertEqual(len(findings), 2)
        url = next(f for f in findings if f["kind"] == "indicator")
        self.assertEqual(url["sources"], ["URLhaus", "Botvrij.eu"])
        vuln = next(f for f in findings if f["kind"] == "vulnerability")
        self.assertEqual(vuln["value"], "CVE-2024-1111")
        self.assertEqual(set(vuln["sources"]), {"URLhaus", "Botvrij.eu", "GCVE"})

    def test_scoring(self):
        feeds = [{"source": "Botvrij.eu", "matches": [{"match": "exact URL", "value": "http://e.example/a"}]}]
        findings, _ = cti.merge_findings(feeds, {})
        points, verdict, _ = cti.score(feeds, {}, findings)
        self.assertEqual((points, verdict), (60, "Malicious"))
        points, verdict, reasons = cti.score([], {"products": [{"label": "WordPress"}]}, [])
        self.assertEqual((points, verdict), (0, "No known threats"))
        self.assertTrue(any("WordPress" in r for r in reasons))

    def test_product_detection_and_vulnerability_parsing(self):
        labels = [p["label"] for p in cti.detect_products(cti.normalize("https://shop.example/wp-admin/admin-ajax.php"))]
        self.assertEqual(labels, ["WordPress"])
        nvd = {"id": "CVE-2024-53677", "descriptions": [{"lang": "en", "value": "Struts upload"}],
               "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "version": "3.1"}}]}}
        s = cti.vulnerability_summary(nvd)
        self.assertEqual((s["id"], s["cvss"]["score"]), ("CVE-2024-53677", 9.8))
        cve5 = {"cveMetadata": {"cveId": "cve-2024-6387"}, "containers": {"cna": {"title": "regreSSHion", "metrics": [{"cvssV3_1": {"baseScore": 8.1, "baseSeverity": "HIGH"}}]}}}
        self.assertEqual(cti.vulnerability_summary(cve5)["cvss"]["severity"], "HIGH")

    def test_virustotal_lookup_and_weighting(self):
        import os
        from unittest.mock import Mock, patch

        def client_for(malicious):
            def get(url, headers=None):
                self.assertEqual(headers, {"x-apikey": "k"})
                r = Mock()
                if "/urls/" in url:
                    results = {f"E{i}": {"category": "malicious", "result": "phishing"} for i in range(malicious)}
                    r.status_code, r.json.return_value = 200, {"data": {"attributes": {
                        "last_analysis_stats": {"malicious": malicious, "suspicious": 0, "harmless": 60, "undetected": 10},
                        "last_analysis_results": results}}}
                else:
                    r.status_code = 404
                return r
            return Mock(get=get)

        target = cti.normalize("http://bad.example/login")
        with patch.dict(os.environ, {"VT_API_KEY": "k"}):
            one = cti.check_virustotal(target, client_for(1))
            five = cti.check_virustotal(target, client_for(5))
            clean = cti.check_virustotal(target, client_for(0))
        self.assertEqual((one["status"], one["score_points"]), ("hit", 15))
        self.assertEqual((five["status"], five["score_points"]), ("hit", 60))
        self.assertEqual(clean["status"], "no_match")
        self.assertEqual(cti.score([five], {}, [])[1], "Malicious")
        with patch.dict(os.environ, {"VT_API_KEY": ""}):
            self.assertEqual(cti.check_virustotal(target, Mock())["status"], "not_configured")

    def test_threatfox_match_fields(self):
        self.assertEqual(cti._threatfox_match_fields("url", "https://Morkovka.cn/qqkb/"),
                         {"match_url": "morkovka.cn/qqkb", "match_host": "morkovka.cn"})
        self.assertEqual(cti._threatfox_match_fields("domain", "Evil.Example."), {"match_host": "evil.example"})
        self.assertEqual(cti._threatfox_match_fields("ip:port", "1.2.3.4:8080"), {"match_ip": "1.2.3.4"})
        self.assertEqual(cti._threatfox_match_fields("sha256_hash", "abc"), {})

    def test_botvrij_event_attributes_get_match_keys(self):
        docs = cti._event_documents("ev1", {"info": "x", "Attribute": [
            {"uuid": "1", "type": "url", "value": "http://evil.example/p"},
            {"uuid": "2", "type": "domain|ip", "value": "evil.example|1.2.3.4"},
            {"uuid": "3", "type": "link", "value": "https://github.com/report"}],
            "Object": [{"Attribute": [{"uuid": "4", "type": "ip-dst", "value": "5.6.7.8"}]}]})
        by = {d["_id"]: d for d in docs}
        self.assertEqual(by["ev1:1"]["match_url"], "evil.example/p")
        self.assertEqual((by["ev1:2"]["match_host"], by["ev1:2"]["match_ip"]), ("evil.example", "1.2.3.4"))
        self.assertNotIn("match_host", by["ev1:3"])  # report links are not IOCs
        self.assertEqual(by["ev1:4"]["match_ip"], "5.6.7.8")


if __name__ == "__main__":
    unittest.main()
