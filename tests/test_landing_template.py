"""Public template regression checks; no credentials, app or scanner imports."""
import pathlib
import shutil
import tempfile
import unittest
from unittest.mock import patch

import landing


class LandingTemplateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = pathlib.Path(self.temp.name)
        shutil.copytree(landing.ROOT / "landing", root / "landing")
        shutil.copytree(landing.ROOT / "assets", root / "assets")
        shutil.copyfile(landing.ROOT / "logo.png.png", root / "logo.png.png")
        shutil.copyfile(landing.ROOT / "app.py", root / "app.py")
        self.template = root / "landing" / "index.html"
        self.root_patch = patch.object(landing, "ROOT", root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def test_both_languages_resolve_new_logo_and_nested_demo_values(self):
        for language in ("es", "en"):
            html = landing.document(language)
            self.assertNotIn("{{hero_logo}}", html)
            self.assertNotIn("{{medium_count}}", html)
            self.assertIn('width:0.0%', html)
            self.assertIn('width:40.0%', html)
            self.assertIn('width:72%', html)
            self.assertIn('72<small>/100</small>', html)

    def test_unknown_marker_is_reported_by_name(self):
        self.template.write_text(self.template.read_text(encoding="utf-8") + "{{missing_asset}}", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Unresolved landing template: missing_asset"):
            landing.document()

    def test_quota_changes_follow_existing_app_configuration(self):
        source = landing.ROOT / "app.py"
        old = 'if plan == "Pro":\n        return 25'
        text = source.read_text(encoding="utf-8-sig")
        self.assertEqual(text.count(old), 1)
        source.write_text(text.replace(old, 'if plan == "Pro":\n        return 12'), encoding="utf-8")
        self.assertIn("12 distinct targets per month.", landing.document("en"))

    def test_legitimate_javascript_nested_blocks_are_not_placeholders(self):
        block = "<script>if (true) {{ const ok = 1; }}</script>"
        self.template.write_text(self.template.read_text(encoding="utf-8") + block, encoding="utf-8")
        self.assertIn(block, landing.document())
