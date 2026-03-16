from pathlib import Path

from django.test import SimpleTestCase


class StaticAssetSafetyTests(SimpleTestCase):
    def test_import_modal_staticfiles_has_no_row_innerhtml_injection(self):
        root = Path(__file__).resolve().parents[2]
        js_dir = root / "staticfiles" / "js"
        for path in js_dir.glob("import_modal*.js"):
            content = path.read_text(encoding="utf-8")
            self.assertNotIn("tr.innerHTML", content)

    def test_import_modal_staticfiles_has_no_entry_interpolation_in_innerhtml(self):
        root = Path(__file__).resolve().parents[2]
        js_dir = root / "staticfiles" / "js"
        for path in js_dir.glob("import_modal*.js"):
            content = path.read_text(encoding="utf-8")
            self.assertNotIn("${entry.", content)
