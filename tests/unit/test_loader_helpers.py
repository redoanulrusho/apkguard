"""Loader helpers exercised with a fake androguard APK object (no real APK needed)."""

from __future__ import annotations

from apkguard.loader import MAX_ASSET_BYTES, _load_asset_strings, _load_network_security_config

from helpers import manifest

NSC_XML = (
    b'<?xml version="1.0" encoding="utf-8"?><network-security-config>'
    b'<base-config cleartextTrafficPermitted="true"/></network-security-config>'
)


class _FakeResources:
    def __init__(self, mapping: dict[int, str]) -> None:
        self.mapping = mapping

    def get_resolved_res_configs(self, res_id: int) -> list[tuple[object, str]]:
        return [(object(), self.mapping[res_id])] if res_id in self.mapping else []


class _FakeApk:
    def __init__(self, files: dict[str, bytes], resources: dict[int, str] | None = None) -> None:
        self.files = files
        self.resources = _FakeResources(resources or {})

    def get_file(self, name: str) -> bytes:
        if name not in self.files:
            raise FileNotFoundError(name)
        return self.files[name]

    def get_files(self) -> list[str]:
        return list(self.files)

    def get_android_resources(self) -> _FakeResources:
        return self.resources


def test_network_security_config_resolved_via_resource_id() -> None:
    apk = _FakeApk({"res/Xy.xml": NSC_XML}, {0x7F0E0001: "res/Xy.xml"})
    m = manifest(app='android:networkSecurityConfig="@7F0E0001"')
    path, root = _load_network_security_config(apk, m)
    assert path == "res/Xy.xml"
    assert root is not None
    assert root.find("base-config").get("cleartextTrafficPermitted") == "true"  # type: ignore[union-attr]


def test_network_security_config_falls_back_to_conventional_path() -> None:
    apk = _FakeApk({"res/xml/network_security_config.xml": NSC_XML})
    m = manifest(app='android:networkSecurityConfig="@xml/network_security_config"')
    path, root = _load_network_security_config(apk, m)
    assert path == "res/xml/network_security_config.xml"
    assert root is not None


def test_no_network_security_config() -> None:
    path, root = _load_network_security_config(_FakeApk({}), manifest())
    assert (path, root) == (None, None)


def test_asset_strings_extracted_per_line_and_filtered() -> None:
    apk = _FakeApk(
        {
            "assets/config.json": b'{\n  "api": "https://api.example.com/v1"\n}\n',
            "assets/image.png": b"\x89PNG....",
            "assets/huge.txt": b"x" * (MAX_ASSET_BYTES + 1),
            "res/raw/binary.xml": b"\x03\x00\x08\x00rest-of-binary-xml",
            "res/raw/keys.properties": b"token=abcdefghijklmnop\n",
            "classes.dex": b"dex\n035",
        }
    )
    items = _load_asset_strings(apk)
    assert [(i.file, i.symbol) for i in items] == [
        ("assets/config.json", "line 2"),
        ("res/raw/keys.properties", "line 1"),
    ]
    assert items[0].value == '"api": "https://api.example.com/v1"'
