from io import BytesIO
from struct import pack
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from core.burp_extensions import MAX_ARCHIVE_BYTES, MAX_CLASS_BYTES, inspect_burp_archive


def sample_extension_archive():
    pool = []

    def constant(tag, data):
        pool.append(pack('>B', tag) + data)
        return len(pool)

    def utf(text):
        data = text.encode('ascii')
        return constant(1, pack('>H', len(data)) + data)

    def class_ref(name):
        return constant(7, pack('>H', utf(name)))

    def method(owner, name, descriptor, tag=11):
        owner = class_ref(owner)
        signature = constant(12, pack('>HH', utf(name), utf(descriptor)))
        return constant(tag, pack('>HH', owner, signature))

    extension = class_ref('demo/InspectorExtension')
    parent = class_ref('java/lang/Object')
    interface = class_ref('burp/api/montoya/BurpExtension')
    class_ref('javax/swing/JPanel')
    method('burp/api/montoya/ui/UserInterface', 'registerSuiteTab', '(Ljava/lang/String;Ljava/awt/Component;)V')
    method('burp/api/montoya/ui/UserInterface', 'registerHttpResponseEditorProvider',
           '(Lburp/api/montoya/ui/editor/extension/HttpResponseEditorProvider;)V')
    method('burp/IBurpExtenderCallbacks', 'registerContextMenuFactory', '(Lburp/IContextMenuFactory;)V')
    method('demo/FakeInterface', 'registerHotKeyHandler', '()V', tag=10)
    utf('registerSettingsPanel')
    data = b''.join((pack('>IHHH', 0xCAFEBABE, 0, 61, len(pool) + 1), *pool,
                     pack('>8H', 0x21, extension, parent, 1, interface, 0, 0, 0)))
    output = BytesIO()
    with ZipFile(output, mode='w', compression=ZIP_DEFLATED) as archive:
        archive.writestr('demo/InspectorExtension.class', data)
        archive.writestr('bad.class', data[:24])
        archive.writestr('oversized.class', b'x' * (MAX_CLASS_BYTES + 1))
        archive.writestr('burp/api/montoya/BurpExtension.class', data)
        archive.writestr('resources/nested.jar', 'not opened')
    return output.getvalue()


def test_static_metadata_distinguishes_real_references_and_reports_skips():
    report = inspect_burp_archive(sample_extension_archive())
    assert report == {
        'classes': {'scanned': 1, 'skipped': 2, 'bundled_api': 1},
        'nested_archives': 1,
        'apis': ['Montoya', 'Legacy Extender'],
        'montoya_packages': ['ui'],
        'ui_contributions': ['context_menu', 'response_editor', 'workspace_tab'],
        'ui_frameworks': ['AWT', 'Swing'],
    }


def sample_bapp_archive(entry_point='build/inspector.jar'):
    output = BytesIO()
    with ZipFile(output, mode='w', compression=ZIP_DEFLATED) as archive:
        archive.writestr('BappManifest.bmf', f'Name: Inspector\nEntryPoint: {entry_point}\n')
        archive.writestr('build/inspector.jar', sample_extension_archive())
        archive.writestr('lib/optional.jar', b'left unopened')
    return output.getvalue()


def test_bapp_reads_only_its_declared_java_entry_point():
    report = inspect_burp_archive(sample_bapp_archive())
    assert report['bapp_entry_point'] == 'build/inspector.jar'
    assert report['classes']['scanned'] == 1
    assert report['nested_archives'] == 2
    with pytest.raises(ValueError, match='missing or ambiguous'):
        inspect_burp_archive(sample_bapp_archive('other.jar'))
    with pytest.raises(ValueError, match='Java JAR entry point'):
        inspect_burp_archive(sample_bapp_archive('main.py'))


@pytest.mark.asyncio
async def test_archive_inspection_rejects_invalid_and_cross_origin_uploads(app_client):
    client, _ = app_client
    path = '/api/extensions/inspect'
    assert (await client.post(path, content=b'not an archive')).status_code == 422
    assert (await client.post(path, content=b'x' * (MAX_ARCHIVE_BYTES + 1))).status_code == 413
    jar = sample_extension_archive()
    denied = await client.post(path, content=jar, headers={'Origin': 'https://example.org'})
    assert denied.status_code == 403
    accepted = await client.post(path, content=jar, headers={'Origin': 'chrome-extension://' + 'a' * 32})
    assert accepted.status_code == 200
    assert accepted.json()['ui_contributions'] == ['context_menu', 'response_editor', 'workspace_tab']
