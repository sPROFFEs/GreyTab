"""Read static Java class references from an extension archive without loading it."""

from io import BytesIO
import re
from struct import Struct, error as StructError
from zipfile import BadZipFile, ZIP_DEFLATED, ZIP_STORED, ZipFile
from zlib import error as DeflateError

MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 10_000
MAX_CLASS_BYTES = 512 * 1024
MAX_CLASS_TOTAL = 24 * 1024 * 1024
SUPPORTED_COMPRESSION = {ZIP_STORED, ZIP_DEFLATED}

U2 = Struct('>H')
PAIR = Struct('>HH')
CLASS_HEADER = Struct('>IHHH')
UI_OWNERS = {'burp/api/montoya/ui/UserInterface', 'burp/IBurpExtenderCallbacks'}
UI_METHODS = {
    'registerSuiteTab': 'workspace_tab',
    'addSuiteTab': 'workspace_tab',
    'registerHttpRequestEditorProvider': 'request_editor',
    'registerHttpResponseEditorProvider': 'response_editor',
    'registerMessageEditorTabFactory': 'http_editor',
    'registerWebSocketMessageEditorProvider': 'websocket_editor',
    'registerContextMenuItemsProvider': 'context_menu',
    'registerContextMenuFactory': 'context_menu',
    'registerSettingsPanel': 'settings_panel',
    'registerHotKeyHandler': 'hotkey',
    'applyThemeToComponent': 'theme',
    'customizeUiComponent': 'theme',
    'menuBar': 'menu_bar',
}
UI_FRAMEWORKS = {'java/awt/': 'AWT', 'javax/swing/': 'Swing', 'javafx/': 'JavaFX', 'org/eclipse/swt/': 'SWT'}
DESCRIPTOR_TYPE = re.compile(r'L([A-Za-z0-9_$/]+)')
MONTOYA_PACKAGE = re.compile(r'burp/api/montoya/([A-Za-z][A-Za-z0-9_]{0,39})/')


def _class_references(data):
    magic, _, _, count = CLASS_HEADER.unpack_from(data)
    if magic != 0xCAFEBABE or count < 1:
        raise ValueError('Invalid Java class header')

    position = CLASS_HEADER.size
    index = 1
    strings, classes, name_types, methods = {}, {}, {}, []
    fixed_lengths = {3: 4, 4: 4, 5: 8, 6: 8, 8: 2, 9: 4, 15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2}
    while index < count:
        tag = data[position]
        position += 1
        if tag == 1:
            length, = U2.unpack_from(data, position)
            position += U2.size
            strings[index] = data[position:position + length].decode('utf-8', errors='replace')
        elif tag == 7:
            classes[index], = U2.unpack_from(data, position)
            length = U2.size
        elif tag in {10, 11, 12}:
            pair = PAIR.unpack_from(data, position)
            if tag == 12:
                name_types[index] = pair
            else:
                methods.append(pair)
            length = PAIR.size
        else:
            length = fixed_lengths[tag]
        position += length
        index += 2 if tag in {5, 6} else 1

    # The fixed declaration fields follow the constant pool, even for interfaces.
    if position + 8 > len(data) or index != count:
        raise ValueError('Truncated Java class')
    class_names = {index: strings[name] for index, name in classes.items()}
    referenced_types = set(class_names.values())
    for _, descriptor in name_types.values():
        referenced_types.update(DESCRIPTOR_TYPE.findall(strings[descriptor]))
    for name in tuple(referenced_types):
        if name.startswith('['):
            referenced_types.update(DESCRIPTOR_TYPE.findall(name))
    referenced_ui = {
        strings[name_types[signature][0]] for owner, signature in methods if class_names[owner] in UI_OWNERS
    }
    return referenced_types, referenced_ui


def _archive_entries(archive):
    entries = archive.infolist()
    if len(entries) > MAX_ARCHIVE_ENTRIES:
        raise ValueError(f'Archive contains more than {MAX_ARCHIVE_ENTRIES:,} entries.')
    return entries


def _bapp_jar(archive, entries, manifest):
    if manifest.file_size > 8192 or manifest.compress_type not in SUPPORTED_COMPRESSION:
        raise ValueError('The BApp manifest exceeds the inspection limits.')
    try:
        fields = archive.read(manifest).decode('utf-8-sig').splitlines()
    except UnicodeDecodeError as error:
        raise ValueError('The BApp manifest is not valid UTF-8.') from error
    paths = [line.partition(':')[2].strip() for line in fields if line.startswith('EntryPoint:')]
    if len(paths) != 1 or not paths[0].lower().endswith('.jar'):
        raise ValueError('This BApp must declare exactly one Java JAR entry point.')
    binaries = [entry for entry in entries if entry.filename == paths[0]]
    if len(binaries) != 1:
        raise ValueError('The JAR declared by the BApp is missing or ambiguous.')
    jar = binaries[0]
    if jar.file_size > MAX_ARCHIVE_BYTES or jar.compress_type not in SUPPORTED_COMPRESSION:
        raise ValueError('The JAR declared by the BApp exceeds the inspection limits.')
    return jar


def _inspect_class_entries(archive, entries):
    types, ui_methods, seen_classes = set(), set(), set()
    skipped = scanned = bundled_api = total_size = nested_archives = 0
    for entry in entries:
        if entry.filename.lower().endswith(('.jar', '.zip')):
            nested_archives += 1
        if not entry.filename.endswith('.class'):
            continue
        if entry.filename.startswith('burp/api/montoya/'):
            bundled_api += 1
            continue
        if (entry.filename in seen_classes or entry.file_size > MAX_CLASS_BYTES or
                total_size + entry.file_size > MAX_CLASS_TOTAL or
                entry.compress_type not in SUPPORTED_COMPRESSION):
            skipped += 1
            continue
        seen_classes.add(entry.filename)
        total_size += entry.file_size
        try:
            class_types, class_ui = _class_references(archive.read(entry))
        except (BadZipFile, DeflateError, EOFError, IndexError, KeyError, OSError, RuntimeError, StructError, ValueError):
            skipped += 1
            continue
        scanned += 1
        types.update(class_types)
        ui_methods.update(class_ui)

    montoya = any(name.startswith('burp/api/montoya/') for name in types)
    packages = sorted({match[1] for name in types if (match := MONTOYA_PACKAGE.match(name))})[:30]
    legacy = any(re.fullmatch(r'burp/I[A-Z][A-Za-z0-9_]*', name) for name in types)
    return {
        'classes': {'scanned': scanned, 'skipped': skipped, 'bundled_api': bundled_api},
        'nested_archives': nested_archives,
        'apis': (['Montoya'] if montoya else []) + (['Legacy Extender'] if legacy else []),
        'montoya_packages': packages,
        'ui_contributions': sorted({UI_METHODS[method] for method in ui_methods if method in UI_METHODS}),
        'ui_frameworks': sorted({label for prefix, label in UI_FRAMEWORKS.items() if any(name.startswith(prefix) for name in types)}),
    }


def inspect_burp_archive(data):
    """Return evidence for a compatibility report, with explicit coverage limits."""
    try:
        with ZipFile(BytesIO(data)) as archive:
            entries = _archive_entries(archive)
            manifests = [entry for entry in entries if entry.filename == 'BappManifest.bmf']
            if not manifests:
                return _inspect_class_entries(archive, entries)
            if len(manifests) != 1:
                raise ValueError('The BApp contains multiple manifests.')
            jar = _bapp_jar(archive, entries, manifests[0])
            with ZipFile(BytesIO(archive.read(jar))) as inner:
                report = _inspect_class_entries(inner, _archive_entries(inner))
            report['bapp_entry_point'] = jar.filename[:240]
            report['nested_archives'] += sum(1 for entry in entries if entry != jar and entry.filename.lower().endswith(('.jar', '.zip')))
            return report
    except (BadZipFile, DeflateError, EOFError, OSError, RuntimeError, StructError) as error:
        raise ValueError('Select a valid Java JAR, BApp or ZIP archive.') from error
