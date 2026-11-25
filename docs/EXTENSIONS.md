# Extensions

The Extensions view in the development checkout provides a catalog, a Burp archive inspector and a manager for native GreyTab view packs. They are available in the desktop workspace and the side panel after opening a session. The features use the existing Linux installation and runtime.

## Browse the catalog

Open **Extensions** → **Catalog**. Search by name or feature and use **Source** to narrow the results to native view packs or BApp listings. **Install** adds a version bundled with GreyTab. **Manage** opens the installed pack, where you can enable, disable or remove it. Catalog metadata is bundled and works offline. **View on BApp Store** opens the relevant PortSwigger page in a browser tab.

The catalog lists [JQ 1.2](https://portswigger.net/bappstore/c0d90a42c99848588d3df017cca717b5) and [Copy Request Response 2.4.0](https://portswigger.net/bappstore/0d05f52c00a64cb2b2bea68744f6316c) as Burp listings. To inspect either package, download it from its official page and select the downloaded archive in **Burp compatibility**. Native installation is available for **JSON Inspector** and **HTTP Exchange Export**.

## Inspect a Burp extension

Select a `.jar`, `.bapp` or `.zip` in **Extensions** → **Burp compatibility**, then select **Inspect archive**. For a BApp, GreyTab reads the Java JAR named by its manifest. The report lists detected Montoya or legacy Extender references, interface contributions such as suite tabs and custom editors, Java UI frameworks, and skipped classes. Archives are analyzed in memory from Java class references. Reflection and behavior registered dynamically may be absent from the report. The report cannot establish runtime compatibility or verify BApp signatures.

Burp extensions depend on the host's APIs. Montoya's UI registration methods accept Java components, including Swing components. GreyTab needs native ports of those views. The archive inspector reads Java bytecode as data. Running Burp extensions, including their menus, shortcuts, Java settings panels and traffic callbacks, falls outside the inspector's scope. See [Montoya UserInterface](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/ui/UserInterface.html).

The inspector processed both catalog BApps. JQ referenced a legacy HTTP message editor using AWT and Swing. Copy Request Response referenced Montoya context menus, shortcuts and a settings panel. These checks cover archive reporting. GreyTab's JSON Inspector provides formatting and HTTP Exchange Export provides the full-message and headers-only clipboard workflows in History.

## Install a native view pack

Install **JSON Inspector** from the catalog or import the [example manifest](examples/json-inspector.json) from **Installed**. It adds **Readable JSON** to the offline workspace, the History and Repeater response viewers, and the History row menu. Open a viewer's **Extensions** tab and select the new view, or use the row menu in History to open it directly. The built-in **Message views** pack also offers **Format JSON** and **HTTP headers**.

Install **HTTP Exchange Export**, open a captured History row's menu and choose **Request and response** or **Request and response headers**. Review the result in the exchange viewer and select **Copy view**. The view uses the captured messages displayed by History, including its recorded body preview and size limits.

A view pack is a JSON manifest. The fields in the example are required. `id` values use lowercase letters, digits, dots and hyphens, begin with a letter and have 2–48 characters. Each pack has 1–4 views and the view IDs must be unique within that pack. Installing a pack with the same ID updates it and preserves its enabled state. Enable, disable and remove packs from either window. Changes apply to both windows. The application stores only the pack definitions and enabled states. Messages processed in the offline workspace stay in that view until cleared or the page closes.

| Operation | What it displays |
| --- | --- |
| `json-format` | Original JSON tokens with indentation, including duplicate keys and the original number spellings. |
| `http-headers` | The raw HTTP start line and headers, in source order. |
| `http-exchange` | The captured request and response, with their available bodies. |
| `http-exchange-headers` | The start lines and headers of both messages. |

| Placement | Where it appears |
| --- | --- |
| `workspace` | **Extensions** → **Offline message views**, using pasted text. |
| `history-request` | History → exchange → **Extensions** → **Request**. |
| `history-response` | History → exchange → **Extensions** → **Response**. |
| `repeater-response` | Repeater → response → **Extensions**. |
| `history-exchange` | History → exchange → **Extensions** → **Exchange**. This placement uses the two exchange operations. |
| `history-menu` | History row menu → **Extensions**. This action opens the associated response or exchange view. At most six such actions appear. |

Views display text and leave captured requests and responses unchanged. Pack definitions select built-in operations and placements. Limits are 8 imported packs, 32 KiB per pack file, 65,536 input characters and 262,144 output characters per view. Archive inspection supports up to 16 MiB per upload, 10,000 entries per archive, 512 KiB per class and 24 MiB of class data per report. The BApp entry JAR is the only nested archive read.
