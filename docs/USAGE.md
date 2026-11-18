# Using GreyTab

Create a session with a name and optional comma-separated domain scope. Domains match the host and its subdomains; they are domain names, not URL keywords. Resume previous sessions from the landing screen. Switching sessions resets the active scope; stop an active scan before switching.

## Proxy and History

Browse the target through the launched Chromium. HTTP, HTTPS and WebSocket traffic is captured for the active session. GreyTab's own API traffic bypasses capture. Scope and exclusions control interception, rules and logging.

Enable request and/or response interception in Proxy. Select a queued message, edit its raw text and Forward or Drop it. Turning a toggle off releases its pending messages. Queues can be recovered after reopening the panel. Detached scanner windows observe interception and do not forward the main panel's messages.

History searches recorded URLs and notes across the active session. Use host, method, status, content type and annotation filters together, then move between pages with Newer and Older. Each page contains at most 200 requests. Regex on page applies a case-insensitive pattern to URLs on the current page and reports invalid or slow patterns. Pause stops the visible list from advancing while the proxy continues to record. Refresh returns to the latest results.

Select a row to read the request and response. Copy message copies the captured text for the current view, and Wrap controls line wrapping. Inspect shows connection details, decoded query and form fields, and captured headers. Save notes and highlights directly in the inspector. Use the row menu or right-click for actions and code exports. Site Map groups recent traffic by host and path and opens the matching history when you select a path.

Keyboard shortcuts: Ctrl+R sends the selected request to Repeater, Ctrl+I to Intruder, Ctrl+F focuses History search, and j/k move between visible History rows. The browser's extension keyboard shortcut can be configured at `chrome://extensions/shortcuts`.

## Repeater

Send a request from History or create a tab. The Destination field preserves HTTP versus HTTPS and the target port. Edit the request line, headers and body; Send recalculates Content-Length. Set a destination explicitly for a hand-written origin-form request. HTTP Host remains editable for virtual-host tests.

Tabs keep their own requests and responses. A response arriving after you switch tabs updates the original tab. Diff compares the last two sends of that tab. Render shows a sandboxed static preview with scripts and remote resources blocked; use Raw to inspect complete captured text. Redirect following is explicit. Independent sends do not inherit cookies from earlier sends; include the Cookie header you intend to test.

## Intruder

Send a request from History, select text and Mark Selection to surround insertion points with `§`. Auto detects common parameters. Choose a list, numeric range or wordlist. Numbers need a positive step and an ascending range.

- Sniper changes each marked position independently.
- Battering Ram inserts the same payload in every position.
- Pitchfork zips lists by row; separate lists with a blank line.
- Cluster Bomb combines lists as a Cartesian product.

For Pitchfork and Cluster Bomb, each position uses its corresponding list; if fewer lists exist, the last list is reused. Wordlist/numeric modes reuse their one list. Threads are limited to 20. Optional grep extraction shows the first captured regex group, or the full match if there is no group. Stop prevents further scheduling and waits for in-flight requests to settle. Results retain a response preview.

## AutoScanner

Set a URL and select the test families. Enable crawling to discover same-host links and forms; disable it to test the seed without crawling. The History lightning button tests actual captured query/form/JSON parameters, including nested JSON, without creating a crawler. The captured request's method, authentication and other fields are retained.

Authenticated mode reads browser cookies for the target. A saved Login Macro can run before a scan; its configured injected header applies to the matching target host. XSS headless confirmation attempts a real DOM execution check using the installed Chromium. OAST needs a callback endpoint reachable by the target; loopback alone cannot receive remote callbacks. Select findings and attempts to inspect their evidence, replay them or send them to installed tools. Manual findings are saved in the report database.

Detectors use heuristics and confirmation probes. Review evidence and validate findings; passing software tests is not a measurement of real-world detection coverage. See [lab regression](../regression/README.md).

## Utilities

Race Tester takes the selected History request or a Repeater tab and sends 2–100 requests concurrently, displaying status/length distributions and durations. This is parallel replay, without packet-level or last-byte synchronization.

WebSocket Traffic lists up to 500 recent frames, supports a URL/content filter and displays individual frame contents. Frames are inspection-only.

Login Macros can be assembled from selected History requests. Save an ordered JSON array of steps with `method`, `url`, `headers`, `body`, optional `extract` and `extract_kind` (`regex` or `header`). Captures become `{variable}` substitutions in following steps. For example:

```json
[
  {
    "method": "POST",
    "url": "https://target.example/login",
    "headers": {"Content-Type": "application/json"},
    "body": "{\"username\":\"tester\",\"password\":\"example\"}",
    "extract": {"token": "\"access_token\":\\s*\"([^\"]+)\""},
    "extract_kind": "regex"
  }
]
```

Set Inject Header to `Authorization` and Template to `Bearer {token}` to use the capture. Test with Run; select the macro in AutoScanner for a fresh login before scanning. Macro storage contains supplied credentials locally.

GraphQL Explorer loads the selected request's URL and headers and sends an introspection query. Authentication requirements and servers that disable introspection appear in the returned response.

## Tools, Decoder and Bookmarklets

Tools reports installed executables and lists project/system wordlists. Install external tools separately; GreyTab does not silently install scanners such as sqlmap or nuclei. Custom Tools in Settings define executable names and argument templates. The raw command field runs an intentional shell command. Tool terminals fetch output incrementally and recover if opened after a short command has already finished. Cancellation terminates the tool process group.

Decoder supports Unicode text, encodings and hashes. JWT decoding does not verify signatures. HMAC rebuilding supports HS256/384/512 with a supplied key; `alg=none` produces an empty signature. Generated tokens are testing artifacts.

Bookmarklets execute on the active HTTP(S) tab. Smart Reveal restores modified field/visibility state on a second run. Custom snippets run in the page's main world; strict target CSP may block evaluated snippets, in which case GreyTab reports the error. OSINT launchers open third-party sites after user action.

## Settings and AI

Match & Replace edits request/response headers, text bodies and supported request/status fields. Rules can have host filters and regex replacements. Invalid regexes are rejected. Unchanged repeated headers, including Set-Cookie, are retained.

Token Watcher captures configured response-body/cookie values and injects a header into subsequent proxy requests to the same captured hostname. It does not inject that token into other hosts.

AI is optional and disabled by default. Configure provider, endpoint, model and key under Settings → AI Agent Integration. Supported adapters: OpenAI, Anthropic, Gemini, Ollama and custom endpoints. Explain, diff, payload suggestion and triage send the selected audit evidence to that configured endpoint. Keys are masked in API settings responses and stored in a private local configuration file. Live provider availability depends on your account and model.

## Limits

- Linux x86_64 only; the pinned Chromium was validated locally and through CI, not on every Linux distribution.
- History renders up to 200 requests per page. Literal URL and note search and the structured filters cover the session. Regex applies to the current page. Site Map summarizes the 20,000 most recent requests. REST log export can retrieve up to 50,000 entries with `offset` pagination.
- Captured textual request/response bodies and Repeater previews are limited to 1 MiB. Binary data is not an exact editable/replayable message format. The sandboxed preview is static.
- `.pbx` saves up to 50,000 HTTP requests and 5,000 WebSocket frames/tool runs. The UI HAR export defaults to 5,000; the API supports a `limit` up to 50,000. These exports are bounded snapshots rather than unlimited backups of SQLite.
- Intruder caps attacks at 5,000 requests, 20 workers and 16 KiB retained response previews per result. Closing the panel stops its scheduling. Already-sent requests may still complete.
- Scanner backend retains 25,000 attempts; the UI retains 2,000 attempts and renders 500 recent attempt/request rows. XSS confirmation depends on OS Chromium support.
- Workspace storage restores bounded recent results; saved projects and SQLite are the durable record. External tool terminal display retains the latest 200,000 characters; SQLite keeps recorded output.
- WebSockets support inspection, not interactive interception/replay. There is no Collaborator hosting service, Burp extension compatibility, HTTP/2 raw frame editor or last-byte race synchronization.
- Third-party OSINT sites, paid AI services and vulnerability coverage against external lab installations are not certified by the local regression suite.
