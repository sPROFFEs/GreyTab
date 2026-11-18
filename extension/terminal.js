// Incremental snapshots recover output even when the tab opens after a short tool finishes.
const params = new URL(location.href).searchParams;
const runId = params.get('runId');
const name = params.get('toolName') || 'Tool';
const target = params.get('target') || '';
const output = document.getElementById('terminal-output');
const badge = document.getElementById('status-badge');
document.getElementById('tool-name').textContent = `${name} Execution${target ? ' — ' + target : ''}`;
let offset = 0;
let tail = '';
let stopped = false;
function append(text) {
    tail = (tail + text.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '')).slice(-200000);
    output.textContent = tail;
    window.scrollTo(0, document.body.scrollHeight);
}
async function poll() {
    if (!runId || stopped) return;
    let nextDelay = 1000;
    try {
        const response = await fetch(`http://127.0.0.1:8443/api/tools/${encodeURIComponent(runId)}?output_offset=${offset}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const run = await response.json();
        if (run.output) {
            append(run.output);
            // Backend offsets count Unicode code points, not UTF-16 code units.
            offset += Array.from(run.output).length;
        }
        badge.textContent = 'Running'; badge.className = 'status-running';
        if (offset < run.output_length) nextDelay = 0;
        else if (run.status !== 'running') {
            stopped = true;
            badge.textContent = run.exit_code === 0 ? 'Completed' : `Failed (exit ${run.exit_code})`;
            badge.className = run.exit_code === 0 ? 'status-success' : 'status-error';
            append(`\nProcess finished with exit code ${run.exit_code}\nDuration: ${(Number(run.duration_ms || 0) / 1000).toFixed(2)}s\n`);
        }
    } catch (e) {
        badge.textContent = `Reconnecting: ${e.message}`;
        badge.className = 'status-error';
        nextDelay = 3000;
    }
    if (!stopped) setTimeout(poll, nextDelay);
}
poll();
