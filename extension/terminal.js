const urlParams = new URL(window.location.href).searchParams;
const runId = urlParams.get('runId');
const toolName = urlParams.get('toolName');
const toolTarget = urlParams.get('target');

const dom = {
    header: document.getElementById('header'),
    toolName: document.getElementById('tool-name'),
    statusBadge: document.getElementById('status-badge'),
    terminalOutput: document.getElementById('terminal-output'),
};

dom.toolName.textContent = `${toolName || 'Tool'} Execution`;
if (toolTarget) {
    dom.toolName.textContent += ` - ${toolTarget}`;
}

const ws = new WebSocket('ws://127.0.0.1:8443/ws');

async function loadInitialRunOutput() {
    if (!runId) return;
    try {
        const res = await fetch(`http://127.0.0.1:8443/api/tools/${encodeURIComponent(runId)}`);
        if (!res.ok) return;
        const run = await res.json();
        if (run && typeof run.output === 'string' && run.output.trim()) {
            appendOutput(run.output.replace(/\r/g, '').replace(/\n$/, ''));
        }
        if (run && run.status && run.status !== 'running') {
            const exit = Number.isFinite(Number(run.exit_code)) ? Number(run.exit_code) : -1;
            const durationMs = Number.isFinite(Number(run.duration_ms)) ? Number(run.duration_ms) : 0;
            handleCompletion({ exit_code: exit, duration_ms: durationMs });
        }
    } catch (e) {
        console.warn('Failed to load initial tool output:', e);
    }
}

ws.onopen = () => {
    dom.statusBadge.textContent = 'Connected';
    dom.statusBadge.className = 'status-running';
    // Send hello to register connection (although backend handles it automatically for now)
    ws.send(JSON.stringify({ type: 'hello', source: 'terminal', run_id: runId }));
};

loadInitialRunOutput();

ws.onmessage = (event) => {
    try {
        const msg = JSON.parse(event.data);
        const { type, data } = msg;

        // Ensure we only process messages for this run ID
        if (data && data.run_id && String(data.run_id) !== String(runId)) return;

        switch (type) {
            case 'tool_output':
                appendOutput(data.line);
                break;
            case 'tool_complete':
                handleCompletion(data);
                break;
            case 'tool_started':
                // Initial output might come here too
                dom.statusBadge.textContent = 'Running';
                break;
        }
    } catch (e) {
        console.error('Error parsing WS message:', e);
    }
};

ws.onclose = () => {
    dom.statusBadge.textContent = 'Disconnected';
    dom.statusBadge.className = 'status-error';
};

function appendOutput(text) {
    // Simple text handling for now - could add ANSI processing here later
    const span = document.createElement('span');
    span.textContent = text + '\n';
    dom.terminalOutput.appendChild(span);

    // Auto-scroll
    window.scrollTo(0, document.body.scrollHeight);
}

function handleCompletion(data) {
    const isSuccess = data.exit_code === 0;
    dom.statusBadge.textContent = isSuccess ? 'Completed' : `Failed (Exit: ${data.exit_code})`;
    dom.statusBadge.className = isSuccess ? 'status-success' : 'status-error';

    // Add a final line
    appendOutput(`\n----------------------------------------\nProcess finished with exit code ${data.exit_code}\nDuration: ${(data.duration_ms / 1000).toFixed(2)}s`);
}
