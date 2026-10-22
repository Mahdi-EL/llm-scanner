// LLM Scanner for VS Code: finds the system prompt in the open file, scans it
// with your LLM Scanner API, and shows the result next to the code.
//
// Setup: run "LLM Scanner: Set API Key" (the key is kept in VS Code's encrypted
// secret storage) and set llmscanner.apiUrl to your API.
const vscode = require('vscode');
const path   = require('path');

const SECRET_KEY = 'llmscanner.apiKey';
let lastScanId = null;

// ── Decorations ───────────────────────────────────────────────
const decorations = {
    CRITICAL: vscode.window.createTextEditorDecorationType({
        backgroundColor: 'rgba(180, 35, 24, 0.15)', border: '1px solid rgba(180, 35, 24, 0.7)',
        overviewRulerColor: 'rgba(180, 35, 24, 0.8)', overviewRulerLane: vscode.OverviewRulerLane.Right,
        after: { contentText: '  LLM Scanner: critical findings', color: 'rgba(180, 35, 24, 1)', fontWeight: 'bold' },
    }),
    HIGH: vscode.window.createTextEditorDecorationType({
        backgroundColor: 'rgba(196, 50, 10, 0.12)', border: '1px solid rgba(196, 50, 10, 0.6)',
        after: { contentText: '  LLM Scanner: high findings', color: 'rgba(196, 50, 10, 1)' },
    }),
    MEDIUM: vscode.window.createTextEditorDecorationType({
        backgroundColor: 'rgba(161, 92, 7, 0.1)', border: '1px solid rgba(161, 92, 7, 0.5)',
        after: { contentText: '  LLM Scanner: medium findings', color: 'rgba(161, 92, 7, 1)' },
    }),
};

// ── Find system prompts in a file ─────────────────────────────
function extractSystemPrompts(text) {
    const found = [];
    const add = (value, index) => {
        const clean = value.trim();
        if (clean.length > 10 && !found.some(p => p.text === clean)) {
            found.push({ text: clean, line: text.slice(0, index).split('\n').length - 1 });
        }
    };
    const patterns = [
        /system_prompt\s*=\s*"""([\s\S]*?)"""/gi,
        /system_prompt\s*=\s*'''([\s\S]*?)'''/gi,
        /system_?prompt\s*[=:]\s*`([\s\S]*?)`/gi,
        /system_?prompt\s*[=:]\s*"([^"\n]+)"/gi,
        /system_?prompt\s*[=:]\s*'([^'\n]+)'/gi,
        /"role"\s*:\s*"system"\s*,\s*"content"\s*:\s*"([^"]+)"/g,
        /role\s*:\s*['"]system['"]\s*,\s*content\s*:\s*['"`]([^'"`]+)['"`]/g,
    ];
    for (const pattern of patterns) {
        for (const match of text.matchAll(pattern)) add(match[1], match.index);
    }
    return found;
}

// ── API ───────────────────────────────────────────────────────
function settings() {
    const config = vscode.workspace.getConfiguration('llmscanner');
    return {
        apiUrl    : (config.get('apiUrl') || 'http://localhost:8000').replace(/\/+$/, ''),
        appUrl    : (config.get('appUrl') || '').replace(/\/+$/, ''),
        categories: config.get('categories') || [],
        quickScan : config.get('quickScan') !== false,
    };
}

const MAX_PROMPT = 20000;   // the API's limit for system_prompt

// FastAPI sends a string for most errors and a list of {loc, msg} for invalid input.
function errorDetail(data, status) {
    if (typeof data.detail === 'string') return data.detail;
    if (Array.isArray(data.detail) && data.detail.length) {
        return data.detail.map(d => d.msg || String(d)).join('; ');
    }
    return `HTTP ${status}`;
}

async function api(context, method, route, body) {
    const key = await context.secrets.get(SECRET_KEY);
    if (!key) throw new Error('No API key. Run "LLM Scanner: Set API Key" first.');
    const { apiUrl } = settings();
    let response;
    try {
        response = await fetch(`${apiUrl}${route}`, {
            method,
            headers: { 'Content-Type': 'application/json', 'X-API-Key': key },
            body: body ? JSON.stringify(body) : undefined,
        });
    } catch (e) {
        throw apiError(`Can't reach ${apiUrl} (${e.message}). Check llmscanner.apiUrl.`, 0);
    }
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
        if (response.status === 401) throw apiError('API key rejected. Run "LLM Scanner: Set API Key".', 401);
        const detail = errorDetail(data, response.status);
        throw apiError(response.status === 402 && /quick scan/i.test(detail)
            ? `${detail} (turn on the llmscanner.quickScan setting)` : detail, response.status);
    }
    return data;
}

// status 0: the API couldn't be reached
function apiError(message, status) {
    return Object.assign(new Error(message), { status });
}

// A poll may fail this many times in a row (the API restarting, a 502 from its proxy) before the
// scan is reported as failed: the scan itself resumes after a restart.
const POLL_RETRIES = 6;
const passing = e => e.status === 0 || e.status === 429 || e.status >= 500;

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function waitForScan(context, scanId, progress, token, delay = 3000) {
    let lastPct = 0, failures = 0;
    for (;;) {
        if (token.isCancellationRequested) {
            await api(context, 'POST', `/scan/${scanId}/cancel`).catch(() => {});
            throw new Error('Scan cancelled');
        }
        let scan;
        try {
            scan = await api(context, 'GET', `/scan/${scanId}`);
            failures = 0;
        } catch (e) {
            if (!passing(e) || ++failures > POLL_RETRIES) throw e;
            progress.report({ message: 'waiting for the API…' });
            await sleep(delay * failures);
            continue;
        }
        if (scan.status === 'complete') return scan;
        if (scan.status === 'failed' || scan.status === 'cancelled') {
            throw new Error(scan.error_message || `Scan ${scan.status}`);
        }
        const pct = scan.progress || 0;
        progress.report({
            increment: Math.max(0, pct - lastPct),
            message: scan.status === 'pending' ? 'queued…' : `${scan.completed_attacks}/${scan.total_attacks} attacks`,
        });
        lastPct = pct;
        await sleep(delay);
    }
}

// ── Results panel (no scripts; everything escaped) ────────────
const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, ch =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));

function showResultsPanel(scan, title) {
    const panel = vscode.window.createWebviewPanel('llmScannerResults', `LLM Scanner: ${title}`,
        vscode.ViewColumn.Beside, { enableScripts: false });
    const summary  = { ...(scan.summary || {}), ...(scan.results?.summary || {}) };
    const findings = (scan.results?.results || []).filter(r => !['SAFE', 'ERROR'].includes(r.severity));
    const colors   = { CRITICAL: '#b42318', HIGH: '#c4320a', MEDIUM: '#a15c07', LOW: '#4b6b2f' };
    const rows = findings.slice(0, 50).map(r => `
        <details>
          <summary><b style="color:${colors[r.severity] || '#888'}">${escapeHtml(r.severity)}</b>
            ${escapeHtml((r.category || '').replace(/_/g, ' '))} · ${escapeHtml(r.score)}/10</summary>
          <p><b>Attack</b></p><pre>${escapeHtml(r.attack)}</pre>
          <p><b>Reply</b></p><pre>${escapeHtml(r.response)}</pre>
          <p>${escapeHtml(r.reason)}</p>
        </details>`).join('');
    const recs = (scan.recommendations || []).slice(0, 5).map(r =>
        `<li><b>${escapeHtml(r.priority)} ${escapeHtml(r.title)}</b>: ${escapeHtml(r.fix[0] || '')}</li>`).join('');

    panel.webview.html = `<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
<style>
  body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 16px 20px; }
  .score { font-size: 44px; font-family: Georgia, serif; }
  pre { white-space: pre-wrap; word-break: break-word; background: var(--vscode-textCodeBlock-background); padding: 8px; }
  details { border-bottom: 1px solid var(--vscode-panel-border); padding: 6px 0; }
  summary { cursor: pointer; }
</style></head>
<body>
  <h2>${escapeHtml(scan.target_name)}</h2>
  <div class="score">${escapeHtml(summary.security_score ?? 0)}/100 · grade ${escapeHtml(summary.grade || '?')}</div>
  <p>${escapeHtml(summary.critical || 0)} critical · ${escapeHtml(summary.high || 0)} high ·
     ${escapeHtml(summary.medium || 0)} medium · ${escapeHtml(summary.low || 0)} low · ${escapeHtml(summary.safe || 0)} safe</p>
  ${recs ? `<h3>What to fix first</h3><ul>${recs}</ul>` : ''}
  <h3>Failed attacks (${findings.length})</h3>
  ${rows || '<p>No attack succeeded.</p>'}
</body></html>`;
}

function decorate(editor, prompt, summary) {
    Object.values(decorations).forEach(d => editor.setDecorations(d, []));
    const worst = summary.critical ? 'CRITICAL' : summary.high ? 'HIGH' : summary.medium ? 'MEDIUM' : null;
    if (!worst) return;
    const line = Math.min(prompt.line, editor.document.lineCount - 1);
    editor.setDecorations(decorations[worst], [{
        range: editor.document.lineAt(line).range,
        hoverMessage: `LLM Scanner: ${summary.critical || 0} critical, ${summary.high || 0} high findings. ` +
                      `Score ${summary.security_score}/100.`,
    }]);
}

// ── Commands ──────────────────────────────────────────────────
async function runScan(context, editor, promptText, promptInfo) {
    const name = path.basename(editor.document.fileName);
    const { categories, quickScan } = settings();
    if (promptText.length > MAX_PROMPT) {
        vscode.window.showErrorMessage(`LLM Scanner: this prompt has ${promptText.length.toLocaleString()} characters; ` +
            `the limit is ${MAX_PROMPT.toLocaleString()}.`);
        return;
    }
    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification, title: `LLM Scanner: ${name}${quickScan ? ' (quick scan)' : ''}`, cancellable: true,
    }, async (progress, token) => {
        try {
            const body = { target_name: name, target_type: 'simulation', system_prompt: promptText, quick: quickScan };
            if (categories.length) body.categories = categories;
            const started = await api(context, 'POST', '/scan', body);
            lastScanId = started.scan_id;
            const scan = await waitForScan(context, started.scan_id, progress, token);
            const summary = { ...(scan.summary || {}), ...(scan.results?.summary || {}) };
            if (promptInfo) decorate(editor, promptInfo, summary);
            showResultsPanel(scan, name);
            vscode.window.showInformationMessage(
                `LLM Scanner: ${summary.security_score}/100 (grade ${summary.grade}) for ${name}`);
        } catch (e) {
            vscode.window.showErrorMessage(`LLM Scanner: ${e.message}`);
        }
    });
}

async function scanFile(context, editor) {
    if (!editor) { vscode.window.showErrorMessage('Open a file first.'); return; }
    const prompts = extractSystemPrompts(editor.document.getText());
    if (!prompts.length) {
        vscode.window.showInformationMessage('No system prompt found. Select the prompt text and run "Scan Selected Text".');
        return;
    }
    let chosen = prompts[0];
    if (prompts.length > 1) {
        const pick = await vscode.window.showQuickPick(
            prompts.map(p => ({ label: p.text.slice(0, 80), description: `line ${p.line + 1}`, prompt: p })),
            { placeHolder: 'Which system prompt should be scanned?' });
        if (!pick) return;
        chosen = pick.prompt;
    }
    await runScan(context, editor, chosen.text, chosen);
}

function activate(context) {
    context.subscriptions.push(
        vscode.commands.registerCommand('llmscanner.setApiKey', async () => {
            const key = await vscode.window.showInputBox({
                prompt: 'LLM Scanner API key (create one in Settings → API keys)', password: true,
                ignoreFocusOut: true, validateInput: v => v && v.startsWith('llmsk_') ? null : 'Keys start with llmsk_',
            });
            if (key) { await context.secrets.store(SECRET_KEY, key); vscode.window.showInformationMessage('LLM Scanner: API key saved.'); }
        }),
        vscode.commands.registerCommand('llmscanner.scanFile', () => scanFile(context, vscode.window.activeTextEditor)),
        vscode.commands.registerCommand('llmscanner.scanPrompt', async () => {
            const editor = vscode.window.activeTextEditor;
            const selection = editor && editor.document.getText(editor.selection);
            if (!selection || selection.trim().length < 10) { vscode.window.showErrorMessage('Select the system prompt text first.'); return; }
            await runScan(context, editor, selection, { line: editor.selection.start.line });
        }),
        vscode.commands.registerCommand('llmscanner.showReport', () => {
            const { appUrl } = settings();
            if (!lastScanId) { vscode.window.showInformationMessage('Run a scan first.'); return; }
            if (!appUrl) { vscode.window.showInformationMessage(`Last scan: ${lastScanId}. Set llmscanner.appUrl to open it in the browser.`); return; }
            vscode.env.openExternal(vscode.Uri.parse(`${appUrl}/results/${lastScanId}`));
        }),
        vscode.workspace.onDidSaveTextDocument(doc => {
            const editor = vscode.window.activeTextEditor;
            if (vscode.workspace.getConfiguration('llmscanner').get('autoScan') && editor && editor.document === doc) {
                scanFile(context, editor);
            }
        }),
    );

    const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBar.text = '$(shield) LLM Scanner';
    statusBar.tooltip = 'Scan the system prompt in this file';
    statusBar.command = 'llmscanner.scanFile';
    statusBar.show();
    context.subscriptions.push(statusBar);
}

function deactivate() {}

module.exports = { activate, deactivate, extractSystemPrompts, escapeHtml, errorDetail, waitForScan };
