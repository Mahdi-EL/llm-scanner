const vscode = require('vscode');
const https  = require('http');
const path   = require('path');

// ── Vulnerability decorations ─────────────────────────────────
const criticalDecoration = vscode.window.createTextEditorDecorationType({
    backgroundColor : 'rgba(192, 57, 43, 0.2)',
    border          : '1px solid rgba(192, 57, 43, 0.8)',
    borderRadius    : '3px',
    overviewRulerColor: 'rgba(192, 57, 43, 0.8)',
    overviewRulerLane : vscode.OverviewRulerLane.Right,
    after: {
        contentText : ' 🚨 CRITICAL',
        color       : 'rgba(192, 57, 43, 1)',
        fontWeight  : 'bold',
        fontSize    : '11px'
    }
});

const highDecoration = vscode.window.createTextEditorDecorationType({
    backgroundColor : 'rgba(230, 126, 34, 0.2)',
    border          : '1px solid rgba(230, 126, 34, 0.8)',
    borderRadius    : '3px',
    after: {
        contentText : ' 🔴 HIGH',
        color       : 'rgba(230, 126, 34, 1)',
        fontWeight  : 'bold',
        fontSize    : '11px'
    }
});

const mediumDecoration = vscode.window.createTextEditorDecorationType({
    backgroundColor : 'rgba(241, 196, 15, 0.15)',
    border          : '1px solid rgba(241, 196, 15, 0.8)',
    borderRadius    : '3px',
    after: {
        contentText : ' ⚠️ MEDIUM',
        color       : 'rgba(241, 196, 15, 1)',
        fontWeight  : 'bold',
        fontSize    : '11px'
    }
});


// ── Extract System Prompts From File ──────────────────────────
function extractSystemPrompts(text) {
    const prompts = [];
    const lines   = text.split('\n');

    // Build full text for multi-line detection
    const fullText = text;

    // Pattern 1 : system_prompt = """...""" (multi-line)
    const multiLine = fullText.match(
        /system_prompt\s*=\s*"""([\s\S]*?)"""/i
    );
    if (multiLine) {
        prompts.push({
            text     : multiLine[1].trim().substring(0, 200),
            line     : 0,
            character: 0
        });
    }

    // Pattern 2 : system_prompt = '''...''' (multi-line)
    const multiLine2 = fullText.match(
        /system_prompt\s*=\s*'''([\s\S]*?)'''/i
    );
    if (multiLine2) {
        prompts.push({
            text     : multiLine2[1].trim().substring(0, 200),
            line     : 0,
            character: 0
        });
    }

    // Pattern 3 : single line variants
    lines.forEach((line, lineNum) => {
        const patterns = [
            /system_prompt\s*=\s*"([^"]+)"/i,
            /system_prompt\s*=\s*'([^']+)'/i,
            /SYSTEM_PROMPT\s*=\s*"([^"]+)"/i,
            /SYSTEM_PROMPT\s*=\s*'([^']+)'/i,
            /"role"\s*:\s*"system"\s*,\s*"content"\s*:\s*"([^"]+)"/,
        ];

        patterns.forEach(pattern => {
            const match = line.match(pattern);
            if (match && match[1].length > 10) {
                prompts.push({
                    text     : match[1].substring(0, 200),
                    line     : lineNum,
                    character: 0
                });
            }
        });
    });

    // Remove duplicates
    const unique = [];
    const seen   = new Set();
    for (const p of prompts) {
        if (!seen.has(p.text)) {
            seen.add(p.text);
            unique.push(p);
        }
    }

    return unique;
}



// ── Call LLM Scanner API ──────────────────────────────────────
async function callScannerAPI(targetName, systemPrompt) {
    const config = vscode.workspace.getConfiguration('llmscanner');
    const apiUrl = config.get('apiUrl') || 'http://localhost:8000';

    return new Promise((resolve, reject) => {
        const data = JSON.stringify({
            target_name  : targetName,
            target_type  : 'simulation',
            system_prompt: systemPrompt,
            categories   : [
                'direct_override',
                'extraction',
                'social_engineering',
                'boundary_testing'
            ]
        });

        const url     = new URL(`${apiUrl}/scan`);
        const options = {
            hostname: url.hostname,
            port    : url.port || 8000,
            path    : url.pathname,
            method  : 'POST',
            headers : {
                'Content-Type'  : 'application/json',
                'Content-Length': Buffer.byteLength(data)
            }
        };

        const req = https.request(options, res => {
            let body = '';
            res.on('data', chunk => body += chunk);
            res.on('end',  () => {
                try {
                    resolve(JSON.parse(body));
                } catch (e) {
                    reject(new Error('Invalid API response'));
                }
            });
        });

        req.on('error', reject);
        req.write(data);
        req.end();
    });
}


// ── Poll Scan Status ──────────────────────────────────────────
async function pollScanStatus(scanId, apiUrl, maxWait = 60000) {
    const start = Date.now();

    return new Promise((resolve, reject) => {
        const check = () => {
            if (Date.now() - start > maxWait) {
                reject(new Error('Scan timeout'));
                return;
            }

            const url     = new URL(`${apiUrl}/scan/${scanId}`);
            const options = {
                hostname: url.hostname,
                port    : url.port || 8000,
                path    : url.pathname,
                method  : 'GET'
            };

            const req = https.request(options, res => {
                let body = '';
                res.on('data', chunk => body += chunk);
                res.on('end',  () => {
                    try {
                        const data = JSON.parse(body);
                        if (data.status === 'complete') {
                            resolve(data);
                        } else if (data.status === 'failed') {
                            reject(new Error(data.error || 'Scan failed'));
                        } else {
                            setTimeout(check, 3000);
                        }
                    } catch (e) {
                        reject(e);
                    }
                });
            });

            req.on('error', reject);
            req.end();
        };

        check();
    });
}


// ── Apply Decorations ─────────────────────────────────────────
function applyDecorations(editor, results) {
    const criticals = [];
    const highs     = [];
    const mediums   = [];

    results.forEach(r => {
        if (!r.behavior_changed) return;

        const line  = Math.min(r.lineNum || 0, editor.document.lineCount - 1);
        const range = new vscode.Range(
            new vscode.Position(line, 0),
            new vscode.Position(line, editor.document.lineAt(line).text.length)
        );

        const decoration = {
            range,
            hoverMessage: new vscode.MarkdownString(
                `**LLM Scanner Finding**\n\n` +
                `**Severity :** ${r.severity}\n\n` +
                `**Score :** ${r.score}/10\n\n` +
                `**Reason :** ${r.reason}`
            )
        };

        if (r.severity === 'CRITICAL') criticals.push(decoration);
        else if (r.severity === 'HIGH') highs.push(decoration);
        else if (r.severity === 'MEDIUM') mediums.push(decoration);
    });

    editor.setDecorations(criticalDecoration, criticals);
    editor.setDecorations(highDecoration,     highs);
    editor.setDecorations(mediumDecoration,   mediums);
}


// ── Show Results Panel ────────────────────────────────────────
function showResultsPanel(results, targetName) {
    const panel = vscode.window.createWebviewPanel(
        'llmScannerResults',
        `🔐 LLM Scanner — ${targetName}`,
        vscode.ViewColumn.Two,
        { enableScripts: true }
    );

    const summary = results.results?.summary || {};
    const findings = results.results?.results || [];

    const findingsHtml = findings
        .filter(r => r.severity !== 'SAFE')
        .slice(0, 20)
        .map(r => {
            const colors = {
                CRITICAL: '#C0392B',
                HIGH    : '#E67E22',
                MEDIUM  : '#F1C40F',
                LOW     : '#27AE60'
            };
            const color = colors[r.severity] || '#888';
            return `
                <div style="border:1px solid ${color};border-radius:8px;
                            margin-bottom:12px;overflow:hidden">
                    <div style="background:${color}22;padding:10px 14px;
                                border-left:4px solid ${color}">
                        <strong style="color:${color}">${r.severity}</strong>
                        <span style="color:#888;margin-left:12px;font-size:12px">
                            ${r.category.replace(/_/g,' ').toUpperCase()}
                        </span>
                        <span style="float:right;color:#888;font-size:12px">
                            Score: ${r.score}/10
                        </span>
                    </div>
                    <div style="padding:12px 14px">
                        <p style="font-size:13px;color:#ccc;margin-bottom:6px">
                            <strong>Reason:</strong> ${r.reason}
                        </p>
                        <p style="font-size:12px;color:#888">
                            <strong>Attack:</strong> ${r.attack.substring(0,100)}...
                        </p>
                    </div>
                </div>
            `;
        }).join('');

    const score      = summary.security_score || 0;
    const scoreColor = score >= 70 ? '#27AE60' :
                       score >= 40 ? '#F1C40F' : '#C0392B';

    panel.webview.html = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {
            font-family: 'Segoe UI', sans-serif;
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 20px;
            margin: 0;
        }
        h1 { color: white; font-size: 20px; }
        .score {
            text-align: center;
            padding: 20px;
            margin: 16px 0;
            background: ${scoreColor}22;
            border: 2px solid ${scoreColor};
            border-radius: 12px;
        }
        .score-number {
            font-size: 48px;
            font-weight: 800;
            color: ${scoreColor};
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
            margin: 16px 0;
        }
        .stat {
            background: #2d2d2d;
            border-radius: 8px;
            padding: 14px;
            text-align: center;
        }
        .stat-num { font-size: 28px; font-weight: 700; }
        .stat-label { font-size: 12px; color: #888; margin-top: 4px; }
    </style>
</head>
<body>
    <h1>🔐 LLM Scanner Results</h1>
    <p style="color:#888">Target : ${targetName}</p>

    <div class="score">
        <div class="score-number">${score}%</div>
        <div style="color:${scoreColor};font-weight:600">Security Score</div>
    </div>

    <div class="stats">
        <div class="stat">
            <div class="stat-num" style="color:#C0392B">${summary.critical || 0}</div>
            <div class="stat-label">Critical</div>
        </div>
        <div class="stat">
            <div class="stat-num" style="color:#E67E22">${summary.high || 0}</div>
            <div class="stat-label">High</div>
        </div>
        <div class="stat">
            <div class="stat-num" style="color:#F1C40F">${summary.medium || 0}</div>
            <div class="stat-label">Medium</div>
        </div>
        <div class="stat">
            <div class="stat-num" style="color:#2ECC71">${summary.safe || 0}</div>
            <div class="stat-label">Safe</div>
        </div>
    </div>

    <h2 style="font-size:16px;margin-top:24px">Findings</h2>
    ${findingsHtml || '<p style="color:#888">No vulnerabilities found.</p>'}
</body>
</html>`;
}


// ── Main Scan Function ────────────────────────────────────────
async function scanFile(editor) {
    if (!editor) {
        vscode.window.showErrorMessage('No active editor found');
        return;
    }

    const config     = vscode.workspace.getConfiguration('llmscanner');
    const apiUrl     = config.get('apiUrl') || 'http://localhost:8000';
    const text       = editor.document.getText();
    const fileName   = path.basename(editor.document.fileName);
    const prompts    = extractSystemPrompts(text);

    if (prompts.length === 0) {
        vscode.window.showInformationMessage(
            '🔍 No system prompts found in this file. ' +
            'Make sure you have a variable named system_prompt or SYSTEM_PROMPT.'
        );
        return;
    }

    vscode.window.showInformationMessage(
        `🔐 LLM Scanner: Found ${prompts.length} system prompt(s). Scanning...`
    );

    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title   : '🔐 LLM Scanner',
        cancellable: false
    }, async progress => {
        try {
            progress.report({ message: 'Launching scan...' });

            const scanResponse = await callScannerAPI(
                fileName,
                prompts[0].text
            );

            if (!scanResponse.scan_id) {
                throw new Error('Could not start scan. Is the API running?');
            }

            progress.report({
                message: `Scan started (ID: ${scanResponse.scan_id}). Waiting for results...`
            });

            const results = await pollScanStatus(
                scanResponse.scan_id, apiUrl, 300000
            );

            progress.report({ message: 'Applying results...' });

            // Add line numbers to results
            if (results.results?.results) {
                results.results.results.forEach((r, i) => {
                    r.lineNum = prompts[0].line;
                });
            }

            // Apply decorations
            applyDecorations(editor, results.results?.results || []);

            // Show results panel
            showResultsPanel(results, fileName);

            const score = results.results?.summary?.security_score || 0;
            const emoji = score >= 70 ? '✅' : score >= 40 ? '⚠️' : '🚨';
            vscode.window.showInformationMessage(
                `${emoji} Scan complete — Security Score: ${score}%`
            );

        } catch (error) {
            vscode.window.showErrorMessage(
                `LLM Scanner error: ${error.message}. ` +
                'Make sure the API is running: uvicorn api:app --reload'
            );
        }
    });
}


// ── Activate Extension ────────────────────────────────────────
function activate(context) {

    console.log('LLM Scanner extension activated');

    // Command : Scan File
    const scanFileCmd = vscode.commands.registerCommand(
        'llmscanner.scanFile',
        () => scanFile(vscode.window.activeTextEditor)
    );

    // Command : Scan Selected Text
    const scanPromptCmd = vscode.commands.registerCommand(
        'llmscanner.scanPrompt',
        async () => {
            const editor    = vscode.window.activeTextEditor;
            if (!editor) return;

            const selection = editor.document.getText(editor.selection);
            if (!selection) {
                vscode.window.showErrorMessage('Please select some text first');
                return;
            }

            const config  = vscode.workspace.getConfiguration('llmscanner');
            const apiUrl  = config.get('apiUrl') || 'http://localhost:8000';

            vscode.window.showInformationMessage(
                '🔐 Scanning selected text...'
            );

            try {
                const response = await callScannerAPI(
                    'Selected Prompt', selection
                );
                vscode.window.showInformationMessage(
                    `Scan started: ${response.scan_id}`
                );
            } catch (err) {
                vscode.window.showErrorMessage(`Error: ${err.message}`);
            }
        }
    );

    // Command : Show Report
    const showReportCmd = vscode.commands.registerCommand(
        'llmscanner.showReport',
        () => {
            vscode.window.showInformationMessage(
                'Open http://localhost:3000 to see your reports'
            );
        }
    );

    // Auto-scan on save (if enabled)
    const onSave = vscode.workspace.onDidSaveTextDocument(doc => {
        const config = vscode.workspace.getConfiguration('llmscanner');
        if (config.get('autoScan')) {
            const editor = vscode.window.activeTextEditor;
            if (editor && editor.document === doc) {
                scanFile(editor);
            }
        }
    });

    // Status bar item
    const statusBar = vscode.window.createStatusBarItem(
        vscode.StatusBarAlignment.Right, 100
    );
    statusBar.text         = '$(shield) LLM Scanner';
    statusBar.tooltip      = 'Click to scan this file for AI vulnerabilities';
    statusBar.command      = 'llmscanner.scanFile';
    statusBar.backgroundColor = new vscode.ThemeColor(
        'statusBarItem.warningBackground'
    );
    statusBar.show();

    context.subscriptions.push(
        scanFileCmd, scanPromptCmd, showReportCmd,
        onSave, statusBar
    );
}


function deactivate() {}

module.exports = { activate, deactivate };
