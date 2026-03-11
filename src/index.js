const core   = require('@actions/core');
const github = require('@actions/github');
const https  = require('https');

const SEVERITY_ORDER = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const SEVERITY_ICON  = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵', UNKNOWN: '⚪' };

// ── Box-drawing table renderer ────────────────────────────────────────────────
// cols: [{ label, key, width }]
// rows: array of objects
function truncate(str, max) {
  const s = String(str ?? '');
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

function renderTable(cols, rows) {
  const w   = cols.map(c => c.width);
  const top = '  ┌' + w.map(n => '─'.repeat(n + 2)).join('┬') + '┐';
  const mid = '  ├' + w.map(n => '─'.repeat(n + 2)).join('┼') + '┤';
  const bot = '  └' + w.map(n => '─'.repeat(n + 2)).join('┴') + '┘';
  const row = (cells) =>
    '  │' + cells.map((v, i) => ` ${truncate(v, w[i]).padEnd(w[i])} `).join('│') + '│';

  const lines = [];
  lines.push(top);
  lines.push(row(cols.map(c => c.label)));
  lines.push(mid.replace(/─/g, '═').replace(/├/g, '╞').replace(/┤/g, '╡').replace(/┼/g, '╪'));
  rows.forEach((r, i) => {
    lines.push(row(cols.map(c => r[c.key] ?? '')));
    lines.push(i < rows.length - 1 ? mid : bot);
  });
  return lines;
}

function getSeverity(f) {
  return (
    f.severity        ||
    f.check_severity  ||
    f.risk_level      ||
    f.level           ||
    'UNKNOWN'
  ).toUpperCase();
}

function sevCell(f) {
  const s = getSeverity(f);
  return `${SEVERITY_ICON[s] || '⚪'} ${s}`;
}

// ── Dividers ──────────────────────────────────────────────────────────────────
function L(c = '─', n = 80) { return c.repeat(n); }
function blank() { core.info(''); }
function heading(t) {
  blank();
  core.info('  ' + L('═'));
  core.info(`  ${t}`);
  core.info('  ' + L('═'));
  blank();
}

// ── Main ──────────────────────────────────────────────────────────────────────
async function run() {
  try {
    const apiKey = core.getInput('api-key', { required: true });
    const orgId  = core.getInput('org-id',  { required: true });
    const apiUrl = core.getInput('api-url');
    const failOn = core.getInput('fail-on') || 'HIGH';

    const ctx       = github.context;
    const repoName  = `${ctx.repo.owner}/${ctx.repo.repo}`;
    const branch    = ctx.ref.replace('refs/heads/', '');
    const sha       = ctx.sha;
    const shortSha  = sha.slice(0, 7);
    const scannedAt = new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC';

    const payload = JSON.stringify({ org_id: orgId, repo_name: repoName, branch, commit_sha: sha });
    const url     = new URL(apiUrl);
    const options = {
      hostname: url.hostname,
      path:     url.pathname,
      method:   'POST',
      headers: {
        'Content-Type':   'application/json',
        'x-api-key':      apiKey,
        'Content-Length': Buffer.byteLength(payload),
      },
    };

    blank();
    core.info('  ' + L('━'));
    core.info('  ⚓  SECONDBOAT  —  IaC SECURITY SCAN REPORT');
    core.info('  ' + L('━'));
    blank();
    core.info(`    Repository  : ${repoName}`);
    core.info(`    Branch      : ${branch}`);
    core.info(`    Commit      : ${shortSha}`);
    core.info(`    Scanned At  : ${scannedAt}`);
    core.info(`    Fail On     : ${failOn}+`);
    blank();

    const body = await new Promise((resolve, reject) => {
      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () =>
          res.statusCode !== 200
            ? reject(new Error(`HTTP ${res.statusCode}: ${data}`))
            : resolve(JSON.parse(data))
        );
      });
      req.on('error', reject);
      req.write(payload);
      req.end();
    });

    if (body.status === 'no_iac') {
      core.warning('  ⚠️   No IaC files detected in this repository');
      core.setOutput('status', 'no_iac');
      core.setOutput('total_failed', '0');
      return;
    }

    const security   = body.checkov   || {};
    const governance = body.governance || {};
    const secFindings = security.findings   || [];
    const govFindings = governance.findings || [];
    const secPassed = security.total_passed   ?? 0;
    const secFailed = security.total_failed   ?? 0;
    const secTotal  = security.total_checks   ?? (secPassed + secFailed);
    const govPassed = governance.total_passed ?? 0;
    const govFailed = governance.total_failed ?? 0;
    const govTotal  = governance.total_checks ?? (govPassed + govFailed);

    // ══════════════════════════════════════════════════════════════════════════
    //  SECTION 1 — SECURITY FINDINGS
    // ══════════════════════════════════════════════════════════════════════════
    heading('SECTION 1 of 2  ·  SECURITY FINDINGS');
    core.info(`    ✅  Passed : ${secPassed}    ❌  Failed : ${secFailed}    📊  Total : ${secTotal}`);

    if (secFailed === 0) {
      blank();
      core.info('  🎉  All security checks passed — no violations found');
    } else {
      // Sort CRITICAL → HIGH → MEDIUM → LOW → UNKNOWN
      const sorted = [...secFindings].sort((a, b) =>
        SEVERITY_ORDER.indexOf(getSeverity(b)) - SEVERITY_ORDER.indexOf(getSeverity(a))
      );

      const rows = sorted.map((f, i) => ({
        num:      String(i + 1).padStart(2, '0'),
        sev:      sevCell(f),
        id:       f.check_id   || '',
        name:     f.check_name || '',
        resource: f.resource   || '',
        location: `${f.file_path || ''}:${f.line_start || ''}`,
      }));

      // Column widths tuned to ~120 chars total
      const cols = [
        { label: '#',          key: 'num',      width: 3  },
        { label: 'Severity',   key: 'sev',      width: 12 },
        { label: 'Check ID',   key: 'id',       width: 14 },
        { label: 'Check Name', key: 'name',     width: 46 },
        { label: 'Resource',   key: 'resource', width: 30 },
        { label: 'Location',   key: 'location', width: 20 },
      ];

      blank();
      renderTable(cols, rows).forEach(l => core.info(l));
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  SECTION 2 — GOVERNANCE FINDINGS
    // ══════════════════════════════════════════════════════════════════════════
    heading('SECTION 2 of 2  ·  GOVERNANCE FINDINGS');
    core.info(`    ✅  Passed : ${govPassed}    ❌  Failed : ${govFailed}    📊  Total : ${govTotal}`);

    if (govTotal === 0) {
      blank();
      core.info('  ℹ️   No governance policies configured for this organization');
    } else if (govFailed === 0) {
      blank();
      core.info('  🎉  All governance policies passed');
    } else {
      const failedGov = govFindings.filter(f => f.status === 'FAILED');

      const sorted = [...failedGov].sort((a, b) =>
        SEVERITY_ORDER.indexOf(getSeverity(b)) - SEVERITY_ORDER.indexOf(getSeverity(a))
      );

      const rows = sorted.map((f, i) => ({
        num:      String(i + 1).padStart(2, '0'),
        sev:      sevCell(f),
        policy:   f.policy_title || f.name || '',
        resource: f.resource     || '',
        category: f.category     || 'N/A',
        // Show each failed condition as: key expected "val" got "val"
        conditions: (f.failed_conditions || [])
          .map(c => `${c.key} ${c.operator} "${c.expected}" (got: "${c.actual}")`)
          .join('  ·  ') || 'N/A',
      }));

      const cols = [
        { label: '#',          key: 'num',        width: 3  },
        { label: 'Severity',   key: 'sev',        width: 12 },
        { label: 'Policy',     key: 'policy',     width: 32 },
        { label: 'Resource',   key: 'resource',   width: 28 },
        { label: 'Category',   key: 'category',   width: 14 },
        { label: 'Conditions', key: 'conditions', width: 50 },
      ];

      blank();
      renderTable(cols, rows).forEach(l => core.info(l));
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  SUMMARY
    // ══════════════════════════════════════════════════════════════════════════
    const totalFailed = secFailed + govFailed;
    const totalPassed = secPassed + govPassed;

    blank();
    core.info('  ' + L('━'));
    core.info('  SCAN SUMMARY');
    core.info('  ' + L('━'));
    blank();
    core.info(`    ✅  Passed         : ${totalPassed}`);
    core.info(`    ❌  Failed         : ${totalFailed}`);
    core.info(`    📊  Total Checks   : ${totalPassed + totalFailed}`);
    core.info(`    🎯  Fail Threshold : ${failOn}+`);

    if (totalFailed > 0) {
      blank();
      core.info('    Severity Breakdown (failures):');
      const allFailed = [
        ...secFindings,
        ...govFindings.filter(f => f.status === 'FAILED'),
      ];
      [...SEVERITY_ORDER].reverse().forEach(sev => {
        const count = allFailed.filter(f => getSeverity(f) === sev).length;
        if (count) core.info(`      ${SEVERITY_ICON[sev]}  ${sev.padEnd(8)} : ${count}`);
      });
    }

    blank();
    core.info('  ' + L('━'));
    blank();

    // ── FAIL GATE ─────────────────────────────────────────────────────────────
    const shouldFail = failOn !== 'none' && (
      secFindings.some(f =>
        SEVERITY_ORDER.indexOf(getSeverity(f)) >= SEVERITY_ORDER.indexOf(failOn)
      ) ||
      govFindings.some(f =>
        f.status === 'FAILED' &&
        SEVERITY_ORDER.indexOf(getSeverity(f)) >= SEVERITY_ORDER.indexOf(failOn)
      )
    );

    if (shouldFail) {
      core.setFailed(`❌  SecondBoat found violations at or above ${failOn} severity`);
    } else if (totalFailed > 0) {
      core.warning(`⚠️   Violations found but all are below ${failOn} threshold — pipeline continues`);
    }

    core.setOutput('status',       body.status);
    core.setOutput('total_failed', String(totalFailed));

  } catch (err) {
    core.setFailed(`SecondBoat scan failed: ${err.message}`);
  }
}

run();
