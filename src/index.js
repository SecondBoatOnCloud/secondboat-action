const core   = require('@actions/core');
const github = require('@actions/github');
const https  = require('https');

const SEVERITY_ORDER = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const SEVERITY_ICON  = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵' };

// ── ASCII table helpers ───────────────────────────────────────────────────────

function wrap(text, width) {
  const str = String(text ?? '');
  if (str.length <= width) return [str];
  const lines = [];
  let remaining = str;
  while (remaining.length > width) {
    let cut = remaining.lastIndexOf(' ', width);
    if (cut <= 0) cut = width;
    lines.push(remaining.slice(0, cut).trim());
    remaining = remaining.slice(cut).trim();
  }
  if (remaining) lines.push(remaining);
  return lines;
}

function renderTable(headers, rows, opts = {}) {
  // headers: [{ label, key, width, align }]
  // rows: array of objects
  const cols = headers.map(h => ({
    ...h,
    w: h.width || Math.max(h.label.length, ...rows.map(r => String(r[h.key] ?? '').length), 4),
  }));

  const sep  = '  +' + cols.map(c => '-'.repeat(c.w + 2)).join('+') + '+';
  const head = '  |' + cols.map(c => ` ${c.label.padEnd(c.w)} `).join('|') + '|';

  const out = [];
  out.push(sep);
  out.push(head);
  out.push(sep.replace(/-/g, '='));

  rows.forEach(row => {
    // wrap each cell
    const cells = cols.map(c => wrap(row[c.key] ?? '', c.w));
    const height = Math.max(...cells.map(c => c.length));

    for (let l = 0; l < height; l++) {
      const line = '  |' + cols.map((c, i) => {
        const val = cells[i][l] ?? '';
        return c.align === 'right'
          ? ` ${val.padStart(c.w)} `
          : ` ${val.padEnd(c.w)} `;
      }).join('|') + '|';
      out.push(line);
    }
    out.push(sep);
  });

  return out;
}

// ── Dividers ──────────────────────────────────────────────────────────────────
function L(c = '─', n = 76) { return c.repeat(n); }
function blank() { core.info(''); }
function heading(t) {
  blank();
  core.info(L('═'));
  core.info(`  ${t}`);
  core.info(L('═'));
  blank();
}

// ── Main ──────────────────────────────────────────────────────────────────────
async function run() {
  try {
    const apiKey = core.getInput('api-key', { required: true });
    const orgId  = core.getInput('org-id',  { required: true });
    const apiUrl = core.getInput('api-url');
    const failOn = core.getInput('fail-on') || 'HIGH';

    const ctx      = github.context;
    const repoName = `${ctx.repo.owner}/${ctx.repo.repo}`;
    const branch   = ctx.ref.replace('refs/heads/', '');
    const sha      = ctx.sha;
    const shortSha = sha.slice(0, 7);
    const scannedAt = new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC';

    const payload = JSON.stringify({ org_id: orgId, repo_name: repoName, branch, commit_sha: sha });

    const url = new URL(apiUrl);
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
    core.info(L('━'));
    core.info('  ⚓  SECONDBOAT  —  IaC SECURITY SCAN REPORT');
    core.info(L('━'));
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
      core.info(L('━'));
      core.warning('  ⚠️   No IaC files detected in this repository');
      core.info(L('━'));
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
    core.info(`    ✅  Passed : ${secPassed}   ❌  Failed : ${secFailed}   📊  Total : ${secTotal}`);

    if (secFailed === 0) {
      blank();
      core.info('  🎉  All security checks passed — no violations found');
    } else {
      // Sort: CRITICAL → HIGH → MEDIUM → LOW
      const sorted = [...secFindings].sort((a, b) =>
        SEVERITY_ORDER.indexOf((b.severity || '').toUpperCase()) -
        SEVERITY_ORDER.indexOf((a.severity || '').toUpperCase())
      );

      const rows = sorted.map((f, i) => ({
        num:        String(i + 1).padStart(2, '0'),
        sev:        `${SEVERITY_ICON[(f.severity||'').toUpperCase()] || '⚪'} ${(f.severity||'N/A').toUpperCase()}`,
        check_id:   f.check_id   || '',
        check_name: f.check_name || '',
        resource:   f.resource   || '',
        location:   `${f.file_path || ''}:${f.line_start || ''}`,
        framework:  f.framework  || 'N/A',
        guideline:  f.guideline  || f.fix_hint || f.remediation || '',
      }));

      const headers = [
        { label: '#',          key: 'num',        width: 3  },
        { label: 'Severity',   key: 'sev',        width: 12 },
        { label: 'Check ID',   key: 'check_id',   width: 15 },
        { label: 'Check Name', key: 'check_name', width: 36 },
        { label: 'Resource',   key: 'resource',   width: 30 },
        { label: 'Location',   key: 'location',   width: 28 },
        { label: 'Framework',  key: 'framework',  width: 14 },
        { label: 'Guideline',  key: 'guideline',  width: 40 },
      ];

      blank();
      renderTable(headers, rows).forEach(l => core.info(l));
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  SECTION 2 — GOVERNANCE FINDINGS
    // ══════════════════════════════════════════════════════════════════════════
    heading('SECTION 2 of 2  ·  GOVERNANCE FINDINGS');
    core.info(`    ✅  Passed : ${govPassed}   ❌  Failed : ${govFailed}   📊  Total : ${govTotal}`);

    if (govTotal === 0) {
      blank();
      core.info('  ℹ️   No governance policies configured for this organization');
    } else if (govFailed === 0) {
      blank();
      core.info('  🎉  All governance policies passed');
    } else {
      const failedGov = govFindings.filter(f => f.status === 'FAILED');

      const sorted = [...failedGov].sort((a, b) =>
        SEVERITY_ORDER.indexOf((b.severity || '').toUpperCase()) -
        SEVERITY_ORDER.indexOf((a.severity || '').toUpperCase())
      );

      const rows = sorted.map((f, i) => ({
        num:        String(i + 1).padStart(2, '0'),
        sev:        `${SEVERITY_ICON[(f.severity||'').toUpperCase()] || '⚪'} ${(f.severity||'N/A').toUpperCase()}`,
        policy:     f.policy_title || '',
        category:   f.category     || 'N/A',
        resource:   f.resource     || '',
        conditions: (f.failed_conditions || [])
                      .map(c => `${c.key}: expected ${c.operator} "${c.expected}", got "${c.actual}"`)
                      .join(' | ') || 'N/A',
        remediation: f.remediation || '',
      }));

      const headers = [
        { label: '#',           key: 'num',         width: 3  },
        { label: 'Severity',    key: 'sev',         width: 12 },
        { label: 'Policy',      key: 'policy',      width: 30 },
        { label: 'Category',    key: 'category',    width: 16 },
        { label: 'Resource',    key: 'resource',    width: 28 },
        { label: 'Conditions',  key: 'conditions',  width: 42 },
        { label: 'Remediation', key: 'remediation', width: 36 },
      ];

      blank();
      renderTable(headers, rows).forEach(l => core.info(l));
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  FINAL SUMMARY
    // ══════════════════════════════════════════════════════════════════════════
    const totalFailed = secFailed + govFailed;
    const totalPassed = secPassed + govPassed;

    blank();
    core.info(L('━'));
    core.info('  SCAN SUMMARY');
    core.info(L('━'));
    blank();
    core.info(`    ✅  Passed         : ${totalPassed}`);
    core.info(`    ❌  Failed         : ${totalFailed}`);
    core.info(`    📊  Total Checks   : ${totalPassed + totalFailed}`);
    core.info(`    🎯  Fail Threshold : ${failOn}+`);

    if (totalFailed > 0) {
      blank();
      core.info('    Severity Breakdown:');
      const allFailed = [
        ...secFindings,
        ...govFindings.filter(f => f.status === 'FAILED'),
      ];
      [...SEVERITY_ORDER].reverse().forEach(sev => {
        const count = allFailed.filter(f => (f.severity || '').toUpperCase() === sev).length;
        if (count) core.info(`      ${SEVERITY_ICON[sev]}  ${sev.padEnd(8)} : ${count}`);
      });
    }

    blank();
    core.info(L('━'));
    blank();

    // ── FAIL GATE ─────────────────────────────────────────────────────────────
    const shouldFail = failOn !== 'none' && (
      secFindings.some(f =>
        SEVERITY_ORDER.indexOf((f.severity || '').toUpperCase()) >= SEVERITY_ORDER.indexOf(failOn)
      ) ||
      govFindings.some(f =>
        f.status === 'FAILED' &&
        SEVERITY_ORDER.indexOf((f.severity || '').toUpperCase()) >= SEVERITY_ORDER.indexOf(failOn)
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
