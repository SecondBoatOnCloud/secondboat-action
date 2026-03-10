const core = require('@actions/core');
const github = require('@actions/github');
const https = require('https');

const SEVERITY_ORDER = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

const SEVERITY_ICON = {
  CRITICAL: '🔴',
  HIGH: '🟠',
  MEDIUM: '🟡',
  LOW: '🔵',
};

function line(char = '─', len = 60) {
  return char.repeat(len);
}

function pad(label, value, width = 16) {
  return `  ${label.padEnd(width)}: ${value}`;
}

async function run() {
  try {
    const apiKey = core.getInput('api-key', { required: true });
    const orgId = core.getInput('org-id', { required: true });
    const apiUrl = core.getInput('api-url');
    const failOn = core.getInput('fail-on') || 'HIGH';

    const ctx = github.context;
    const repoName = `${ctx.repo.owner}/${ctx.repo.repo}`;
    const branch = ctx.ref.replace('refs/heads/', '');
    const sha = ctx.sha;
    const shortSha = sha.slice(0, 7);

    const payload = JSON.stringify({
      org_id: orgId,
      repo_name: repoName,
      branch: branch,
      commit_sha: sha,
    });

    const url = new URL(apiUrl);
    const options = {
      hostname: url.hostname,
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'Content-Length': Buffer.byteLength(payload),
      },
    };

    core.info('');
    core.info('  🔍  SecondBoat IaC Scan Starting...');
    core.info('');

    const body = await new Promise((resolve, reject) => {
      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          if (res.statusCode !== 200)
            reject(new Error(`HTTP ${res.statusCode}: ${data}`));
          else
            resolve(JSON.parse(data));
        });
      });
      req.on('error', reject);
      req.write(payload);
      req.end();
    });

    const frameworks = body.iac_frameworks?.join(', ') ?? 'N/A';
    const scannedAt = new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC';

    const security = body.checkov || {};
    const governance = body.governance || {};

    const secFindings = security.findings || [];
    const govFindings = governance.findings || [];

    const secPassed = security.total_passed ?? 0;
    const secFailed = security.total_failed ?? 0;
    const secTotal = security.total_checks ?? (secPassed + secFailed);
    const govPassed = governance.total_passed ?? 0;
    const govFailed = governance.total_failed ?? 0;
    const govTotal = governance.total_checks ?? (govPassed + govFailed);

    // ── HEADER ────────────────────────────────────────────────────────────────
    core.info(line('━'));
    core.info('  SECONDBOAT  —  IaC SECURITY SCAN REPORT');
    core.info(line('━'));
    core.info('');
    core.info(pad('Repository', repoName));
    core.info(pad('Branch', branch));
    core.info(pad('Commit', shortSha));
    core.info(pad('Frameworks', frameworks));
    core.info(pad('Scanned At', scannedAt));
    core.info('');

    // ── NO IAC ────────────────────────────────────────────────────────────────
    if (body.status === 'no_iac') {
      core.info(line());
      core.warning('  ⚠️   No IaC files detected in this repository');
      core.info(line('━'));
      core.setOutput('status', 'no_iac');
      core.setOutput('total_failed', '0');
      return;
    }

    // ── SECURITY FINDINGS SECTION ─────────────────────────────────────────────
    core.info(line());
    core.info('  SECURITY FINDINGS');
    core.info(line());
    core.info('');
    core.info(`  ✅  Passed   : ${secPassed}`);
    core.info(`  ❌  Failed   : ${secFailed}`);
    core.info(`  📊  Total    : ${secTotal}`);
    core.info('');

    if (secFailed > 0) {
      // Group by severity
      const bySeverity = {};
      secFindings.forEach(f => {
        const sev = (f.severity || 'UNKNOWN').toUpperCase();
        if (!bySeverity[sev]) bySeverity[sev] = [];
        bySeverity[sev].push(f);
      });

      // Print in severity order (highest first)
      [...SEVERITY_ORDER].reverse().forEach(sev => {
        const group = bySeverity[sev];
        if (!group || group.length === 0) return;
        const icon = SEVERITY_ICON[sev] || '⚪';

        core.info(`  ${icon}  ${sev}  (${group.length})`);
        core.info(`  ${line('·', 56)}`);

        group.forEach(f => {
          core.info(`    ✗  ${f.check_id}`);
          core.info(`       ${f.check_name || ''}`);
          core.info(`       Resource : ${f.resource}`);
          core.info(`       Location : ${f.file_path}:${f.line_start}`);
          core.info('');
        });
      });
    } else {
      core.info('  🎉  No security violations found');
      core.info('');
    }

    // ── GOVERNANCE FINDINGS SECTION ───────────────────────────────────────────
    core.info(line());
    core.info('  GOVERNANCE FINDINGS');
    core.info(line());
    core.info('');
    core.info(`  ✅  Passed   : ${govPassed}`);
    core.info(`  ❌  Failed   : ${govFailed}`);
    core.info(`  📊  Total    : ${govTotal}`);
    core.info('');

    if (govFailed > 0) {
      const bySeverity = {};
      govFindings.filter(f => f.status === 'FAILED').forEach(f => {
        const sev = (f.severity || 'LOW').toUpperCase();
        if (!bySeverity[sev]) bySeverity[sev] = [];
        bySeverity[sev].push(f);
      });

      [...SEVERITY_ORDER].reverse().forEach(sev => {
        const group = bySeverity[sev];
        if (!group || group.length === 0) return;
        const icon = SEVERITY_ICON[sev] || '⚪';

        core.info(`  ${icon}  ${sev}  (${group.length})`);
        core.info(`  ${line('·', 56)}`);

        group.forEach(f => {
          core.info(`    ✗  ${f.policy_title}`);
          core.info(`       Resource : ${f.resource}`);
          core.info(`       Category : ${f.category || 'N/A'}`);

          if (f.failed_conditions?.length > 0) {
            core.info('       Violations:');
            f.failed_conditions.forEach(c => {
              core.info(`         • ${c.key} should be ${c.operator} "${c.expected}" (got: "${c.actual}")`);
            });
          }
          core.info('');
        });
      });
    } else if (govTotal === 0) {
      core.info('  ℹ️   No governance policies configured for this organization');
      core.info('');
    } else {
      core.info('  🎉  All governance policies passed');
      core.info('');
    }

    // ── SUMMARY ───────────────────────────────────────────────────────────────
    core.info(line('━'));
    const totalFailed = secFailed + govFailed;
    const totalPassed = secPassed + govPassed;
    core.info(`  SUMMARY   ✅ ${totalPassed} passed   ❌ ${totalFailed} failed   📊 ${totalPassed + totalFailed} total`);
    core.info(line('━'));
    core.info('');

    // ── FAIL LOGIC ────────────────────────────────────────────────────────────
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
      core.setFailed(`❌  SecondBoat found violations at ${failOn}+ severity`);
    } else if (totalFailed > 0) {
      core.warning(`⚠️   Violations found but below ${failOn} threshold — pipeline continues`);
    }

    core.setOutput('status', body.status);
    core.setOutput('total_failed', String(totalFailed));

  } catch (err) {
    core.setFailed(`SecondBoat scan failed: ${err.message}`);
  }
}

run();
