const core = require('@actions/core');
const github = require('@actions/github');
const https = require('https');

const SEVERITY_ORDER = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

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

    core.info('🔍 Starting SecondBoat IaC Scan...');

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
    const shortSha = sha.slice(0, 7);

    core.info('──────────────────────────────────────');
    core.info(`  Repository : ${repoName}`);
    core.info(`  Branch     : ${branch}`);
    core.info(`  Commit     : ${shortSha}`);
    core.info(`  Frameworks : ${frameworks}`);
    core.info('──────────────────────────────────────');
    core.info(`  ✅ Passed  : ${body.total_passed}`);
    core.info(`  ❌ Failed  : ${body.total_failed}`);
    core.info(`  📊 Total   : ${body.total_checks}`);
    core.info('──────────────────────────────────────');

    if (body.status === 'no_iac') {
      core.warning('⚠️  No IaC files detected in this repository');
    } else if (body.total_failed > 0) {
      core.info('\n  Failed Checks:');
      body.findings?.forEach(f => {
        core.error(`[${f.severity}] ${f.check_id} — ${f.resource} | ${f.file_path}:${f.line_start}`);
      });

      const shouldFail = failOn !== 'none' && body.findings?.some(f =>
        SEVERITY_ORDER.indexOf(f.severity) >= SEVERITY_ORDER.indexOf(failOn)
      );

      if (shouldFail) {
        core.setFailed(`❌ SecondBoat found violations at ${failOn}+ severity`);
      } else {
        core.warning(`⚠️  Violations found but below ${failOn} threshold — pipeline continues`);
      }
    } else {
      core.info('  🎉 All checks passed');
    }

    core.setOutput('status', body.status);
    core.setOutput('total_failed', String(body.total_failed));

  } catch (err) {
    core.setFailed(`SecondBoat scan failed: ${err.message}`);
  }
}

run();
