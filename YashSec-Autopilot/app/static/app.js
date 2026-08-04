(() => {
  'use strict';

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const escapeHtml = (value) => String(value ?? '')
    .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;').replaceAll("'", '&#039;');
  const formatDate = (value) => value ? new Date(value.endsWith?.('Z') ? value : `${value}Z`).toLocaleString() : '—';
  const shortPath = (value, limit = 54) => value && value.length > limit ? `…${value.slice(-(limit - 1))}` : (value || '—');
  const titleCase = (value) => String(value || 'unknown').replaceAll('_', ' ').replace(/\b\w/g, (m) => m.toUpperCase());
  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
  const FINAL_SCAN_STATES = new Set(['completed', 'completed_partial', 'failed', 'cancelled']);

  const state = {
    token: sessionStorage.getItem('yashsec_token') || '',
    transport: sessionStorage.getItem('yashsec_transport') || '',
    user: null,
    view: 'overview',
    repositories: [],
    scans: [],
    findings: [],
    tools: [],
    aiHealth: null,
    selectedFinding: null,
    currentScanId: null,
    currentFindingIdForAi: null,
    reauth: null,
    setupCreated: false,
    demoMode: false,
    commandItems: [],
  };

  const pageInfo = {
    overview: ['SECURITY WORKSPACE', 'Overview', 'What needs attention and what coverage was achieved.'],
    projects: ['REPOSITORY CONTROL', 'Projects', 'Repository sources, detected stacks, approved runtime and scan history.'],
    scans: ['HONEST COVERAGE', 'Scans', 'Every selected, skipped, failed and completed stage remains visible.'],
    findings: ['EVIDENCE FIRST', 'Findings', 'Triage scanner evidence before relying on generated interpretation.'],
    assistant: ['DEFENSIVE AI', 'AI Assistant', 'Repository-aware analysis through local Ollama, Ollama Cloud, or the optional AirLLM worker.'],
    reports: ['PROFESSIONAL EVIDENCE', 'Reports', 'Export technical evidence without hiding partial coverage.'],
    audit: ['TAMPER-EVIDENT HISTORY', 'Audit Logs', 'Review security-sensitive actions and verify the local hash chain.'],
    tools: ['CAPABILITY HEALTH', 'Tool Manager', 'Connect optional scanners without breaking the core application.'],
    settings: ['LOCAL CONTROL', 'Settings', 'Storage, privacy, AI providers, backup and application security.'],
  };

  function captureTransportToken() {
    const params = new URLSearchParams(location.search);
    const token = params.get('transport');
    if (token) {
      state.transport = token;
      sessionStorage.setItem('yashsec_transport', token);
      params.delete('transport');
      const query = params.toString();
      history.replaceState({}, '', `${location.pathname}${query ? `?${query}` : ''}${location.hash}`);
    }
  }

  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    if (!(options.body instanceof FormData) && options.body !== undefined && !headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }
    if (state.token) headers.set('Authorization', `Bearer ${state.token}`);
    if (state.transport) headers.set('X-YashSec-Transport', state.transport);
    const response = await fetch(path, { ...options, headers });
    if (response.status === 401 && !path.includes('/api/auth/login') && !path.includes('/api/setup/initialize')) {
      const detail = await response.json().catch(() => ({}));
      if (String(detail.detail || '').toLowerCase().includes('transport')) {
        showFatalTransport(detail.detail);
      } else if (!options.keepSessionOn401) {
        clearSession();
        showLogin();
      }
    }
    if (!response.ok) {
      const data = await response.json().catch(() => ({ detail: `${response.status} ${response.statusText}` }));
      const error = new Error(data.detail || 'Request failed');
      error.status = response.status;
      error.data = data;
      throw error;
    }
    if (options.raw) return response;
    if (response.status === 204) return null;
    return response.json();
  }

  function clearSession() {
    state.token = '';
    state.user = null;
    sessionStorage.removeItem('yashsec_token');
  }

  function hasPermission(code) {
    return Boolean(state.user?.permissions?.includes(code));
  }

  function showFatalTransport(message) {
    document.body.innerHTML = `<div class="auth-view"><section class="login-card"><div class="brand-hex large">YS</div><div class="eyebrow">DESKTOP SECURITY BOUNDARY</div><h1>Transport authentication failed</h1><p>${escapeHtml(message || 'Launch YashSec through the desktop application or start the backend without transport protection only for local development.')}</p><div class="teaching-note warning"><b>Safe recovery</b><span>Close this window and relaunch YashSec Autopilot. Do not expose the backend to a LAN address.</span></div></section></div>`;
  }

  function toast(title, message = '', type = 'success', duration = 5200) {
    const node = document.createElement('article');
    node.className = `toast ${type}`;
    node.innerHTML = `<b>${escapeHtml(title)}</b>${message ? `<p>${escapeHtml(message)}</p>` : ''}`;
    $('#toastArea').append(node);
    setTimeout(() => node.remove(), duration);
  }

  function setBanner(message, type = 'warning') {
    const banner = $('#globalBanner');
    if (!message) return banner.classList.add('hidden');
    banner.className = `banner ${type}`;
    banner.textContent = message;
  }

  function showOnly(id) {
    ['setupView', 'loginView', 'appShell'].forEach((item) => $(`#${item}`).classList.toggle('hidden', item !== id));
  }

  function showLogin() {
    showOnly('loginView');
    $('#loginPassword').value = '';
    $('#loginMessage').classList.add('hidden');
  }

  function showSetup() {
    showOnly('setupView');
    setSetupStep(1);
  }

  function showApp() {
    if (state.demoMode) {
      setBanner('Public read-only portfolio demo. Use only the bundled sample data and never paste credentials or private source code.', 'warning');
      const badge = $('#privacyBadge');
      if (badge) badge.innerHTML = '<i></i>Read-only demo';
    } else {
      setBanner('');
    }
    // Enter the shell immediately. Repository/tool metadata loads in the
    // background so a slow optional executable can never hold the login screen.
    showOnly('appShell');
    updateProfile();
    applyPermissions();
    navigate('overview');
    void loadCommonData().catch((error) => {
      console.warn('Background workspace metadata could not be loaded:', error);
      updateHealthIndicators();
    });
  }

  function setSetupStep(step) {
    $$('.wizard-step').forEach((node) => node.classList.add('hidden'));
    const target = step === 2 ? '#setupOwnerForm' : `#setupStep${step}`;
    $(target)?.classList.remove('hidden');
    $$('[data-step-dot]').forEach((dot) => {
      const number = Number(dot.dataset.stepDot);
      dot.classList.toggle('active', number === step);
      dot.classList.toggle('complete', number < step);
    });
    if (step === 3) renderSetupTools();
    if (step === 4) renderSetupSummary();
  }

  async function renderSetupTools() {
    const target = $('#setupToolSummary');
    target.classList.add('loading-block');
    try {
      const payload = await api('/api/tools?refresh=true');
      state.tools = payload.tools || [];
      state.aiHealth = payload.ai || null;
      target.innerHTML = state.tools.slice(0, 7).map((tool) => `<div class="mini-tool"><span>${escapeHtml(tool.name)}</span><span class="badge ${tool.available ? 'success' : 'neutral'}">${tool.available ? 'Connected' : 'Optional'}</span></div>`).join('');
    } catch (error) {
      target.innerHTML = `<div class="inline-alert">${escapeHtml(error.message)}</div>`;
    } finally {
      target.classList.remove('loading-block');
    }
  }

  function renderSetupSummary() {
    const installed = state.tools.filter((tool) => tool.available).length;
    const optional = state.tools.length - installed;
    $('#setupReadySummary').innerHTML = `<b>Core workspace ready</b><span>${installed} optional capabilities detected; ${optional} can be connected later through Tool Manager.</span><span>First recommended action: add a local repository and run a Quick scan.</span>`;
  }

  async function bootstrap() {
    captureTransportToken();
    bindEvents();
    applyTheme(localStorage.getItem('yashsec_theme') || 'dark');
    document.body.classList.toggle('reduce-motion', localStorage.getItem('yashsec_reduce_motion') === 'true');
    try {
      const health = await api('/api/health', { keepSessionOn401: true });
      $$('[data-version]').forEach((node) => { node.textContent = health.version; });
      $('#backendState').textContent = health.status === 'ok' ? 'Backend healthy' : 'Backend degraded';
      const setup = await api('/api/setup/status', { keepSessionOn401: true });
      state.demoMode = Boolean(setup.demo_mode);
      $('#demoLogin')?.classList.toggle('hidden', !state.demoMode);
      $('#demoLoginNotice')?.classList.toggle('hidden', !state.demoMode);
      if (state.demoMode) {
        $('#loginPrivacyText').textContent = 'Read-only public demo. Ollama Cloud is optional and configured only through deployment secrets.';
      }
      if (setup.required) return showSetup();
      if (state.token) {
        try {
          state.user = await api('/api/auth/me');
          return showApp();
        } catch (_) {
          clearSession();
        }
      }
      showLogin();
    } catch (error) {
      $('#backendState').textContent = 'Backend unavailable';
      showLogin();
      const box = $('#loginMessage');
      box.textContent = `Backend connection failed: ${error.message}`;
      box.classList.remove('hidden');
    }
  }

  async function enterDemo() {
    const button = $('#demoLogin');
    if (button) { button.disabled = true; button.textContent = 'Opening demo…'; }
    try {
      const result = await api('/api/demo/session', { method: 'POST', body: JSON.stringify({}), keepSessionOn401: true });
      state.token = result.token;
      state.user = result.user;
      state.demoMode = true;
      sessionStorage.setItem('yashsec_token', state.token);
      showApp();
    } catch (error) {
      const box = $('#loginMessage');
      box.textContent = error.message;
      box.classList.remove('hidden');
    } finally {
      if (button) { button.disabled = false; button.textContent = 'Open read-only live demo'; }
    }
  }

  async function loadCommonData() {
    const tasks = [
      api('/api/repositories').catch(() => []),
      api('/api/scans?limit=100').catch(() => []),
      api('/api/tools').catch(() => ({ tools: [], ai: null })),
    ];
    const [repositories, scans, toolsPayload] = await Promise.all(tasks);
    state.repositories = repositories;
    state.scans = scans;
    state.tools = toolsPayload.tools || [];
    state.aiHealth = toolsPayload.ai || null;
    updateHealthIndicators();
    populateRepositorySelects();
  }

  function updateProfile() {
    const user = state.user || {};
    $('#profileName').textContent = user.username || 'User';
    $('#profileAvatar').textContent = (user.username || 'Y').slice(0, 1).toUpperCase();
    $('#profileRole').textContent = (user.roles || []).map(titleCase).join(', ') || titleCase(user.role);
  }

  function applyPermissions() {
    $$('.permission-audit-read').forEach((node) => node.classList.toggle('hidden', !hasPermission('audit.read')));
    $('#newScanTop').classList.toggle('hidden', !hasPermission('scans.create'));
  }

  function updateHealthIndicators() {
    const installed = state.tools.filter((tool) => tool.available).length;
    $('#scannerHealthText').textContent = `${installed}/${state.tools.length || 0} optional tools connected`;
    const provider = state.aiHealth?.config?.provider || 'ollama';
    const healthy = Boolean(state.aiHealth?.[provider]);
    $('#aiStatusText').textContent = healthy ? `${titleCase(provider)} connected` : `${titleCase(provider)} unavailable`;
    $('#aiStatusDot').className = `status-dot ${healthy ? 'success' : 'warning'}`;
  }

  function populateRepositorySelects() {
    const options = state.repositories.length
      ? state.repositories.map((repo) => `<option value="${repo.id}">${escapeHtml(repo.name)}</option>`).join('')
      : '<option value="">No projects</option>';
    $('#scanRepository').innerHTML = options;
    $('#assistantRepo').innerHTML = options;
    if (state.repositories[0]) {
      loadScanRepository(state.repositories[0].id);
      updateAiContext(state.repositories[0]);
    }
  }

  function navigate(view, options = {}) {
    if (!pageInfo[view]) view = 'overview';
    state.view = view;
    $$('.nav-item').forEach((node) => node.classList.toggle('active', node.dataset.view === view));
    const [eyebrow, title, subtitle] = pageInfo[view];
    $('#pageEyebrow').textContent = eyebrow;
    $('#pageTitle').textContent = title;
    $('#pageSubtitle').textContent = subtitle;
    $('#projectBreadcrumb').textContent = title;
    setBanner('');
    renderView(view, options);
  }

  async function renderView(view, options = {}) {
    const content = $('#content');
    content.innerHTML = '<div class="panel loading-block" style="min-height:220px"></div>';
    try {
      if (view === 'overview') await renderOverview();
      else if (view === 'projects') await renderProjects();
      else if (view === 'scans') await renderScans(options.scanId);
      else if (view === 'findings') await renderFindings();
      else if (view === 'assistant') renderAssistantWorkspace();
      else if (view === 'reports') await renderReports();
      else if (view === 'audit') await renderAudit();
      else if (view === 'tools') await renderTools();
      else if (view === 'settings') await renderSettings();
    } catch (error) {
      content.innerHTML = errorState('This screen could not be loaded', error.message);
    }
  }

  const metricCard = (label, value, detail, tone = '') => `<article class="metric-card ${tone}"><span class="metric-label">${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong><small>${escapeHtml(detail)}</small></article>`;
  const badge = (value, override) => `<span class="badge ${override || String(value || '').toLowerCase()}">${escapeHtml(titleCase(value))}</span>`;
  const emptyState = (title, message, action = '') => `<div class="empty-state"><div class="empty-shield">YS</div><h2>${escapeHtml(title)}</h2><p>${escapeHtml(message)}</p>${action}</div>`;
  const errorState = (title, message) => emptyState(title, message, '<button class="button quiet" onclick="location.reload()">Reload application</button>');

  async function renderOverview() {
    const dashboard = await api('/api/dashboard');
    const sev = dashboard.severities || {};
    const score = dashboard.recent_scans?.[0]?.summary?.security_score;
    $('#content').innerHTML = `
      <section class="metric-grid">
        ${metricCard('Security score', score ?? '—', score == null ? 'Run a scan to establish a baseline' : 'Score never overrides critical findings or coverage', 'mint')}
        ${metricCard('Critical findings', sev.critical || 0, 'Open evidence requiring immediate review', 'critical')}
        ${metricCard('High findings', sev.high || 0, 'Prioritise alongside confidence and reachability', 'warning')}
        ${metricCard('All findings', dashboard.findings || 0, 'Across repositories visible to your account', 'blue')}
        ${metricCard('Missing tools', dashboard.missing_tools || 0, 'Optional capabilities not currently connected')}
      </section>
      <section class="two-panel">
        <article class="panel"><header class="panel-header"><div><h2>Priority queue</h2><p>Evidence that deserves attention first</p></div><button class="button quiet compact" data-go="findings">Open findings</button></header><div id="overviewPriority" class="panel-body priority-list"></div></article>
        <article class="panel"><header class="panel-header"><div><h2>Latest coverage</h2><p>Completed stages and visible gaps</p></div></header><div id="overviewCoverage" class="panel-body coverage-card"></div></article>
      </section>
      <section class="panel"><header class="panel-header"><div><h2>Recent scan activity</h2><p>Independent scanner failures do not erase completed evidence</p></div><button class="button primary compact" data-open-scan>New scan</button></header><div class="panel-body activity-list">${renderRecentScanList(dashboard.recent_scans || [])}</div></section>
      <section class="teaching-note"><b>Privacy by default</b><span>Repository code remains local while Ollama or AirLLM is selected. An external provider must never be enabled without project-owner approval.</span></section>`;
    const recent = dashboard.recent_scans || [];
    const latest = recent[0];
    $('#overviewCoverage').innerHTML = renderCoverage(latest);
    const priority = await api('/api/findings?limit=5').catch(() => []);
    $('#overviewPriority').innerHTML = priority.length ? priority.map((finding) => `
      <button class="priority-item clickable" data-finding-id="${finding.id}" style="width:100%;text-align:left;background:transparent;color:inherit">
        ${badge(finding.severity)}<span><b>${escapeHtml(finding.title)}</b><small>${escapeHtml(shortPath(finding.file_path || finding.endpoint || finding.category))}</small></span><span>›</span>
      </button>`).join('') : emptyState('No findings yet', 'Add a project and run a scan. No findings detected is not proof of complete security.');
    bindDynamicActions();
  }

  function renderCoverage(scan) {
    if (!scan) return emptyState('No coverage baseline', 'Run a scan to see exactly what was and was not tested.');
    const coverage = scan.coverage || {};
    const entries = Object.entries(coverage).filter(([, value]) => typeof value === 'string');
    const completed = entries.filter(([, value]) => value === 'completed').length;
    const pct = entries.length ? Math.round((completed / entries.length) * 100) : 0;
    return `<div class="coverage-ring" style="--pct:${pct}"><div><strong>${pct}%</strong><small>stage coverage</small></div></div><div class="coverage-legend">${entries.map(([key, value]) => `<div><span>${escapeHtml(titleCase(key))}</span>${badge(value, value === 'completed' ? 'success' : value)}</div>`).join('')}</div>`;
  }

  function renderRecentScanList(scans) {
    if (!scans.length) return emptyState('No scan history', 'Your first Quick scan can run with the built-in scanner even when every optional tool is missing.');
    return scans.map((scan) => `<button class="activity-item clickable" data-scan-id="${scan.id}" style="width:100%;text-align:left;background:transparent;color:inherit"><span class="status-dot ${scan.status === 'completed' ? 'success' : scan.status === 'failed' ? 'error' : scan.status === 'running' ? 'success' : 'warning'}"></span><span><b>${escapeHtml(scan.repository_name || `Project ${scan.repository_id}`)} · ${escapeHtml(titleCase(scan.profile))}</b><small>${escapeHtml(formatDate(scan.created_at))} · ${(scan.summary?.total ?? 0)} finding(s)</small></span>${badge(scan.status, scan.status === 'completed_partial' ? 'warning' : scan.status)}</button>`).join('');
  }

  async function renderProjects() {
    state.repositories = await api('/api/repositories');
    populateRepositorySelects();
    const action = hasPermission('projects.create') ? '<button class="button primary" data-open-project>＋ Add project</button>' : '';
    if (!state.repositories.length) {
      $('#content').innerHTML = emptyState('Add your first project', 'Use a local folder, Git repository or safely extracted ZIP. Detected commands will require explicit approval.', action);
      bindDynamicActions();
      return;
    }
    $('#content').innerHTML = `<div class="card-grid">${state.repositories.map((repo) => renderProjectCard(repo)).join('')}</div>`;
    bindDynamicActions();
  }

  function renderProjectCard(repo) {
    const stacks = (repo.detected_stack || []).map((item) => `<span class="tag">${escapeHtml(item)}</span>`).join('') || '<span class="tag">Stack not identified</span>';
    const candidate = repo.startup_candidates?.[0];
    return `<article class="project-card"><header><div><div class="eyebrow">${escapeHtml(repo.source_type)} / PROJECT ${repo.id}</div><h3>${escapeHtml(repo.name)}</h3></div>${badge(candidate ? 'detected' : 'needs confirmation', candidate ? 'success' : 'warning')}</header><div class="meta-list"><div class="meta-row"><span>Location</span><span title="${escapeHtml(repo.local_path)}">${escapeHtml(shortPath(repo.local_path))}</span></div><div class="meta-row"><span>Branch</span><span>${escapeHtml(repo.default_branch || 'Local working tree')}</span></div><div class="meta-row"><span>Command</span><span class="mono">${escapeHtml(candidate?.command || 'Not detected')}</span></div><div class="meta-row"><span>Ports</span><span>${escapeHtml((repo.port_hints || []).slice(0, 6).join(', ') || 'Not detected')}</span></div></div><div class="tag-row">${stacks}</div><div class="card-actions"><button class="button primary compact" data-scan-repo="${repo.id}">Run scan</button><button class="button quiet compact" data-project-detail="${repo.id}">Inspect</button>${hasPermission('auth_profiles.manage') ? `<button class="button quiet compact" data-auth-profile="${repo.id}">Auth profile</button>` : ''}</div></article>`;
  }

  async function showProjectDetail(id) {
    const repo = await api(`/api/repositories/${id}`);
    const authRows = (repo.auth_profiles || []).map((profile) => `<div class="activity-item"><span class="status-dot ${profile.last_verified_at ? 'success' : ''}"></span><span><b>${escapeHtml(profile.name)}</b><small>${escapeHtml(titleCase(profile.auth_type))} · ${profile.last_verified_at ? `verified ${formatDate(profile.last_verified_at)}` : 'not tested'}</small></span>${badge(profile.enabled ? 'enabled' : 'disabled', profile.enabled ? 'success' : 'neutral')}</div>`).join('');
    $('#findingModalTitle').textContent = repo.name;
    $('#findingModalBody').innerHTML = `<div class="finding-layout"><div class="finding-main"><div class="finding-summary"><h3>Deterministic repository detection</h3><p>High-confidence facts remain distinct from assumptions. A materially changed command requires fresh approval.</p></div><div class="detail-grid"><div class="detail-cell"><span>Source</span><strong>${escapeHtml(titleCase(repo.source_type))}</strong></div><div class="detail-cell"><span>OpenAPI</span><strong>${escapeHtml(repo.detected_openapi || 'Not detected')}</strong></div><div class="detail-cell"><span>Runtime</span><strong>${escapeHtml(repo.runtime?.running ? 'Running' : 'Stopped')}</strong></div></div><div class="evidence-box"><header>Detected startup candidates</header><pre>${escapeHtml((repo.startup_candidates || []).map((c) => `${Math.round(c.confidence * 100)}% · ${c.command}\nSource: ${c.source}\n${c.notes || ''}`).join('\n\n') || 'No startup command detected.')}</pre></div><div class="panel"><header class="panel-header"><div><h2>Authenticated API profiles</h2><p>Only metadata is shown. Secret values are protected and never returned.</p></div></header><div class="panel-body activity-list">${authRows || '<p style="color:var(--text-2)">No authentication profiles configured.</p>'}</div></div></div><aside class="review-pane"><h3>Detected facts</h3><div class="tag-row">${(repo.detected_stack || []).map((s) => `<span class="tag">${escapeHtml(s)}</span>`).join('')}</div><div class="meta-list"><div class="meta-row"><span>Local path</span><span>${escapeHtml(repo.local_path)}</span></div><div class="meta-row"><span>Port hints</span><span>${escapeHtml((repo.port_hints || []).join(', '))}</span></div></div><button class="button primary" data-scan-repo="${repo.id}">Configure scan</button>${hasPermission('projects.update') ? `<button class="button quiet" data-redetect="${repo.id}">Run detection again</button>` : ''}</aside></div>`;
    openModal('findingModal');
    bindDynamicActions();
  }

  async function renderScans(focusScanId) {
    state.scans = await api('/api/scans?limit=150');
    if (focusScanId) state.currentScanId = Number(focusScanId);
    if (state.currentScanId) {
      const current = await api(`/api/scans/${state.currentScanId}`).catch(() => null);
      if (current && !FINAL_SCAN_STATES.has(current.status)) return renderLiveScan(current);
    }
    const body = state.scans.length ? `<div class="table-shell"><table><thead><tr><th>Status</th><th>Project / profile</th><th>Coverage</th><th>Findings</th><th>Started</th><th>Action</th></tr></thead><tbody>${state.scans.map((scan) => `<tr><td>${badge(scan.status, scan.status === 'completed_partial' ? 'warning' : scan.status)}</td><td><strong>${escapeHtml(scan.repository_name || `Project ${scan.repository_id}`)}</strong><span class="subtext">${escapeHtml(titleCase(scan.profile))} · ${(scan.selected_tools || []).join(', ')}</span></td><td>${scan.summary?.coverage_complete ? badge('complete', 'success') : badge('partial', 'warning')}</td><td><strong>${scan.summary?.total ?? 0}</strong><span class="subtext">Critical ${scan.summary?.critical ?? 0} · High ${scan.summary?.high ?? 0}</span></td><td>${escapeHtml(formatDate(scan.started_at || scan.created_at))}</td><td><button class="button quiet compact" data-scan-id="${scan.id}">Open</button></td></tr>`).join('')}</tbody></table></div>` : emptyState('No scans yet', 'A Quick scan always includes the built-in scanner and can run without external tools.', '<button class="button primary" data-open-scan>Run first scan</button>');
    $('#content').innerHTML = body;
    bindDynamicActions();
  }

  async function openScan(id) {
    state.currentScanId = Number(id);
    const scan = await api(`/api/scans/${id}`);
    if (!FINAL_SCAN_STATES.has(scan.status)) {
      navigate('scans', { scanId: id });
      return;
    }
    const log = await api(`/api/scans/${id}/log`).catch(() => ({ log: '' }));
    const stages = scan.stages || {};
    $('#findingModalTitle').textContent = `${scan.repository_name || 'Project'} · Scan ${scan.id}`;
    $('#findingModalBody').innerHTML = `<div class="live-layout"><div><div class="stage-list">${renderStages(stages)}</div></div><aside><div class="coverage-card panel">${renderCoverage(scan)}</div><div class="card-actions"><button class="button primary" data-findings-scan="${scan.id}">Open findings</button>${hasPermission('reports.generate') ? `<button class="button quiet" data-report-download="${scan.id}" data-format="docx">Export DOCX</button>` : ''}</div></aside></div><details style="margin-top:16px"><summary>Diagnostic log</summary><pre class="log-surface">${escapeHtml(log.log || 'No log available')}</pre></details>`;
    openModal('findingModal');
    bindDynamicActions();
  }

  function renderStages(stages) {
    const preferred = ['runtime_start', 'builtin', 'semgrep', 'gitleaks', 'trivy', 'dynamic', 'schemathesis', 'zap', 'normalisation'];
    const keys = [...new Set([...preferred, ...Object.keys(stages || {})])].filter((key) => stages?.[key]);
    if (!keys.length) return '<div class="stage-item"><span class="stage-state">·</span><span><b>Preparing workspace</b><small>Waiting for stage data</small></span><span></span></div>';
    return keys.map((key) => {
      const stage = stages[key] || {};
      const cls = stage.status === 'completed_with_warnings' ? 'warning' : stage.status;
      const icon = stage.status === 'completed' ? '✓' : stage.status === 'running' ? '◌' : stage.status === 'failed' || stage.status === 'error' ? '!' : stage.status === 'skipped' ? '–' : '·';
      return `<div class="stage-item ${escapeHtml(cls)}"><span class="stage-state">${icon}</span><span><b>${escapeHtml(titleCase(key))}</b><small>${escapeHtml(stage.message || titleCase(stage.status))}</small></span>${badge(stage.status || 'waiting', stage.status === 'completed_with_warnings' ? 'warning' : stage.status)}</div>`;
    }).join('');
  }

  function renderLiveScan(scan) {
    $('#content').innerHTML = `<section class="live-layout"><article class="panel"><header class="panel-header"><div><h2>${escapeHtml(scan.repository_name || 'Project')} · ${escapeHtml(titleCase(scan.profile))} scan</h2><p>Stage-based progress. Independent scanners continue after another tool fails.</p></div>${hasPermission('scans.cancel') ? `<button class="button danger compact" data-cancel-scan="${scan.id}">Cancel safely</button>` : ''}</header><div class="panel-body stage-list" id="liveStages">${renderStages(scan.stages)}</div></article><aside><div class="panel coverage-card" id="liveCoverage">${renderCoverage(scan)}</div><article class="panel" style="margin-top:16px"><header class="panel-header"><div><h2>Evidence discovered</h2><p>Not final until normalisation completes</p></div></header><div class="panel-body"><strong style="font-size:34px">${scan.finding_count ?? scan.summary?.total ?? 0}</strong><p style="color:var(--text-2)">${escapeHtml(titleCase(scan.status))}</p></div></article></aside></section><details class="panel"><summary style="padding:14px">Live diagnostic log</summary><pre id="liveLog" class="log-surface" style="margin:0 14px 14px">Loading...</pre></details>`;
    bindDynamicActions();
    pollScan(scan.id);
  }

  async function pollScan(id) {
    if (state.view !== 'scans' || state.currentScanId !== Number(id)) return;
    try {
      const [scan, log] = await Promise.all([api(`/api/scans/${id}`), api(`/api/scans/${id}/log`).catch(() => ({ log: '' }))]);
      $('#liveStages') && ($('#liveStages').innerHTML = renderStages(scan.stages));
      $('#liveCoverage') && ($('#liveCoverage').innerHTML = renderCoverage(scan));
      $('#liveLog') && ($('#liveLog').textContent = log.log || 'No log output yet.');
      if (FINAL_SCAN_STATES.has(scan.status)) {
        toast('Scan finished', scan.status === 'completed' ? 'All selected stages completed.' : `Status: ${titleCase(scan.status)}`, scan.status === 'failed' ? 'error' : 'success');
        await sleep(700);
        return renderScans();
      }
      setTimeout(() => pollScan(id), 1200);
    } catch (error) {
      setBanner(`Live scan refresh failed: ${error.message}`);
    }
  }

  async function renderFindings(filters = {}) {
    const params = new URLSearchParams({ limit: '500' });
    Object.entries(filters).forEach(([key, value]) => value && params.set(key, value));
    state.findings = await api(`/api/findings?${params}`);
    const rows = state.findings.length ? state.findings.map((finding) => `<tr data-finding-id="${finding.id}" class="clickable"><td>${badge(finding.severity)}</td><td><strong>${escapeHtml(finding.title)}</strong><span class="subtext">${escapeHtml(finding.description)}</span></td><td><span class="mono">${escapeHtml(shortPath(finding.file_path || finding.endpoint || 'Repository-level'))}</span><span class="subtext">${finding.line_start ? `Line ${finding.line_start}` : ''}</span></td><td><strong>${escapeHtml(finding.tool)}</strong><span class="subtext">${escapeHtml([finding.cwe, finding.owasp].filter(Boolean).join(' · ') || finding.category || '')}</span></td><td>${badge(finding.confidence || 'medium', 'neutral')}</td><td>${badge(finding.review_status || 'open', finding.review_status === 'fixed' ? 'success' : 'neutral')}</td><td>${escapeHtml(formatDate(finding.last_seen_at || finding.created_at))}</td></tr>`).join('') : `<tr><td colspan="7">${emptyState('No matching findings', 'Change filters or run a scan. Absence of findings is not proof of complete security.')}</td></tr>`;
    $('#content').innerHTML = `<div class="table-toolbar"><input id="findingSearch" placeholder="Search title, evidence, file or endpoint"><select id="findingSeverity"><option value="">All severities</option>${severityOrder.map((s) => `<option value="${s}">${titleCase(s)}</option>`).join('')}</select><select id="findingStatus"><option value="">All statuses</option><option>open</option><option>reviewed</option><option>false_positive</option><option>accepted_risk</option><option>fixed</option></select><button id="applyFindingFilters" class="button quiet compact">Apply</button></div><div class="table-shell" style="border-radius:0 0 var(--radius-card) var(--radius-card)"><table><thead><tr><th>Severity</th><th>Finding</th><th>Affected asset</th><th>Scanner / classification</th><th>Confidence</th><th>Status</th><th>Latest</th></tr></thead><tbody>${rows}</tbody></table></div>`;
    bindDynamicActions();
    $('#applyFindingFilters').onclick = () => renderFindings({ search: $('#findingSearch').value, severity: $('#findingSeverity').value, review_status: $('#findingStatus').value });
    $('#findingSearch').addEventListener('keydown', (event) => { if (event.key === 'Enter') $('#applyFindingFilters').click(); });
  }

  async function openFinding(id) {
    const finding = await api(`/api/findings/${id}`);
    state.selectedFinding = finding;
    state.currentFindingIdForAi = finding.id;
    $('#findingModalTitle').textContent = finding.title;
    const location = [finding.file_path, finding.line_start ? `line ${finding.line_start}` : null, finding.function_name, finding.endpoint].filter(Boolean).join(' · ') || 'Repository-level evidence';
    $('#findingModalBody').innerHTML = `<div class="finding-layout"><main class="finding-main"><div class="finding-summary"><div class="tag-row">${badge(finding.severity)}${badge(finding.confidence || 'medium', 'neutral')}${badge(finding.review_status || 'open', 'neutral')}${badge(finding.tool, 'neutral')}</div><h3>Why this matters</h3><p>${escapeHtml(finding.description || 'No plain-language description was supplied by the scanner.')}</p></div><div class="detail-grid"><div class="detail-cell"><span>Location</span><strong>${escapeHtml(location)}</strong></div><div class="detail-cell"><span>CWE / OWASP</span><strong>${escapeHtml([finding.cwe, finding.owasp].filter(Boolean).join(' · ') || 'Not mapped')}</strong></div><div class="detail-cell"><span>Occurrence</span><strong>${escapeHtml(`${formatDate(finding.first_seen_at)} → ${formatDate(finding.last_seen_at)}`)}</strong></div></div><div class="evidence-box"><header>Scanner-confirmed evidence</header><pre>${escapeHtml(finding.evidence || 'No evidence payload was supplied.')}</pre></div><div class="finding-summary"><h3>Recommended remediation</h3><p>${escapeHtml(finding.remediation || 'Review the affected code and confirm intended business behaviour before applying a change.')}</p></div><button class="button quiet" data-ai-finding="${finding.id}">✦ Explain with local AI</button></main><aside class="review-pane"><h3>Human review</h3><label>Status<select id="reviewStatus"><option value="open">Open</option><option value="reviewed">Reviewed</option><option value="false_positive">False positive</option><option value="accepted_risk">Accepted risk</option><option value="fixed">Fixed</option></select></label><label>Reviewer notes<textarea id="reviewNotes" rows="8" placeholder="Record evidence, rationale or business clarification needed.">${escapeHtml(finding.reviewer_notes || '')}</textarea></label><button id="saveFindingReview" class="button primary">Save review</button><div class="review-history">AI cannot change this status. Accepted risk requires fresh password confirmation and a meaningful reason.</div></aside></div>`;
    $('#reviewStatus').value = finding.review_status || 'open';
    openModal('findingModal');
    $('#saveFindingReview').onclick = () => saveFindingReview(finding.id);
    bindDynamicActions();
  }

  async function saveFindingReview(id) {
    const review_status = $('#reviewStatus').value;
    const reviewer_notes = $('#reviewNotes').value;
    const execute = async (stepUpToken = '') => {
      await api(`/api/findings/${id}`, { method: 'PATCH', headers: stepUpToken ? { 'X-Step-Up-Token': stepUpToken } : {}, body: JSON.stringify({ review_status, reviewer_notes }) });
      toast('Finding updated', `Status: ${titleCase(review_status)}`);
      closeModals();
      if (state.view === 'findings') renderFindings();
    };
    if (review_status === 'accepted_risk') {
      if (reviewer_notes.trim().length < 10) return toast('Reason required', 'Accepted risk requires a meaningful reviewer justification.', 'warning');
      requestReauth('accept-risk', 'Accepting security risk requires fresh password verification.', execute);
    } else {
      try { await execute(); } catch (error) { toast('Update failed', error.message, 'error'); }
    }
  }

  function renderAssistantWorkspace() {
    $('#content').innerHTML = `<section class="two-panel"><article class="panel"><header class="panel-header"><div><h2>Local analysis workspace</h2><p>Scanner evidence, repository excerpts and AI interpretation remain visibly distinct.</p></div><button class="button primary" id="openAssistantPane">Open docked assistant</button></header><div class="panel-body"><div class="teaching-note"><b>Trust contract</b><span>Project files are untrusted data, not instructions. Known secret files are excluded from context. AI never runs commands, changes findings or edits files.</span></div><div class="three-panel" style="margin-top:14px"><div class="settings-card"><h3>Ollama</h3><p>Recommended for interactive local questions and focused remediation suggestions.</p>${badge(state.aiHealth?.ollama ? 'connected' : 'unavailable', state.aiHealth?.ollama ? 'success' : 'warning')}</div><div class="settings-card"><h3>AirLLM</h3><p>Optional worker for slower, deeper batch reasoning and larger-model experiments.</p>${badge(state.aiHealth?.airllm ? 'connected' : 'unavailable', state.aiHealth?.airllm ? 'success' : 'warning')}</div><div class="settings-card"><h3>Context policy</h3><p>Responses label evidence, interpretation, assumptions and missing information.</p>${badge('local-first', 'success')}</div></div></div></article><article class="panel"><header class="panel-header"><div><h2>Suggested questions</h2><p>Choose a project in the docked pane</p></div></header><div class="panel-body priority-list">${['Where is authentication implemented?', 'Summarise critical findings.', 'Which logging statements may expose personal data?', 'Why did this scanner fail?', 'Draft a safe replacement without applying it.'].map((q) => `<button class="priority-item ai-suggest" data-question="${escapeHtml(q)}" style="width:100%;background:transparent;color:inherit;text-align:left"><span>✦</span><span><b>${escapeHtml(q)}</b><small>Uses selected repository context</small></span><span>›</span></button>`).join('')}</div></article></section>`;
    $('#openAssistantPane').onclick = openInspector;
    $$('.ai-suggest').forEach((button) => button.onclick = () => { openInspector(); $('#assistantQuestion').value = button.dataset.question; $('#assistantQuestion').focus(); });
  }

  async function renderReports() {
    state.scans = await api('/api/scans?limit=100');
    const finalScans = state.scans.filter((scan) => FINAL_SCAN_STATES.has(scan.status));
    $('#content').innerHTML = `<div class="card-grid">${[
      ['Executive', 'Management-ready risk posture and coverage limitations.'],
      ['Technical', 'Evidence, classifications, locations and remediation.'],
      ['Developer remediation', 'Action-focused findings for engineering teams.'],
      ['Audit', 'Coverage, review status and traceability.'],
      ['Selected findings', 'Focused export for a chosen scope.'],
      ['Scan comparison', 'Added, resolved, reopened and unchanged evidence.'],
    ].map(([name, desc], index) => `<article class="report-card"><div class="eyebrow">TEMPLATE ${String(index + 1).padStart(2, '0')}</div><h3>${name}</h3><p>${desc}</p>${index < 4 ? badge('available', 'success') : badge('planned', 'neutral')}</article>`).join('')}</div><article class="panel"><header class="panel-header"><div><h2>Previous scans</h2><p>DOCX, HTML and JSON exports include partial-coverage warnings.</p></div></header><div class="panel-body activity-list">${finalScans.length ? finalScans.map((scan) => `<div class="activity-item"><span>${badge(scan.status, scan.status === 'completed_partial' ? 'warning' : scan.status)}</span><span><b>${escapeHtml(scan.repository_name)} · scan ${scan.id}</b><small>${formatDate(scan.completed_at || scan.created_at)} · ${scan.summary?.total ?? 0} findings</small></span><span class="card-actions" style="margin:0;padding:0;border:0"><button class="button quiet compact" data-report-download="${scan.id}" data-format="docx">DOCX</button><button class="button quiet compact" data-report-download="${scan.id}" data-format="html">HTML</button><button class="button quiet compact" data-report-download="${scan.id}" data-format="json">JSON</button></span></div>`).join('') : emptyState('No completed scans', 'Complete a scan before exporting an evidence report.')}</div></article>`;
    bindDynamicActions();
  }

  async function downloadReport(scanId, format) {
    try {
      const response = await api(`/api/reports/${scanId}?format=${format}`, { raw: true });
      const blob = await response.blob();
      const disposition = response.headers.get('content-disposition') || '';
      const match = disposition.match(/filename="?([^";]+)"?/i);
      const filename = match?.[1] || `yashsec-scan-${scanId}.${format}`;
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url; anchor.download = filename; anchor.click();
      setTimeout(() => URL.revokeObjectURL(url), 5000);
      toast('Report generated', filename);
    } catch (error) { toast('Report generation failed', error.message, 'error'); }
  }

  async function renderAudit() {
    if (!hasPermission('audit.read')) return $('#content').innerHTML = emptyState('Permission required', 'Your account cannot read audit history.');
    const [events, verification] = await Promise.all([api('/api/audit?limit=500'), api('/api/audit/verify')]);
    $('#content').innerHTML = `<div class="teaching-note ${verification.valid ? '' : 'warning'}"><b>${verification.valid ? 'Hash chain verified' : 'Integrity warning'}</b><span>${escapeHtml(verification.message)} Local audit is tamper-evident, not magically immutable against a Windows administrator.</span></div><div class="table-shell"><table><thead><tr><th>Time</th><th>User</th><th>Action</th><th>Result</th><th>Resource</th><th>Correlation</th></tr></thead><tbody>${events.map((event) => `<tr><td>${escapeHtml(formatDate(event.created_at || event.timestamp))}</td><td>${escapeHtml(event.username || 'System')}</td><td><strong>${escapeHtml(titleCase(event.action))}</strong><span class="subtext">${escapeHtml(event.purpose || '')}</span></td><td>${badge(event.result, event.result === 'success' ? 'success' : event.result === 'failure' ? 'error' : 'neutral')}</td><td>${escapeHtml(`${event.resource_type || '—'}${event.resource_id ? ` #${event.resource_id}` : ''}`)}</td><td><span class="mono">${escapeHtml((event.correlation_id || '').slice(0, 14) || '—')}</span></td></tr>`).join('')}</tbody></table></div>`;
  }

  async function renderTools() {
    const payload = await api('/api/tools?refresh=true');
    state.tools = payload.tools || [];
    state.aiHealth = payload.ai || null;
    updateHealthIndicators();
    const aiCards = [
      { key: 'ollama-ai', name: 'Ollama local AI', purpose: 'Interactive local assistant. Recommended default.', available: state.aiHealth?.ollama, version: state.aiHealth?.config?.ollama_model, path: state.aiHealth?.config?.ollama_url, official_url: 'https://ollama.com/download/windows' },
      { key: 'airllm-ai', name: 'AirLLM worker', purpose: 'Optional deep/batch local analysis service.', available: state.aiHealth?.airllm, path: state.aiHealth?.config?.airllm_url, official_url: 'docs/OLLAMA_AND_AIRLLM_GUIDE.md' },
    ];
    $('#content').innerHTML = `<div class="teaching-note"><b>Capability model</b><span>A missing optional tool blocks only the related scanner. Built-in scanning, review and reporting remain available.</span></div><div class="card-grid">${[...state.tools, ...aiCards].map((tool) => `<article class="tool-card ${tool.available ? '' : 'unavailable'}"><header><div><h3>${escapeHtml(tool.name)}</h3><div class="tool-status-line"><span class="status-dot ${tool.available ? 'success' : 'warning'}"></span><span>${tool.available ? 'Installed and reachable' : 'Not connected'}</span></div></div>${badge(tool.available ? 'working' : 'optional', tool.available ? 'success' : 'warning')}</header><p>${escapeHtml(tool.purpose || '')}</p>${!tool.available ? `<div class="impact">Affected feature will be skipped and recorded as partial coverage.</div>` : ''}<code>${escapeHtml(tool.path || 'Executable or service not detected')}</code>${tool.version ? `<p>Version: ${escapeHtml(tool.version)}</p>` : ''}<div class="card-actions"><button class="button quiet compact" data-refresh-tools>Test again</button>${tool.official_url?.startsWith('http') ? `<button class="button quiet compact" data-external-url="${escapeHtml(tool.official_url)}">Official guide</button>` : ''}</div></article>`).join('')}</div>`;
    bindDynamicActions();
  }

  async function renderSettings() {
    const [ai, setup, backups] = await Promise.all([api('/api/ai/settings'), api('/api/setup/status'), hasPermission('backups.manage') ? api('/api/backups') : Promise.resolve([])]);
    $('#content').innerHTML = `<div class="settings-sections"><article class="settings-card"><h3>General and appearance</h3><p>Quiet Power uses a Windows-native graphite structure, restrained mint signals and evidence-first density.</p><div class="setting-row"><div><b>Theme</b><span>Dark and semantic light themes share the same trust language.</span></div><select id="settingsTheme"><option value="dark">Quiet Power dark</option><option value="light">Quiet Power light</option></select></div><div class="setting-row"><div><b>Reduced motion</b><span>Replace transitions with crossfades and static state indicators.</span></div><button id="settingsMotion" class="switch ${document.body.classList.contains('reduce-motion') ? 'on' : ''}" aria-label="Toggle reduced motion"></button></div></article><article class="settings-card"><h3>Storage and recovery</h3><p>User data is outside Program Files and survives normal upgrades and uninstall unless explicitly removed.</p><div class="setting-row"><div><b>Data directory</b><span>${escapeHtml(setup.data_directory)}</span></div><code>${escapeHtml(setup.database_path)}</code></div>${hasPermission('backups.manage') ? `<div class="setting-row"><div><b>Database backups</b><span>${backups.length} verified backup record(s). SQLite online backup is used.</span></div><button id="createBackup" class="button quiet">Create backup</button></div>` : ''}</article><article class="settings-card"><h3>AI provider</h3><p>Local Ollama is the privacy-first default. Ollama Cloud is supported only through explicit allow-listing and a deployment secret; AirLLM remains optional.</p><form id="aiSettingsForm" class="stack"><div class="two-col"><label>Provider<select id="aiProvider"><option value="ollama">Ollama</option><option value="airllm">AirLLM</option></select></label><label>Ollama model<input id="ollamaModel" value="${escapeHtml(ai.ollama_model)}"></label></div><label>Ollama endpoint<input id="ollamaUrl" value="${escapeHtml(ai.ollama_url)}"></label><label>AirLLM worker endpoint<input id="airllmUrl" value="${escapeHtml(ai.airllm_url)}"></label>${hasPermission('settings.manage') ? '<button class="button primary" type="submit">Save AI settings</button>' : '<div class="teaching-note warning"><b>Read-only</b><span>Your role cannot change application settings.</span></div>'}</form></article><article class="settings-card"><h3>Security boundary</h3><p>Backend address, transport authentication, database integrity and audit-chain status.</p><div id="securityDiagnostics" class="activity-list"></div></article></div>`;
    $('#settingsTheme').value = document.documentElement.dataset.theme || 'dark';
    $('#aiProvider').value = ai.provider;
    $('#settingsTheme').onchange = (event) => applyTheme(event.target.value);
    $('#settingsMotion').onclick = () => { document.body.classList.toggle('reduce-motion'); localStorage.setItem('yashsec_reduce_motion', document.body.classList.contains('reduce-motion')); $('#settingsMotion').classList.toggle('on'); };
    $('#createBackup') && ($('#createBackup').onclick = createBackup);
    $('#aiSettingsForm').onsubmit = saveAiSettings;
    const health = await api('/api/health');
    $('#securityDiagnostics').innerHTML = [
      ['Backend binding', health.bind, health.bind.startsWith('127.0.0.1') ? 'success' : 'error'],
      ['Desktop transport', health.transport_protected ? 'Per-launch token required' : 'Development mode', health.transport_protected ? 'success' : 'warning'],
      ['Database', health.database?.message, health.database?.healthy ? 'success' : 'error'],
      ['Audit chain', health.audit_chain?.message, health.audit_chain?.valid ? 'success' : 'error'],
    ].map(([name, detail, status]) => `<div class="activity-item"><span class="status-dot ${status}"></span><span><b>${escapeHtml(name)}</b><small>${escapeHtml(detail)}</small></span>${badge(status, status)}</div>`).join('');
  }

  async function saveAiSettings(event) {
    event.preventDefault();
    if (!hasPermission('settings.manage')) return;
    try {
      await api('/api/ai/settings', { method: 'PATCH', body: JSON.stringify({ ai_provider: $('#aiProvider').value, ollama_url: $('#ollamaUrl').value, ollama_model: $('#ollamaModel').value, airllm_url: $('#airllmUrl').value }) });
      toast('AI settings saved', 'Run Tool Manager health check to verify the provider.');
      await loadCommonData();
    } catch (error) { toast('Settings rejected', error.message, 'error'); }
  }

  async function createBackup() {
    try {
      const result = await api('/api/backups', { method: 'POST', body: JSON.stringify({ reason: 'manual-settings-backup' }) });
      toast('Backup created', shortPath(result.path || result.filename || `Backup ${result.id}`));
      renderSettings();
    } catch (error) { toast('Backup failed', error.message, 'error'); }
  }

  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem('yashsec_theme', theme);
    document.querySelector('meta[name="theme-color"]')?.setAttribute('content', theme === 'light' ? '#EDF2F5' : '#0B1019');
  }

  function openInspector() {
    $('#inspector').classList.add('open');
    if (state.selectedFinding) updateAiContext(state.repositories.find((repo) => repo.id === state.selectedFinding.repository_id), state.selectedFinding);
  }
  function closeInspector() { $('#inspector').classList.remove('open'); }
  function updateAiContext(repo, finding = null) {
    if (!repo) return $('#aiContextBar').innerHTML = '<span class="context-chip">No project context</span>';
    const chips = [repo.name, ...(repo.detected_stack || []).slice(0, 2), finding ? `Finding ${finding.id}` : null, finding?.tool].filter(Boolean);
    $('#aiContextBar').innerHTML = chips.map((chip) => `<span class="context-chip">${escapeHtml(chip)}</span>`).join('');
  }

  async function sendAssistant(event) {
    event.preventDefault();
    const repositoryId = Number($('#assistantRepo').value);
    const question = $('#assistantQuestion').value.trim();
    if (!repositoryId || !question) return;
    const messages = $('#assistantMessages');
    messages.insertAdjacentHTML('beforeend', `<article class="user-message"><b>You</b><p>${escapeHtml(question)}</p></article><article id="aiPending" class="ai-message loading-block"><b>Local assistant</b><p>Retrieving relevant local context...</p></article>`);
    $('#assistantQuestion').value = '';
    messages.scrollTop = messages.scrollHeight;
    try {
      const response = await api('/api/ai/chat', { method: 'POST', body: JSON.stringify({ repository_id: repositoryId, question, finding_id: state.currentFindingIdForAi, provider: $('#assistantProvider').value }) });
      $('#aiPending')?.remove();
      const context = (response.context || []).map((c) => `${c.file_path}:${c.line_start}`).join(' · ');
      messages.insertAdjacentHTML('beforeend', `<article class="ai-message"><b>${escapeHtml(titleCase(response.provider))} · Generated analysis</b><p>${escapeHtml(response.content)}</p>${context ? `<div class="tag-row"><span class="tag">Context: ${escapeHtml(context)}</span></div>` : ''}</article>`);
    } catch (error) {
      $('#aiPending')?.remove();
      messages.insertAdjacentHTML('beforeend', `<article class="ai-message"><b>Provider unavailable</b><p>${escapeHtml(error.message)}</p></article>`);
    }
    messages.scrollTop = messages.scrollHeight;
  }

  async function loadScanRepository(id) {
    if (!id) return;
    const repo = await api(`/api/repositories/${id}`).catch(() => null);
    if (!repo) return;
    $('#scanApiUrl').value = repo.runtime?.url || '';
    $('#scanOpenApi').value = repo.detected_openapi || '';
    const candidates = repo.startup_candidates || [];
    $('#startupCandidate').innerHTML = candidates.map((candidate, index) => `<option value="${escapeHtml(candidate.command)}">${Math.round(candidate.confidence * 100)}% · ${escapeHtml(candidate.label)}</option>`).join('');
    $('#startupPanel').classList.toggle('hidden', !candidates.length);
    $('#startupPreview').textContent = candidates[0]?.command || '';
    $('#confirmStartup').checked = false;
    $('#scanAuthProfile').innerHTML = '<option value="">Anonymous</option>' + (repo.auth_profiles || []).map((profile) => `<option value="${profile.id}">${escapeHtml(profile.name)} · ${escapeHtml(titleCase(profile.auth_type))}</option>`).join('');
    renderScannerGrid();
  }

  const profileTools = {
    quick: ['builtin', 'semgrep', 'gitleaks'],
    standard: ['builtin', 'semgrep', 'gitleaks', 'trivy'],
    full: ['builtin', 'semgrep', 'gitleaks', 'trivy', 'dynamic', 'schemathesis', 'zap'],
    custom: ['builtin'],
  };

  function renderScannerGrid() {
    const selected = new Set(profileTools[$('#scanProfile').value] || ['builtin']);
    const descriptions = {
      builtin: 'Always available fallback checks', semgrep: 'Language-aware static analysis', gitleaks: 'Hard-coded secrets', trivy: 'Dependencies and configuration', dynamic: 'Safe custom API checks', schemathesis: 'OpenAPI property testing', zap: 'Passive ZAP baseline',
    };
    const toolMap = Object.fromEntries(state.tools.map((tool) => [tool.key, tool]));
    $('#scannerGrid').innerHTML = Object.entries(descriptions).map(([key, desc]) => {
      const external = key !== 'builtin' && key !== 'dynamic';
      const available = !external || key === 'zap' ? (key === 'zap' ? Boolean(toolMap.docker?.available) : true) : Boolean(toolMap[key]?.available);
      return `<label class="scanner-choice"><input type="checkbox" value="${key}" ${selected.has(key) ? 'checked' : ''} ${key === 'builtin' ? 'disabled' : ''}><span><b>${escapeHtml(titleCase(key))} ${available ? '' : '· missing'}</b><small>${escapeHtml(desc)}</small></span></label>`;
    }).join('');
  }

  function openScanModal(repositoryId = null) {
    if (!state.repositories.length) return toast('No project available', 'Add a repository before configuring a scan.', 'warning');
    $('#scanRepository').value = repositoryId || state.repositories[0].id;
    $('#scanProfile').value = 'standard';
    $$('#scanProfiles button').forEach((button) => button.classList.toggle('active', button.dataset.profile === 'standard'));
    loadScanRepository($('#scanRepository').value);
    openModal('scanModal');
  }

  async function submitScan(event) {
    event.preventDefault();
    const selectedTools = $$('#scannerGrid input:checked').map((node) => node.value);
    if (!selectedTools.includes('builtin')) selectedTools.unshift('builtin');
    const command = $('#startupPanel').classList.contains('hidden') ? null : $('#startupCandidate').value;
    const confirm = Boolean(command && $('#confirmStartup').checked);
    if (command && !confirm && ['full', 'custom'].includes($('#scanProfile').value)) {
      toast('Startup not authorised', 'The command will not run. Runtime stages require either a supplied API URL or explicit command approval.', 'warning');
    }
    try {
      const scan = await api('/api/scans', { method: 'POST', body: JSON.stringify({ repository_id: Number($('#scanRepository').value), profile: $('#scanProfile').value, selected_tools: selectedTools, api_url: $('#scanApiUrl').value || null, openapi_path: $('#scanOpenApi').value || null, startup_command: confirm ? command : null, confirm_startup: confirm, auth_profile_id: $('#scanAuthProfile').value ? Number($('#scanAuthProfile').value) : null }) });
      closeModals();
      state.currentScanId = scan.id;
      toast('Scan launched', 'Progress is based on real stage events.');
      navigate('scans', { scanId: scan.id });
    } catch (error) { toast('Scan could not start', error.message, 'error'); }
  }

  async function cancelScan(id) {
    try { await api(`/api/scans/${id}/cancel`, { method: 'POST' }); toast('Cancellation requested', 'Completed evidence will be preserved where possible.', 'warning'); }
    catch (error) { toast('Cancellation failed', error.message, 'error'); }
  }

  function openProjectModal() { openModal('projectModal'); }

  async function submitProject(event) {
    event.preventDefault();
    const type = $('#projectSourceType').value;
    try {
      let repo;
      if (type === 'zip') {
        const file = $('#projectZip').files[0];
        if (!file) throw new Error('Choose a ZIP archive.');
        const form = new FormData(); form.append('archive', file); if ($('#projectName').value) form.append('name', $('#projectName').value);
        repo = await api('/api/repositories/import-zip', { method: 'POST', body: form });
      } else {
        repo = await api('/api/repositories', { method: 'POST', body: JSON.stringify({ source_type: type, source: $('#projectSource').value, name: $('#projectName').value || null, branch: type === 'git' ? ($('#projectBranch').value || null) : null }) });
      }
      toast('Project added', `${repo.name} was inspected locally.`);
      closeModals();
      await loadCommonData();
      navigate('projects');
      showProjectDetail(repo.id);
    } catch (error) { toast('Project import failed', error.message, 'error'); }
  }

  async function pickFolder() {
    try {
      const result = await api('/api/system/pick-folder', { method: 'POST' });
      if (result.path) $('#projectSource').value = result.path;
    } catch (error) { toast('Folder picker unavailable', error.message, 'warning'); }
  }

  function setSourceTab(type) {
    $('#projectSourceType').value = type;
    $$('.source-tabs button').forEach((button) => button.classList.toggle('active', button.dataset.sourceTab === type));
    $('#projectSourceLabel').classList.toggle('hidden', type === 'zip');
    $('#projectBranchLabel').classList.toggle('hidden', type !== 'git');
    $('#projectZipLabel').classList.toggle('hidden', type !== 'zip');
    $('#projectSourceLabel').firstChild.textContent = type === 'git' ? 'Git URL ' : 'Folder path ';
    $('#projectSource').placeholder = type === 'git' ? 'https://github.com/org/repository.git' : 'C:\\Projects\\PaymentApi';
    $('#browseFolder').classList.toggle('hidden', type !== 'local');
  }

  function authFields(type) {
    const fields = {
      bearer: '<label>Bearer token<input name="token" type="password" required></label><label>Header prefix<input name="prefix" value="Bearer"></label>',
      api_key_header: '<label>Header name<input name="header_name" value="X-API-Key" required></label><label>API key<input name="api_key" type="password" required></label>',
      api_key_query: '<label>Query parameter<input name="parameter_name" value="api_key" required></label><label>API key<input name="api_key" type="password" required></label>',
      basic: '<div class="two-col"><label>Username<input name="username" required></label><label>Password<input name="password" type="password" required></label></div>',
      oauth_client_credentials: '<label>Token URL<input name="token_url" placeholder="http://127.0.0.1:4000/oauth/token" required></label><div class="two-col"><label>Client ID<input name="client_id" required></label><label>Client secret<input name="client_secret" type="password" required></label></div><label>Scopes<input name="scopes" placeholder="read write"></label>',
      cookie: '<label>Cookie name<input name="cookie_name" value="session" required></label><label>Cookie value<input name="cookie_value" type="password" required></label>',
    };
    $('#authProfileFields').innerHTML = fields[type] || '';
  }

  function openAuthProfileModal(repoId) {
    $('#authProfileRepositoryId').value = repoId;
    $('#authProfileForm').reset();
    $('#authProfileRepositoryId').value = repoId;
    $('#authProfileType').value = 'bearer';
    authFields('bearer');
    openModal('authProfileModal');
  }

  async function submitAuthProfile(event) {
    event.preventDefault();
    const type = $('#authProfileType').value;
    const form = new FormData(event.target);
    const config = {};
    const secret = {};
    const secretKeys = new Set(['token', 'api_key', 'password', 'client_secret', 'cookie_value']);
    for (const [key, value] of form.entries()) {
      if (['authProfileRepositoryId'].includes(key)) continue;
      (secretKeys.has(key) ? secret : config)[key] = value;
    }
    if (type === 'oauth_client_credentials') { config.scope = String(config.scopes || '').trim(); delete config.scopes; }
    try {
      await api(`/api/repositories/${$('#authProfileRepositoryId').value}/auth-profiles`, { method: 'POST', body: JSON.stringify({ name: $('#authProfileName').value, auth_type: type, config, secret }) });
      toast('Authentication profile saved', 'Secret material was sent once to protected local storage.');
      closeModals();
    } catch (error) { toast('Authentication profile rejected', error.message, 'error'); }
  }

  function requestReauth(purpose, reason, callback) {
    state.reauth = { purpose, callback };
    $('#reauthReason').textContent = reason;
    $('#reauthPassword').value = '';
    openModal('reauthModal');
  }

  async function submitReauth(event) {
    event.preventDefault();
    if (!state.reauth) return;
    try {
      const result = await api('/api/auth/reauth', { method: 'POST', body: JSON.stringify({ password: $('#reauthPassword').value, purpose: state.reauth.purpose }) });
      const callback = state.reauth.callback;
      state.reauth = null;
      closeModals();
      await callback(result.step_up_token);
    } catch (error) { toast('Verification failed', error.message, 'error'); }
  }

  function openModal(id) {
    $('#modalBackdrop').classList.remove('hidden');
    $(`#${id}`).classList.remove('hidden');
  }

  function closeModals() {
    $('#modalBackdrop').classList.add('hidden');
    $$('.modal').forEach((modal) => modal.classList.add('hidden'));
  }

  function openCommandPalette() {
    rebuildCommands();
    $('#commandPalette').classList.remove('hidden');
    $('#commandSearch').value = '';
    renderCommandResults('');
    setTimeout(() => $('#commandSearch').focus(), 0);
  }

  function rebuildCommands() {
    state.commandItems = [
      ...Object.entries(pageInfo).filter(([key]) => key !== 'audit' || hasPermission('audit.read')).map(([key, [, title, subtitle]]) => ({ icon: '↗', title: `Open ${title}`, detail: subtitle, action: () => navigate(key) })),
      ...(hasPermission('projects.create') ? [{ icon: '+', title: 'Add project', detail: 'Local folder, Git or ZIP', action: openProjectModal }] : []),
      ...(hasPermission('scans.create') ? [{ icon: '◎', title: 'Start a new scan', detail: 'Quick, Standard, Full or Custom', action: () => openScanModal() }] : []),
      { icon: '✦', title: 'Ask local AI', detail: 'Open docked security copilot', action: openInspector },
      ...state.repositories.map((repo) => ({ icon: '⌂', title: `Open ${repo.name}`, detail: shortPath(repo.local_path), action: () => { navigate('projects'); setTimeout(() => showProjectDetail(repo.id), 100); } })),
    ];
  }

  function renderCommandResults(query) {
    const normalized = query.trim().toLowerCase();
    const items = state.commandItems.filter((item) => `${item.title} ${item.detail}`.toLowerCase().includes(normalized)).slice(0, 18);
    $('#commandResults').innerHTML = items.length ? items.map((item, index) => `<button class="command-result ${index === 0 ? 'selected' : ''}" data-command-index="${state.commandItems.indexOf(item)}"><span>${escapeHtml(item.icon)}</span><span><b>${escapeHtml(item.title)}</b><small>${escapeHtml(item.detail)}</small></span><kbd>Enter</kbd></button>`).join('') : '<div class="empty-state"><h2>No matching command</h2><p>Try a screen, project, scan or report action.</p></div>';
    $$('[data-command-index]').forEach((button) => button.onclick = () => runCommand(Number(button.dataset.commandIndex)));
  }

  function runCommand(index) {
    const item = state.commandItems[index];
    if (!item) return;
    $('#commandPalette').classList.add('hidden');
    item.action();
  }

  function bindDynamicActions() {
    $$('[data-go]').forEach((node) => node.onclick = () => navigate(node.dataset.go));
    $$('[data-open-project]').forEach((node) => node.onclick = openProjectModal);
    $$('[data-open-scan]').forEach((node) => node.onclick = () => openScanModal());
    $$('[data-scan-repo]').forEach((node) => node.onclick = () => openScanModal(Number(node.dataset.scanRepo)));
    $$('[data-project-detail]').forEach((node) => node.onclick = () => showProjectDetail(Number(node.dataset.projectDetail)));
    $$('[data-redetect]').forEach((node) => node.onclick = async () => { try { await api(`/api/repositories/${node.dataset.redetect}/redetect`, { method: 'POST' }); toast('Detection refreshed'); closeModals(); renderProjects(); } catch (e) { toast('Redetection failed', e.message, 'error'); } });
    $$('[data-auth-profile]').forEach((node) => node.onclick = () => openAuthProfileModal(Number(node.dataset.authProfile)));
    $$('[data-scan-id]').forEach((node) => node.onclick = () => openScan(Number(node.dataset.scanId)));
    $$('[data-finding-id]').forEach((node) => node.onclick = () => openFinding(Number(node.dataset.findingId)));
    $$('[data-findings-scan]').forEach((node) => node.onclick = () => { closeModals(); navigate('findings'); setTimeout(() => renderFindings({ scan_id: node.dataset.findingsScan }), 10); });
    $$('[data-cancel-scan]').forEach((node) => node.onclick = () => cancelScan(Number(node.dataset.cancelScan)));
    $$('[data-report-download]').forEach((node) => node.onclick = () => downloadReport(node.dataset.reportDownload, node.dataset.format));
    $$('[data-ai-finding]').forEach((node) => node.onclick = () => { closeModals(); openInspector(); state.currentFindingIdForAi = Number(node.dataset.aiFinding); updateAiContext(state.repositories.find((repo) => repo.id === state.selectedFinding?.repository_id), state.selectedFinding); });
    $$('[data-refresh-tools]').forEach((node) => node.onclick = () => renderTools());
    $$('[data-external-url]').forEach((node) => node.onclick = () => openExternal(node.dataset.externalUrl));
  }

  function openExternal(url) {
    if (window.__TAURI__?.opener?.openUrl) window.__TAURI__.opener.openUrl(url);
    else window.open(url, '_blank', 'noopener,noreferrer');
  }

  function bindEvents() {
    $$('[data-next-step]').forEach((button) => button.addEventListener('click', () => setSetupStep(Number(button.dataset.nextStep))));
    $('#setupOwnerForm').addEventListener('submit', async (event) => {
      event.preventDefault();
      const message = $('#setupMessage');
      if ($('#setupPassword').value !== $('#setupConfirmPassword').value) {
        message.textContent = 'Passwords do not match.'; message.classList.remove('hidden'); return;
      }
      try {
        const result = await api('/api/setup/initialize', { method: 'POST', body: JSON.stringify({ username: $('#setupUsername').value, password: $('#setupPassword').value }) });
        state.token = result.token; state.user = result.user; state.setupCreated = true;
        sessionStorage.setItem('yashsec_token', state.token);
        message.classList.add('hidden'); setSetupStep(3);
      } catch (error) { message.textContent = error.message; message.classList.remove('hidden'); }
    });
    $('#finishSetup').addEventListener('click', () => showApp());
    $('#demoLogin').addEventListener('click', enterDemo);
    $('#loginForm').addEventListener('submit', async (event) => {
      event.preventDefault();
      const message = $('#loginMessage');
      try {
        const result = await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ username: $('#loginUsername').value, password: $('#loginPassword').value, client_instance_id: crypto.randomUUID?.() || `web-${Date.now()}` }) });
        state.token = result.token; state.user = result.user; sessionStorage.setItem('yashsec_token', state.token); message.classList.add('hidden'); await showApp();
      } catch (error) { message.textContent = error.message; message.classList.remove('hidden'); }
    });
    $('#logoutButton').addEventListener('click', async () => { try { await api('/api/auth/logout', { method: 'POST' }); } catch (_) {} clearSession(); showLogin(); });
    $$('.nav-item').forEach((button) => button.addEventListener('click', () => navigate(button.dataset.view)));
    $('#newScanTop').addEventListener('click', () => openScanModal());
    $('#askAiTop').addEventListener('click', openInspector);
    $('#inspectorClose').addEventListener('click', closeInspector);
    $('#assistantForm').addEventListener('submit', sendAssistant);
    $('#assistantRepo').addEventListener('change', () => updateAiContext(state.repositories.find((repo) => repo.id === Number($('#assistantRepo').value))));
    $$('.quick-prompts button').forEach((button) => button.addEventListener('click', () => { $('#assistantQuestion').value = button.textContent; $('#assistantQuestion').focus(); }));
    $('#themeToggle').addEventListener('click', () => applyTheme((document.documentElement.dataset.theme || 'dark') === 'dark' ? 'light' : 'dark'));
    $('#commandButton').addEventListener('click', openCommandPalette);
    $('#commandSearch').addEventListener('input', (event) => renderCommandResults(event.target.value));
    $('#commandPalette').addEventListener('click', (event) => { if (event.target === $('#commandPalette')) $('#commandPalette').classList.add('hidden'); });
    document.addEventListener('keydown', (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); openCommandPalette(); }
      if (event.key === 'Escape') { $('#commandPalette').classList.add('hidden'); closeModals(); }
      if (event.key.toLowerCase() === 'f' && state.view === 'findings' && !['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName)) { event.preventDefault(); $('#findingSearch')?.focus(); }
    });
    $$('.modal-close').forEach((button) => button.addEventListener('click', closeModals));
    $('#modalBackdrop').addEventListener('click', closeModals);
    $$('.source-tabs button').forEach((button) => button.addEventListener('click', () => setSourceTab(button.dataset.sourceTab)));
    $('#browseFolder').addEventListener('click', pickFolder);
    $('#projectForm').addEventListener('submit', submitProject);
    $('#scanRepository').addEventListener('change', (event) => loadScanRepository(event.target.value));
    $('#startupCandidate').addEventListener('change', (event) => { $('#startupPreview').textContent = event.target.value; $('#confirmStartup').checked = false; });
    $$('#scanProfiles button').forEach((button) => button.addEventListener('click', () => { $$('#scanProfiles button').forEach((item) => item.classList.remove('active')); button.classList.add('active'); $('#scanProfile').value = button.dataset.profile; renderScannerGrid(); }));
    $('#scanForm').addEventListener('submit', submitScan);
    $('#authProfileType').addEventListener('change', (event) => authFields(event.target.value));
    $('#authProfileForm').addEventListener('submit', submitAuthProfile);
    $('#reauthForm').addEventListener('submit', submitReauth);
  }

  bootstrap();
})();
