const state = {
  project: null,
  assets: [],
  issues: []
};

const api = {
  async get(path) {
    const response = await fetch(path);
    if (!response.ok) throw new Error(await readError(response));
    return response.json();
  },
  async post(path, body) {
    const response = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    if (!response.ok) throw new Error(await readError(response));
    return response.json();
  },
  async put(path, body) {
    const response = await fetch(path, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    if (!response.ok) throw new Error(await readError(response));
    return response.json();
  }
};

async function readError(response) {
  try {
    const payload = await response.json();
    return payload.message || response.statusText;
  } catch {
    return response.statusText;
  }
}

async function init() {
  await checkHealth();
  await loadProject();
  await loadAll();
  bindEvents();
}

async function checkHealth() {
  const healthStatus = document.getElementById('healthStatus');
  try {
    await api.get('/health');
    healthStatus.textContent = 'Service online';
    healthStatus.classList.add('ready');
  } catch {
    healthStatus.textContent = 'Service unavailable';
    healthStatus.classList.add('down');
  }
}

async function loadProject() {
  const projects = await api.get('/api/projects');
  state.project = projects[0];
  if (!state.project) return;

  document.getElementById('projectName').textContent = state.project.name;
  document.getElementById('projectDescription').textContent = state.project.description;
  document.getElementById('projectProgress').textContent = `${state.project.progress}%`;
  document.getElementById('progressFill').style.width = `${state.project.progress}%`;
  document.getElementById('projectMeta').innerHTML = [
    state.project.code,
    state.project.client,
    state.project.location,
    state.project.sector,
    state.project.stage
  ].map(value => `<span>${escapeHtml(value)}</span>`).join('');
}

async function loadAll() {
  if (!state.project) return;

  const status = document.getElementById('statusFilter')?.value || '';
  const priority = document.getElementById('priorityFilter')?.value || '';
  const query = new URLSearchParams();
  if (status) query.set('status', status);
  if (priority) query.set('priority', priority);

  const [dashboard, assets, issues] = await Promise.all([
    api.get('/api/dashboard'),
    api.get(`/api/projects/${state.project.id}/assets`),
    api.get(`/api/projects/${state.project.id}/issues${query.toString() ? `?${query}` : ''}`)
  ]);

  state.assets = assets;
  state.issues = issues;

  renderDashboard(dashboard);
  renderAssets();
  renderIssues();
  populateAssetSelect();
}

function renderDashboard(dashboard) {
  document.getElementById('totalIssues').textContent = dashboard.totalIssues;
  document.getElementById('openIssues').textContent = dashboard.openIssues;
  document.getElementById('highIssues').textContent = dashboard.highPriorityIssues;
  document.getElementById('overdueIssues').textContent = dashboard.overdueIssues;
}

function renderAssets() {
  const map = document.getElementById('assetMap');
  const list = document.getElementById('assetList');

  map.innerHTML = state.assets.map(asset => `
    <div class="asset-node">
      <strong>${escapeHtml(asset.name)}</strong>
      <span>${escapeHtml(asset.bimReference)}</span><br>
      <span>${escapeHtml(asset.location)}</span><br>
      <span class="${className('priority', asset.riskLevel)}">Risk: ${escapeHtml(asset.riskLevel)}</span>
    </div>
  `).join('');

  list.innerHTML = state.assets.map(asset => `
    <div class="asset-row">
      <div>
        <strong>${escapeHtml(asset.name)}</strong>
        <p>${escapeHtml(asset.category)} • ${escapeHtml(asset.responsibleTeam)} • ${escapeHtml(asset.location)}</p>
      </div>
      <span class="badge ${className('priority', asset.riskLevel)}">${escapeHtml(asset.riskLevel)}</span>
    </div>
  `).join('');
}

function populateAssetSelect() {
  const select = document.getElementById('assetSelect');
  select.innerHTML = '<option value="">No linked asset</option>' + state.assets.map(asset => (
    `<option value="${asset.id}">${escapeHtml(asset.bimReference)} — ${escapeHtml(asset.name)}</option>`
  )).join('');
}

function renderIssues() {
  const body = document.getElementById('issueTable');
  const assetById = new Map(state.assets.map(asset => [asset.id, asset]));

  if (state.issues.length === 0) {
    body.innerHTML = '<tr><td colspan="7">No issues match the selected filters.</td></tr>';
    return;
  }

  body.innerHTML = state.issues.map(issue => {
    const asset = issue.assetId ? assetById.get(issue.assetId) : null;
    return `
      <tr>
        <td>
          <strong>${escapeHtml(issue.title)}</strong>
          <p class="issue-desc">${escapeHtml(issue.description)}</p>
        </td>
        <td>${asset ? `${escapeHtml(asset.bimReference)}<br><span>${escapeHtml(asset.name)}</span>` : 'Not linked'}</td>
        <td><span class="badge ${className('priority', issue.priority)}">${escapeHtml(issue.priority)}</span></td>
        <td><span class="badge ${className('status', issue.status)}">${escapeHtml(issue.status)}</span></td>
        <td>${escapeHtml(issue.assignedTo || 'Unassigned')}</td>
        <td>${formatDate(issue.dueDate)}</td>
        <td>${renderActionButton(issue)}</td>
      </tr>
    `;
  }).join('');

  document.querySelectorAll('[data-status-action]').forEach(button => {
    button.addEventListener('click', () => updateIssueStatus(button.dataset.issueId, button.dataset.nextStatus));
  });
}

function renderActionButton(issue) {
  const next = issue.status === 'Open'
    ? 'In Progress'
    : issue.status === 'In Progress'
      ? 'Resolved'
      : issue.status === 'Blocked'
        ? 'In Progress'
        : 'Closed';

  if (issue.status === 'Closed') {
    return '<span class="badge status-closed">Complete</span>';
  }

  return `<button class="small-button" data-status-action data-issue-id="${issue.id}" data-next-status="${next}">Set ${next}</button>`;
}

async function updateIssueStatus(issueId, nextStatus) {
  await api.put(`/api/issues/${issueId}/status`, {
    status: nextStatus,
    author: 'Project Dashboard',
    note: `Workflow updated to ${nextStatus}.`
  });
  await loadAll();
}

function bindEvents() {
  document.getElementById('refreshButton').addEventListener('click', loadAll);
  document.getElementById('statusFilter').addEventListener('change', loadAll);
  document.getElementById('priorityFilter').addEventListener('change', loadAll);
  document.getElementById('issueForm').addEventListener('submit', submitIssue);
}

async function submitIssue(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const formMessage = document.getElementById('formMessage');
  const data = new FormData(form);

  const dueDate = data.get('dueDate');
  const payload = {
    projectId: state.project.id,
    assetId: data.get('assetId') || null,
    title: data.get('title'),
    description: data.get('description'),
    location: data.get('location'),
    priority: data.get('priority'),
    assignedTo: data.get('assignedTo'),
    dueDate: dueDate ? new Date(`${dueDate}T00:00:00`).toISOString() : null,
    tags: splitCsv(data.get('tags')),
    attachmentNames: []
  };

  try {
    await api.post('/api/issues', payload);
    form.reset();
    formMessage.textContent = 'Issue added.';
    await loadAll();
    setTimeout(() => { formMessage.textContent = ''; }, 2500);
  } catch (error) {
    formMessage.textContent = error.message;
  }
}

function splitCsv(value) {
  return String(value || '')
    .split(',')
    .map(item => item.trim())
    .filter(Boolean);
}

function formatDate(value) {
  if (!value) return 'No due date';
  return new Intl.DateTimeFormat('en-AU', { day: '2-digit', month: 'short', year: 'numeric' }).format(new Date(value));
}

function className(prefix, value) {
  return `${prefix}-${String(value || '').toLowerCase().replaceAll(' ', '-')}`;
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

init().catch(error => {
  document.getElementById('healthStatus').textContent = error.message;
  document.getElementById('healthStatus').classList.add('down');
});
