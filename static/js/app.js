/**
 * TrustVault Client Application Logic
 * Cryptographically Verifiable Zero-Trust Document Vault
 */

let currentUser = null;
let currentActiveDoc = null;
let currentTab = 'documents';
let cachedUsers = [];

// Initialize application on page load
document.addEventListener('DOMContentLoaded', () => {
  checkAuth();
});

// ==========================================================================
// AUTHENTICATION & PERSONA MANAGEMENT
// ==========================================================================

async function checkAuth() {
  try {
    const res = await fetch('/api/auth/me');
    const data = await res.json();
    if (data.authenticated && data.user) {
      currentUser = data.user;
      showDashboard();
    } else {
      showLogin();
    }
  } catch (err) {
    console.error('Auth check error:', err);
    showLogin();
  }
}

function showLogin() {
  currentUser = null;
  document.getElementById('loginView').style.display = 'flex';
  document.getElementById('dashboardView').style.display = 'none';
}

function showDashboard() {
  document.getElementById('loginView').style.display = 'none';
  document.getElementById('dashboardView').style.display = 'flex';
  updateUserBadge();
  switchTab('documents');
  loadUsers();
}

async function loginAsRole(role) {
  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role: role })
    });
    const data = await res.json();
    if (res.ok) {
      currentUser = data.user;
      showDashboard();
    } else {
      alert(data.error || 'Login failed');
    }
  } catch (err) {
    alert('Failed to connect to TrustVault server: ' + err.message);
  }
}

async function loginAsUser(userId) {
  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_id: userId })
    });
    const data = await res.json();
    if (res.ok) {
      currentUser = data.user;
      showDashboard();
    } else {
      alert(data.error || 'Persona switch failed');
    }
  } catch (err) {
    alert('Error switching user: ' + err.message);
  }
}

async function logout() {
  try {
    await fetch('/api/auth/logout', { method: 'POST' });
  } catch (err) {
    console.error('Logout error:', err);
  }
  showLogin();
}

function updateUserBadge() {
  if (!currentUser) return;
  const avatar = document.getElementById('userAvatar');
  const nameLabel = document.getElementById('userNameLabel');
  const roleLabel = document.getElementById('userRoleLabel');

  avatar.textContent = currentUser.full_name.charAt(0);
  avatar.style.backgroundColor = currentUser.avatar_color || '#0ea5e9';
  nameLabel.textContent = currentUser.full_name;
  roleLabel.textContent = currentUser.role;

  roleLabel.className = 'user-role-label';
  if (currentUser.role === 'admin') roleLabel.classList.add('role-admin-text');
  else if (currentUser.role === 'owner') roleLabel.classList.add('role-owner-text');
  else roleLabel.classList.add('role-viewer-text');

  // Also update mobile drawer labels if present
  const mobName = document.getElementById('mobUserNameLabel');
  const mobRole = document.getElementById('mobUserRoleLabel');
  if (mobName) mobName.textContent = currentUser.full_name;
  if (mobRole) {
    mobRole.textContent = currentUser.role.toUpperCase();
    mobRole.className = 'user-role-label ' + (currentUser.role === 'admin' ? 'role-admin-text' : (currentUser.role === 'owner' ? 'role-owner-text' : 'role-viewer-text'));
  }

  // Adjust upload button visibility (only owner and admin can upload)
  const uploadBtn = document.getElementById('uploadBtn');
  if (uploadBtn) {
    if (currentUser.role === 'viewer') {
      uploadBtn.style.opacity = '0.5';
      uploadBtn.title = 'Viewers cannot upload documents (RBAC restricted)';
      uploadBtn.onclick = () => alert('Viewers do not have permission to upload documents.');
    } else {
      uploadBtn.style.opacity = '1';
      uploadBtn.title = 'Upload Document';
      uploadBtn.onclick = openUploadModal;
    }
  }
}

async function loadUsers() {
  try {
    const res = await fetch('/api/users');
    const data = await res.json();
    if (res.ok) {
      cachedUsers = data.users || [];
      populateGrantUserDropdown();
    }
  } catch (err) {
    console.error('Failed to load users:', err);
  }
}

function populateGrantUserDropdown() {
  const select = document.getElementById('grantUserSelect');
  if (!select) return;
  select.innerHTML = '<option value="">Select user to grant access...</option>';
  cachedUsers.forEach(u => {
    if (currentUser && u.id === currentUser.id) return; // skip self
    const opt = document.createElement('option');
    opt.value = u.id;
    opt.textContent = `${u.full_name} (${u.role.toUpperCase()} - ${u.title})`;
    select.appendChild(opt);
  });
}



// ==========================================================================
// TAB ROUTING & NAVIGATION
// ==========================================================================

function toggleMobileMenu() {
  const drawer = document.getElementById('mobileNavDrawer');
  const icon = document.getElementById('menuIcon');
  if (!drawer) return;
  const isOpen = drawer.classList.toggle('open');
  if (icon) icon.textContent = isOpen ? '✕' : '☰';
}

function switchTab(tab) {
  currentTab = tab;
  document.getElementById('tabDocsBtn')?.classList.toggle('active', tab === 'documents');
  document.getElementById('tabAuditBtn')?.classList.toggle('active', tab === 'audit');
  document.getElementById('mobTabDocs')?.classList.toggle('active', tab === 'documents');
  document.getElementById('mobTabAudit')?.classList.toggle('active', tab === 'audit');

  document.getElementById('docsSection').style.display = (tab === 'documents') ? 'block' : 'none';
  document.getElementById('auditSection').style.display = (tab === 'audit') ? 'block' : 'none';

  if (tab === 'documents') {
    loadDocuments();
  } else if (tab === 'audit') {
    loadAuditTrail();
  }
}

// ==========================================================================
// DOCUMENTS MANAGEMENT
// ==========================================================================

let searchDebounceTimeout = null;
function handleDocSearch() {
  clearTimeout(searchDebounceTimeout);
  searchDebounceTimeout = setTimeout(() => {
    loadDocuments();
  }, 250);
}

async function loadDocuments() {
  const query = document.getElementById('docSearchInput').value.trim();
  const category = document.getElementById('docCategorySelect').value;
  const dateFrom = document.getElementById('docDateFilter').value;

  let url = `/api/documents?q=${encodeURIComponent(query)}&category=${encodeURIComponent(category)}`;
  if (dateFrom) url += `&date_from=${encodeURIComponent(dateFrom)}`;

  try {
    const res = await fetch(url);
    if (!res.ok) {
      if (res.status === 401) return showLogin();
      throw new Error('Failed to fetch documents');
    }
    const data = await res.json();
    renderDocuments(data.documents || []);
  } catch (err) {
    console.error('Error loading documents:', err);
  }
}

function renderDocuments(docs) {
  const grid = document.getElementById('documentsGrid');
  grid.innerHTML = '';

  if (docs.length === 0) {
    grid.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">🔒</div>
        <h3>No Documents Found</h3>
        <p style="max-width:400px; margin:8px auto 0;">
          ${currentUser && currentUser.role === 'viewer' 
            ? 'As a Viewer, you only see documents specifically granted to you by document owners. No ungranted documents are visible.' 
            : 'No documents match your active search filters.'}
        </p>
      </div>
    `;
    return;
  }

  docs.forEach(doc => {
    const card = document.createElement('div');
    card.className = 'doc-card';

    const ext = doc.filename.split('.').pop().toUpperCase();
    const isOwner = (currentUser && doc.owner_id === currentUser.id);
    const isAdmin = (currentUser && currentUser.role === 'admin');
    const accessLevel = doc.user_access_level || 'read';

    let iconChar = '📄';
    if (ext === 'PDF') iconChar = '📕';
    else if (['PNG', 'JPG', 'JPEG'].includes(ext)) iconChar = '🖼️';
    else if (['CSV', 'XLSX'].includes(ext)) iconChar = '📊';

    const formattedDate = new Date(doc.created_at).toLocaleDateString('en-US', {
      month: 'short', day: 'numeric', year: 'numeric'
    });

    const formattedSize = (doc.file_size / 1024).toFixed(1) + ' KB';

    card.innerHTML = `
      <div class="doc-card-header">
        <div class="doc-type-icon">${iconChar}</div>
        <div class="doc-card-titles">
          <h4 class="doc-title">${escapeHtml(doc.title)}</h4>
          <span class="doc-category-badge">${escapeHtml(doc.category)}</span>
        </div>
        <span class="doc-access-chip ${accessLevel}">${accessLevel.replace('_', ' ')}</span>
      </div>

      <p class="doc-description">${escapeHtml(doc.description || 'Confidential document safely vaulted under zero-trust governance.')}</p>

      <div class="doc-meta-row">
        <div class="doc-owner-info">
          <span>👤 ${escapeHtml(doc.owner_name)}</span>
        </div>
        <div>📅 ${formattedDate} &bull; ${formattedSize}</div>
      </div>

      <div style="margin-bottom:14px;">
        <div class="doc-hash-preview" title="Cryptographic SHA-256 Checksum: ${doc.sha256_hash}">
          <span>SHA-256:</span>
          <span>${doc.sha256_hash.substring(0, 16)}...</span>
        </div>
      </div>

      <div class="doc-card-actions">
        <button class="btn-secondary" onclick="openDocDetail('${doc.id}')">
          <span>🔍</span> Inspect
        </button>
        <button class="btn-primary" onclick="downloadDoc('${doc.id}')">
          <span>⬇️</span> Download
        </button>
        ${isOwner ? `
          <button class="btn-danger" style="flex:0 0 36px; padding:8px;" onclick="deleteDoc('${doc.id}', '${escapeHtml(doc.title)}')" title="Delete Document">
            🗑️
          </button>
        ` : ''}
      </div>
    `;

    grid.appendChild(card);
  });
}

async function openDocDetail(docId) {
  try {
    const res = await fetch(`/api/documents/${docId}`);
    const data = await res.json();
    if (!res.ok) {
      alert(data.error || 'Failed to load document details');
      return;
    }
    const doc = data.document;
    currentActiveDoc = doc;

    document.getElementById('detailDocTitle').textContent = doc.title;
    document.getElementById('detailDocCategory').textContent = doc.category;
    document.getElementById('detailDocDesc').textContent = doc.description || 'No description provided.';
    document.getElementById('detailDocOwner').textContent = doc.owner_name;
    document.getElementById('detailDocSize').textContent = (doc.file_size / 1024).toFixed(1) + ' KB (' + doc.filename + ')';
    document.getElementById('detailDocCreated').textContent = new Date(doc.created_at).toLocaleString();
    document.getElementById('detailDocHash').textContent = doc.sha256_hash;

    const accessChip = document.getElementById('detailDocYourAccess');
    accessChip.textContent = doc.user_access_level;
    accessChip.className = 'doc-access-chip ' + doc.user_access_level;

    // Load preview content
    loadDocPreview(doc.id, doc.mime_type);

    // Permission Management Section (visible only to Document Owner or Admin)
    const permSection = document.getElementById('permissionsManagementSection');
    const isOwner = (currentUser && doc.owner_id === currentUser.id);
    const isAdmin = (currentUser && currentUser.role === 'admin');

    if (isOwner || isAdmin) {
      permSection.style.display = 'block';
      renderPermissionsRoster(doc.permissions || [], isOwner);
    } else {
      permSection.style.display = 'none';
    }

    openModal('docDetailModal');
  } catch (err) {
    alert('Error opening document: ' + err.message);
  }
}

async function loadDocPreview(docId, mimeType) {
  const container = document.getElementById('previewContainer');
  container.innerHTML = '<span style="color:var(--text-dim);">Fetching encrypted document stream...</span>';

  try {
    const res = await fetch(`/api/documents/${docId}/preview`);
    if (!res.ok) {
      const err = await res.json();
      container.innerHTML = `<span style="color:var(--accent-rose);">🔒 Access Refused: ${escapeHtml(err.error || 'Unauthorized')}</span>`;
      return;
    }

    if (mimeType.includes('pdf') || mimeType.includes('text') || mimeType.includes('json') || mimeType.includes('csv')) {
      const text = await res.text();
      container.textContent = text.substring(0, 3000) + (text.length > 3000 ? '\n\n[...Content truncated for preview...]' : '');
    } else {
      container.innerHTML = `<span style="color:var(--accent-cyan-light);">Binary file (${mimeType}). Click "Download File" to inspect full content.</span>`;
    }
  } catch (err) {
    container.innerHTML = `<span style="color:var(--accent-rose);">Error loading preview: ${err.message}</span>`;
  }
}

function renderPermissionsRoster(perms, isOwner) {
  const tbody = document.getElementById('permissionRosterBody');
  tbody.innerHTML = '';

  if (perms.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:var(--text-dim); padding:16px;">No external access granted. Document is completely private to owner.</td></tr>`;
    return;
  }

  perms.forEach(p => {
    const tr = document.createElement('tr');
    const grantedDate = new Date(p.granted_at).toLocaleDateString();

    tr.innerHTML = `
      <td>
        <div style="display:flex; align-items:center; gap:8px;">
          <div class="user-avatar" style="background:${p.avatar_color}; width:24px; height:24px; font-size:0.7rem;">
            ${p.full_name.charAt(0)}
          </div>
          <div>
            <div style="font-weight:600; color:var(--text-main);">${escapeHtml(p.full_name)}</div>
            <div style="font-size:0.72rem; color:var(--text-dim);">${escapeHtml(p.email)}</div>
          </div>
        </div>
      </td>
      <td>
        <span class="doc-access-chip ${p.access_level}">${p.access_level.toUpperCase()}</span>
      </td>
      <td style="font-size:0.78rem; color:var(--text-dim);">${grantedDate}</td>
      <td style="text-align:right;">
        ${isOwner ? `
          <button class="btn-danger" style="font-size:0.72rem; padding:4px 8px;" onclick="revokePermission('${p.user_id}', '${escapeHtml(p.full_name)}')">
            ⚡ Revoke Access
          </button>
        ` : '<span style="color:var(--text-dim); font-size:0.75rem;">Locked</span>'}
      </td>
    `;
    tbody.appendChild(tr);
  });
}

async function submitGrantPermission() {
  if (!currentActiveDoc) return;
  const userSelect = document.getElementById('grantUserSelect');
  const levelSelect = document.getElementById('grantLevelSelect');

  const targetUserId = userSelect.value;
  const accessLevel = levelSelect.value;

  if (!targetUserId) {
    alert('Please select a user to grant permission to.');
    return;
  }

  try {
    const res = await fetch(`/api/documents/${currentActiveDoc.id}/permissions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_id: targetUserId, access_level: accessLevel })
    });
    const data = await res.json();
    if (res.ok) {
      alert(`Access Granted: ${data.message}`);
      // Re-fetch document detail
      openDocDetail(currentActiveDoc.id);
      loadDocuments();
    } else {
      alert(data.error || 'Failed to grant permission');
    }
  } catch (err) {
    alert('Error granting permission: ' + err.message);
  }
}

async function revokePermission(targetUserId, targetUserName) {
  if (!currentActiveDoc) return;
  if (!confirm(`Are you sure you want to REVOKE access for ${targetUserName}?\n\nThis takes effect IMMEDIATELY: all active download links and sessions will terminate on the spot.`)) {
    return;
  }

  try {
    const res = await fetch(`/api/documents/${currentActiveDoc.id}/permissions/${targetUserId}`, {
      method: 'DELETE'
    });
    const data = await res.json();
    if (res.ok) {
      alert(`⚡ ACCESS IMMEDIATELY REVOKED!\n\n${data.message}`);
      openDocDetail(currentActiveDoc.id);
      loadDocuments();
    } else {
      alert(data.error || 'Failed to revoke access');
    }
  } catch (err) {
    alert('Error revoking access: ' + err.message);
  }
}

async function openShareLinkGen() {
  if (!currentActiveDoc) return;
  try {
    const res = await fetch(`/api/documents/${currentActiveDoc.id}/share-link`, {
      method: 'POST'
    });
    const data = await res.json();
    if (res.ok) {
      const fullUrl = window.location.origin + data.download_url;
      prompt(
        'Revocable Download Link Generated:\n(Tied to your live permission state. If access is revoked by the owner, this link stops working immediately!):',
        fullUrl
      );
    } else {
      alert(data.error || 'Failed to generate link');
    }
  } catch (err) {
    alert('Error generating share link: ' + err.message);
  }
}

function downloadDoc(docId) {
  window.open(`/api/documents/${docId}/download`, '_blank');
}

function downloadCurrentDoc() {
  if (currentActiveDoc) {
    downloadDoc(currentActiveDoc.id);
  }
}

async function deleteDoc(docId, docTitle) {
  if (!confirm(`Are you sure you want to permanently delete "${docTitle}"?\nAll permissions and tokens will be permanently revoked.`)) {
    return;
  }

  try {
    const res = await fetch(`/api/documents/${docId}`, { method: 'DELETE' });
    const data = await res.json();
    if (res.ok) {
      alert(data.message);
      loadDocuments();
    } else {
      alert(data.error || 'Failed to delete document');
    }
  } catch (err) {
    alert('Delete error: ' + err.message);
  }
}

// ==========================================================================
// UPLOAD & FILE VALIDATION
// ==========================================================================

function openUploadModal() {
  if (currentUser && currentUser.role === 'viewer') {
    alert('Permission Denied: Viewers cannot upload documents.');
    return;
  }
  document.getElementById('uploadForm').reset();
  document.getElementById('selectedFileName').textContent = 'Click to browse or drop file here';
  document.getElementById('uploadError').style.display = 'none';
  openModal('uploadModal');
}

function handleFileSelect(input) {
  if (input.files && input.files[0]) {
    const file = input.files[0];
    document.getElementById('selectedFileName').textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
    if (!document.getElementById('uploadTitle').value) {
      document.getElementById('uploadTitle').value = file.name.replace(/\.[^/.]+$/, "");
    }
  }
}

async function handleUploadSubmit(e) {
  e.preventDefault();
  const fileInput = document.getElementById('fileInput');
  const errorDiv = document.getElementById('uploadError');
  const submitBtn = document.getElementById('uploadSubmitBtn');

  if (!fileInput.files || !fileInput.files[0]) {
    errorDiv.textContent = 'Please choose a file to upload';
    errorDiv.style.display = 'block';
    return;
  }

  const formData = new FormData();
  formData.append('file', fileInput.files[0]);
  formData.append('title', document.getElementById('uploadTitle').value.trim());
  formData.append('category', document.getElementById('uploadCategory').value);
  formData.append('description', document.getElementById('uploadDescription').value.trim());

  errorDiv.style.display = 'none';
  submitBtn.disabled = true;
  submitBtn.textContent = 'Validating Magic Bytes & Hashing...';

  try {
    const res = await fetch('/api/documents', {
      method: 'POST',
      body: formData
    });
    const data = await res.json();
    if (res.ok) {
      closeModal('uploadModal');
      alert(`Success: ${data.message}\nFile SHA-256: ${data.document.sha256_hash}`);
      loadDocuments();
    } else {
      errorDiv.textContent = data.error || 'Upload rejected';
      errorDiv.style.display = 'block';
    }
  } catch (err) {
    errorDiv.textContent = 'Upload network error: ' + err.message;
    errorDiv.style.display = 'block';
  } finally {
    submitBtn.disabled = false;
    submitBtn.innerHTML = '<span>🔒</span> Validate & Secure Upload';
  }
}

// ==========================================================================
// AUDIT TRAIL & TAMPER-EVIDENT CRYPTOGRAPHIC LEDGER
// ==========================================================================

async function loadAuditTrail() {
  const statusFilter = document.getElementById('auditStatusSelect').value;
  const actionFilter = document.getElementById('auditActionSelect').value;
  const search = document.getElementById('auditSearchInput').value.trim();

  let url = `/api/audit?status=${encodeURIComponent(statusFilter)}&action=${encodeURIComponent(actionFilter)}&q=${encodeURIComponent(search)}`;

  try {
    const res = await fetch(url);
    if (!res.ok) {
      if (res.status === 403) {
        document.getElementById('auditTableBody').innerHTML = `
          <tr><td colspan="8" style="text-align:center; padding:30px; color:var(--accent-rose);">
            🔒 Access Refused: Only Administrators and Document Owners have clearance to inspect audit ledgers.
          </td></tr>
        `;
        return;
      }
      throw new Error('Failed to load audit trail');
    }
    const data = await res.json();
    renderAuditTable(data.events || []);
  } catch (err) {
    console.error('Audit trail load error:', err);
  }
}

function renderAuditTable(events) {
  const tbody = document.getElementById('auditTableBody');
  tbody.innerHTML = '';

  if (events.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:var(--text-dim); padding:20px;">No audit records found matching criteria.</td></tr>`;
    return;
  }

  events.forEach(e => {
    const tr = document.createElement('tr');
    const timeFormatted = new Date(e.timestamp).toISOString().replace('T', ' ').substring(0, 19);

    const isRefused = (e.status === 'REFUSED');

    tr.innerHTML = `
      <td class="audit-seq">#${e.sequence_id}</td>
      <td style="font-family:var(--font-mono); font-size:0.75rem; color:var(--text-dim);">${timeFormatted}</td>
      <td>
        <div style="font-weight:600; color:var(--text-main);">${escapeHtml(e.actor_name)}</div>
        <div style="font-size:0.7rem; color:var(--text-dim); text-transform:uppercase;">${e.actor_role}</div>
      </td>
      <td>
        <span style="font-family:var(--font-mono); font-size:0.78rem; font-weight:600; color:${isRefused ? 'var(--accent-rose)' : 'var(--accent-blue)'};">
          ${e.action}
        </span>
      </td>
      <td>
        <div style="font-weight:600; font-size:0.82rem; color:var(--text-main);">${escapeHtml(e.target_name)}</div>
        <div style="font-size:0.7rem; color:var(--text-dim);">${e.target_type}</div>
      </td>
      <td>
        <span class="audit-status-badge ${e.status}">
          ${isRefused ? '🛡️ REFUSED' : '✓ ALLOWED'}
        </span>
      </td>
      <td style="font-family:var(--font-mono); font-size:0.75rem; color:var(--text-dim);">${e.ip_address}</td>
      <td>
        <span class="audit-hash-chip" title="Block Hash: ${e.current_hash}\nPrev Hash: ${e.prev_hash}\nHMAC Signature: ${e.signature}">
          ${e.current_hash.substring(0, 16)}...
        </span>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

async function verifyLedgerIntegrity() {
  const icon = document.getElementById('chainStatusIcon');
  const title = document.getElementById('chainStatusTitle');
  const sub = document.getElementById('chainStatusSubtitle');

  title.textContent = 'Verifying cryptographic chain links...';
  icon.textContent = '⏳';

  try {
    const res = await fetch('/api/audit/verify', { method: 'POST' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Verification failed');

    const v = data.verification;
    if (v.valid) {
      icon.textContent = '⛓️';
      icon.className = 'audit-integrity-icon';
      title.textContent = `Tamper-Evident Hash Chain: 100% Cryptographically Verified`;
      sub.textContent = `All ${v.total_records} historical blocks verified from Genesis block. ${v.refused_events_count} refused access attempts preserved. Zero tampering detected.`;
      alert(`[CRYPTOGRAPHIC INTEGRITY PROOF]\n\nStatus: 100% VALID\nTotal Ledger Blocks Verified: ${v.total_records}\nRefused Access Attempts Logged: ${v.refused_events_count}\nBroken Links: 0\nGenesis Hash: ${v.genesis_hash}\nTip Hash: ${v.head_hash}`);
    } else {
      icon.textContent = '⚠️';
      icon.className = 'audit-integrity-icon error';
      title.textContent = `INTEGRITY COMPROMISED: Tampered Record Detected!`;
      sub.textContent = `${v.error_reason} (Block #${v.broken_sequence_id})`;
      alert(`[TAMPERING ALERT DETECTED]\n\n${v.error_reason}`);
    }
  } catch (err) {
    alert('Verification error: ' + err.message);
  }
}

async function simulateCovertTampering() {
  if (!confirm('This demonstration tool will covertly modify a historical audit block in SQLite to demonstrate how TrustVault mathematically detects offline log tampering. Proceed?')) {
    return;
  }

  try {
    const res = await fetch('/api/audit/simulate-tamper', { method: 'POST' });
    const data = await res.json();
    if (res.ok) {
      const demo = data.tampering_demonstration;
      alert(
        `[MATHEMATICAL TAMPER DETECTION DEMO]\n\n` +
        `Scenario: ${demo.attack_scenario}\n` +
        `Target Block: #${demo.tampered_block_id}\n` +
        `Was Tampering Caught?: ${demo.was_tampering_detected ? 'YES (100% DETECTED)' : 'NO'}\n` +
        `Detection Output: ${demo.detection_error}\n\n` +
        `Post-Verification: Clean state successfully restored in database.`
      );
      loadAuditTrail();
    } else {
      alert(data.error || 'Tampering simulation failed');
    }
  } catch (err) {
    alert('Simulation error: ' + err.message);
  }
}

// ==========================================================================
// SECURITY TEST RUNNER
// ==========================================================================

function openTestModal() {
  openModal('testModal');
  runLiveTests();
}

async function runLiveTests() {
  const btn = document.getElementById('runTestsBtn');
  const container = document.getElementById('testListContainer');
  btn.disabled = true;
  btn.innerHTML = '<span>⏳</span> Executing Test Assertions...';

  container.innerHTML = `
    <div style="text-align:center; padding:30px; color:var(--accent-cyan);">
      Running 10 rigorous security assertions against live server endpoints...
    </div>
  `;

  try {
    const res = await fetch('/api/tests/run', { method: 'POST' });
    const data = await res.json();
    renderTestResults(data);
  } catch (err) {
    container.innerHTML = `<div style="color:var(--accent-rose); padding:20px;">Failed to execute tests: ${err.message}</div>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span>▶️</span> Run Live Test Suite';
  }
}

function renderTestResults(report) {
  document.getElementById('testTotalCount').textContent = report.total;
  document.getElementById('testPassedCount').textContent = report.passed;
  document.getElementById('testFailedCount').textContent = report.failed;

  const badge = document.getElementById('testCountBadge');
  if (badge) {
    badge.textContent = `${report.passed}/${report.total} PASS`;
  }

  const container = document.getElementById('testListContainer');
  container.innerHTML = '';

  report.tests.forEach(t => {
    const item = document.createElement('div');
    const isPass = (t.status === 'PASSED');
    item.className = `test-item ${isPass ? 'passed' : 'failed'}`;

    item.innerHTML = `
      <div class="test-title-desc">
        <div class="test-name">
          <span>${isPass ? '✓' : '✗'}</span>
          <span>${t.name}</span>
          <span class="test-badge-standard">${t.standard}</span>
        </div>
        <div class="test-desc">${escapeHtml(t.description)}</div>
        ${t.error ? `<div style="color:var(--accent-rose); font-size:0.75rem; margin-top:4px;">Error: ${escapeHtml(t.error)}</div>` : ''}
      </div>
      <div style="text-align:right;">
        <span class="test-status-tag ${isPass ? 'passed' : 'failed'}">${t.status}</span>
        <div style="font-size:0.72rem; color:var(--text-dim); margin-top:4px; font-family:var(--font-mono);">${t.duration_ms}ms</div>
      </div>
    `;
    container.appendChild(item);
  });
}

// ==========================================================================
// SECURITY SPECIFICATION MODAL
// ==========================================================================

async function openSpecModal() {
  openModal('specModal');
  const body = document.getElementById('specModalBody');
  body.innerHTML = '<p style="color:var(--text-dim);">Loading formal security model...</p>';

  try {
    const res = await fetch('/api/security/spec');
    const spec = await res.json();

    let html = `
      <h3 style="color:var(--text-main); font-size:1.15rem; margin-bottom:12px;">${spec.title}</h3>
      <p style="color:var(--text-muted); margin-bottom:18px;">
        TrustVault implements zero-trust authorization where the server decides every single request, audit events are chained into a cryptographic ledger, and permission revocation operates with zero latency.
      </p>

      <h4 style="color:var(--accent-blue); margin:16px 0 8px;">Role Capabilities & Separation of Duties</h4>
      <div style="display:flex; flex-direction:column; gap:12px; margin-bottom:24px;">
    `;

    spec.roles.forEach(r => {
      html += `
        <div style="background:#f8fafc; border:1px solid var(--border-subtle); border-radius:var(--radius-md); padding:14px;">
          <div style="font-weight:700; color:var(--text-main); font-size:0.95rem; margin-bottom:2px;">
            ${r.role} <span style="font-size:0.75rem; color:var(--accent-sky); font-weight:normal;">(${r.scope})</span>
          </div>
          <div style="margin-top:6px; font-size:0.8rem;">
            <strong style="color:var(--accent-blue);">Can do:</strong>
            <ul style="margin:4px 0 6px 20px; color:var(--text-muted);">
              ${r.can_do.map(c => `<li>${escapeHtml(c)}</li>`).join('')}
            </ul>
            <strong style="color:var(--accent-rose);">Cannot do:</strong>
            <ul style="margin:4px 0 0 20px; color:var(--text-muted);">
              ${r.cannot_do.map(c => `<li>${escapeHtml(c)}</li>`).join('')}
            </ul>
          </div>
        </div>
      `;
    });

    html += `
      </div>
      <h4 style="color:var(--accent-blue); margin:16px 0 8px;">The Three Non-Negotiable Standards</h4>
      <div style="display:flex; flex-direction:column; gap:10px;">
        <div style="background:#eff6ff; border:1px solid #bfdbfe; border-left:4px solid var(--accent-blue); padding:12px; border-radius:4px;">
          <strong style="color:var(--text-main);">1. ${spec.three_non_negotiables.standard_one.name}:</strong>
          <p style="color:var(--text-muted); font-size:0.82rem; margin-top:4px;">${spec.three_non_negotiables.standard_one.implementation}</p>
        </div>
        <div style="background:#f0f9ff; border:1px solid #bae6fd; border-left:4px solid var(--accent-sky); padding:12px; border-radius:4px;">
          <strong style="color:var(--text-main);">2. ${spec.three_non_negotiables.standard_two.name}:</strong>
          <p style="color:var(--text-muted); font-size:0.82rem; margin-top:4px;">${spec.three_non_negotiables.standard_two.implementation}</p>
        </div>
        <div style="background:#eff6ff; border:1px solid #bfdbfe; border-left:4px solid var(--accent-blue-deep); padding:12px; border-radius:4px;">
          <strong style="color:var(--text-main);">3. ${spec.three_non_negotiables.standard_three.name}:</strong>
          <p style="color:var(--text-muted); font-size:0.82rem; margin-top:4px;">${spec.three_non_negotiables.standard_three.implementation}</p>
        </div>
      </div>
    `;

    body.innerHTML = html;
  } catch (err) {
    body.innerHTML = `<p style="color:var(--accent-rose);">Error: ${err.message}</p>`;
  }
}

// ==========================================================================
// MODAL HELPERS & UTILITIES
// ==========================================================================

function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) modal.style.display = 'flex';
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) modal.style.display = 'none';
}

// Close modals when clicking backdrop
window.onclick = function(event) {
  if (event.target.classList.contains('modal-backdrop')) {
    event.target.style.display = 'none';
  }
};

function escapeHtml(text) {
  if (!text) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
