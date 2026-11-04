/**
 * ui/static/app.js
 * ----------------
 * Frontend điều khiển Web UI thuần cho ứng dụng HCMUT_Chat.
 * Kết nối với ClientAgent qua HTTP REST và Server-Sent Events (SSE).
 * Hỗ trợ:
 *   - Phân tách kênh riêng biệt: Kênh công cộng (# Phòng chung) và Tin nhắn riêng (Direct Message).
 *   - Hiển thị người dùng trực tuyến và người dùng đã đăng ký ngoại tuyến (lấy từ cơ sở dữ liệu).
 *   - Lưu trữ bền vững lịch sử tin nhắn cục bộ (localStorage Message Persistence).
 */

// ── TRẠNG THÁI ỨNG DỤNG ────────────────────────────────────────────────────
let currentAuthMode = 'login'; // 'login' hoặc 'register'
let currentUser = null;
let currentConnId = null;
let activeChannel = 'public'; // 'public' hoặc username người nhận DM
let eventSource = null;
let selectedFile = null;
let userPollInterval = null;

// Bộ lưu trữ tin nhắn theo kênh: { 'public': [...], 'userA': [...] }
const messagesStore = {
  'public': []
};

// Đếm tin nhắn chưa đọc: { 'public': 0, 'userA': 0 }
const unreadStore = {
  'public': 0
};

// Danh sách người dùng online và tất cả người dùng trong hệ thống
let currentOnlineUsers = [];
let currentAllUsers = [];

// Khởi chạy khi tài liệu tải xong
document.addEventListener('DOMContentLoaded', () => {
  checkAuthStatus();
});

// ── LƯU TRỮ VÀ NẠP LỊCH SỬ TIN NHẮN (PERSISTENCE) ──────────────────────────
function loadSavedMessages() {
  try {
    if (!currentUser) return;
    const raw = localStorage.getItem('hcmut_chat_' + currentUser);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object') {
        for (const k in parsed) {
          if (Array.isArray(parsed[k])) {
            messagesStore[k] = parsed[k];
          }
        }
      }
    }
  } catch (e) {
    console.warn('Lỗi đọc lịch sử tin nhắn từ localStorage:', e);
  }
}

function saveMessages() {
  try {
    if (!currentUser) return;
    localStorage.setItem('hcmut_chat_' + currentUser, JSON.stringify(messagesStore));
  } catch (e) {}
}

// ── XÁC THỰC VÀ TRẠNG THÁI (AUTH) ──────────────────────────────────────────
async function checkAuthStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    if (data.server_host) {
      updateServerBadge(data.server_host, data.server_tcp_port);
    }
    if (data.authenticated) {
      onAuthenticated(data.username, data.conn_id, data.online_users, data.all_users, data.server_host, data.server_tcp_port);
    } else {
      showAuthScreen();
    }
  } catch (e) {
    showAuthScreen();
  }
}

function updateServerBadge(host, port) {
  const badge = document.getElementById('server-target-badge');
  const txt = document.getElementById('server-target-text');
  if (badge && txt) {
    txt.textContent = `Server: ${host || '127.0.0.1'}:${port || 9000}`;
    badge.style.display = 'inline-flex';
  }
}

function switchAuthTab(mode) {
  currentAuthMode = mode;
  document.getElementById('tab-login').classList.toggle('active', mode === 'login');
  document.getElementById('tab-register').classList.toggle('active', mode === 'register');
  document.getElementById('btn-auth-submit').textContent = mode === 'login' ? 'Đăng nhập vào hệ thống' : 'Đăng ký tài khoản mới';
  hideAlert();
}

async function submitAuth() {
  const username = document.getElementById('auth-username').value.trim();
  const password = document.getElementById('auth-password').value;

  if (!username || !password) {
    showAlert('Vui lòng nhập đầy đủ tên người dùng và mật khẩu.');
    return;
  }

  const endpoint = currentAuthMode === 'login' ? '/api/login' : '/api/register';
  const btn = document.getElementById('btn-auth-submit');
  btn.disabled = true;
  btn.textContent = 'Đang xử lý kết nối...';
  hideAlert();

  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const result = await res.json();

    if (result.ok) {
      onAuthenticated(result.username, result.conn_id);
    } else {
      showAlert(result.error || 'Thao tác không thành công.');
    }
  } catch (err) {
    showAlert('Không thể kết nối tới máy chủ ứng dụng.');
  } finally {
    btn.disabled = false;
    btn.textContent = currentAuthMode === 'login' ? 'Đăng nhập vào hệ thống' : 'Đăng ký tài khoản mới';
  }
}

async function fetchUsers() {
  try {
    const res = await fetch('/api/users');
    const data = await res.json();
    if (data) {
      updateOnlineUsers(data.users || [], data.all_users || []);
    }
  } catch (e) {}
}

function onAuthenticated(username, connId, initialUsers = [], initialAllUsers = [], serverHost = null, serverPort = null) {
  currentUser = username;
  currentConnId = connId;

  if (serverHost) {
    updateServerBadge(serverHost, serverPort);
  }

  // Nạp lại các tin nhắn cũ đã lưu
  loadSavedMessages();

  // Cập nhật giao diện
  document.getElementById('auth-screen').style.display = 'none';
  document.getElementById('workspace-screen').style.display = 'grid';

  const userBadge = document.getElementById('user-profile-badge');
  userBadge.style.display = 'flex';
  document.getElementById('nav-avatar').textContent = username.charAt(0).toUpperCase();
  document.getElementById('nav-username').textContent = username;

  const statusBadge = document.getElementById('conn-status-badge');
  if (statusBadge) {
    statusBadge.className = 'online-check-badge';
    statusBadge.textContent = '✓';
    statusBadge.title = 'Đang trực tuyến';
  }

  document.getElementById('btn-logout').style.display = 'inline-flex';

  if (initialUsers && initialUsers.length > 0) {
    updateOnlineUsers(initialUsers, initialAllUsers);
  }

  // Khởi động luồng SSE nhận sự kiện thời gian thực
  startSSE();
  fetchUsers();
  fetchDownloads();

  if (userPollInterval) clearInterval(userPollInterval);
  userPollInterval = setInterval(fetchUsers, 3000);

  // Mở kênh phòng chung và hiển thị các tin nhắn cũ
  switchChannel('public');
}

async function handleLogout() {
  if (userPollInterval) {
    clearInterval(userPollInterval);
    userPollInterval = null;
  }
  if (eventSource) {
    eventSource.close();
    eventSource = null;
  }
  try {
    await fetch('/api/logout', { method: 'POST' });
  } catch (e) {}
  window.location.reload();
}

function showAuthScreen() {
  document.getElementById('auth-screen').style.display = 'flex';
  document.getElementById('workspace-screen').style.display = 'none';
  document.getElementById('user-profile-badge').style.display = 'none';
  document.getElementById('btn-logout').style.display = 'none';
}

function showAlert(msg) {
  const box = document.getElementById('auth-alert');
  box.className = 'alert-box alert-error';
  box.textContent = msg;
  box.style.display = 'block';
}

function hideAlert() {
  document.getElementById('auth-alert').style.display = 'none';
}

// ── SERVER-SENT EVENTS (SSE) ──────────────────────────────────────────────
function startSSE() {
  if (eventSource) eventSource.close();

  eventSource = new EventSource('/api/events');

  eventSource.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      handleIncomingEvent(msg);
    } catch (e) {
      console.error('Lỗi phân tích JSON SSE:', e);
    }
  };

  eventSource.onerror = () => {
    console.warn('Mất kết nối SSE, đang tự động kết nối lại...');
  };
}

function handleIncomingEvent(msg) {
  const type = msg.type;

  if (type === 'USER_LIST') {
    updateOnlineUsers(msg.users || [], msg.all_users || []);
  } else if (type === 'MSG_BCAST') {
    const isSelf = (msg.from === currentUser);
    const messageObj = {
      channel: 'public',
      sender: isSelf ? 'Bạn' : msg.from,
      rawSender: msg.from,
      content: msg.content,
      isDm: false,
      isSelf: isSelf,
      timestamp: msg.timestamp || Math.floor(Date.now() / 1000)
    };

    if (!messagesStore['public']) messagesStore['public'] = [];
    messagesStore['public'].push(messageObj);
    saveMessages();

    if (activeChannel === 'public') {
      renderSingleMessage(messageObj);
    } else {
      unreadStore['public'] = (unreadStore['public'] || 0) + 1;
      updateUnreadBadges();
    }
  } else if (type === 'MSG_DM') {
    const isSelf = (msg.from === currentUser);
    const peer = isSelf ? msg.to : msg.from;

    const messageObj = {
      channel: peer,
      sender: isSelf ? 'Bạn' : msg.from,
      rawSender: msg.from,
      content: msg.content,
      isDm: true,
      isSelf: isSelf,
      timestamp: msg.timestamp || Math.floor(Date.now() / 1000)
    };

    if (!messagesStore[peer]) messagesStore[peer] = [];
    messagesStore[peer].push(messageObj);
    saveMessages();

    if (activeChannel === peer) {
      renderSingleMessage(messageObj);
    } else {
      unreadStore[peer] = (unreadStore[peer] || 0) + 1;
      updateUnreadBadges();
    }
  } else if (type === 'FILE_RECEIVED') {
    const peer = msg.from;
    const fileMsg = {
      channel: peer,
      sender: `@${msg.from}`,
      rawSender: msg.from,
      content: `[Tệp đính kèm] ${msg.filename}`,
      isFile: true,
      filename: msg.filename,
      isDm: true,
      isSelf: false,
      timestamp: Math.floor(Date.now() / 1000)
    };
    if (!messagesStore[peer]) messagesStore[peer] = [];
    messagesStore[peer].push(fileMsg);
    saveMessages();

    if (activeChannel === peer) {
      renderSingleMessage(fileMsg);
    } else {
      unreadStore[peer] = (unreadStore[peer] || 0) + 1;
      updateUnreadBadges();
    }

    appendSystemNotice(`Đã nhận tệp "${msg.filename}" từ @${msg.from}. Bạn có thể tải về ở khung chat hoặc mục Tệp đã nhận!`);
    fetchDownloads();
  } else if (type === 'ERROR') {
    appendSystemNotice(`Thông báo lỗi: ${msg.message}`);
  }
}

// ── QUẢN LÝ DANH SÁCH NGƯỜI DÙNG (ONLINE & OFFLINE TỪ DATABASE) ───────────
function updateOnlineUsers(onlineUsers = [], allUsers = []) {
  currentOnlineUsers = onlineUsers;
  currentAllUsers = allUsers;
  const listEl = document.getElementById('online-users-list');
  const countBadge = document.getElementById('online-count-badge');
  const selectEl = document.getElementById('file-recipient-select');

  // Lọc danh sách người dùng loại trừ chính mình
  const onlineOthers = onlineUsers.filter(u => u !== currentUser);
  countBadge.textContent = onlineOthers.length;

  // Cập nhật dropdown người nhận file (chỉ người đang online)
  const currentSelectVal = selectEl.value;
  selectEl.innerHTML = '<option value="">-- Chọn người nhận --</option>';
  onlineOthers.forEach(u => {
    const opt = document.createElement('option');
    opt.value = u;
    opt.textContent = `@${u}`;
    selectEl.appendChild(opt);
  });
  if (onlineOthers.includes(currentSelectVal)) {
    selectEl.value = currentSelectVal;
  } else if (activeChannel !== 'public' && onlineOthers.includes(activeChannel)) {
    selectEl.value = activeChannel;
  }

  // Kết hợp danh sách hiển thị
  const userMap = new Map();

  // Nạp toàn bộ người dùng từ CSDL nếu có
  if (allUsers && allUsers.length > 0) {
    allUsers.forEach(uInfo => {
      if (uInfo.username !== currentUser) {
        userMap.set(uInfo.username, {
          username: uInfo.username,
          online: uInfo.online || onlineOthers.includes(uInfo.username),
          last_seen: uInfo.last_seen
        });
      }
    });
  }

  // Bổ sung các tài khoản đang online
  onlineOthers.forEach(u => {
    if (!userMap.has(u)) {
      userMap.set(u, { username: u, online: true, last_seen: null });
    } else {
      userMap.get(u).online = true;
    }
  });

  const displayList = Array.from(userMap.values());
  // Sắp xếp: Online lên đầu, sau đó đến Offline, theo tên bảng chữ cái
  displayList.sort((a, b) => {
    if (a.online === b.online) {
      return a.username.localeCompare(b.username);
    }
    return a.online ? -1 : 1;
  });

  listEl.innerHTML = '';
  if (displayList.length === 0) {
    listEl.innerHTML = '<div class="empty-state">Chưa có người dùng nào khác.</div>';
    return;
  }

  displayList.forEach(u => {
    const item = document.createElement('div');
    const isActive = (activeChannel === u.username);
    item.className = `user-item ${isActive ? 'active' : ''} ${u.online ? '' : 'offline'}`;
    item.onclick = () => switchChannel(u.username);

    const unread = unreadStore[u.username] || 0;
    const unreadHtml = unread > 0 ? `<span class="unread-pill">${unread}</span>` : '';
    const statusDotClass = u.online ? 'user-status-dot' : 'user-status-dot offline';
    const offlineTag = u.online ? '' : '<span class="user-offline-tag">(offline)</span>';

    item.innerHTML = `
      <div class="user-item-left">
        <span class="${statusDotClass}"></span>
        <span class="user-item-name">@${escapeHtml(u.username)} ${offlineTag}</span>
      </div>
      ${unreadHtml}
    `;
    listEl.appendChild(item);
  });
}

// ── CẬP NHẬT BADGE TIN CHƯA ĐỌC ───────────────────────────────────────────
function updateUnreadBadges() {
  const pubBadge = document.getElementById('unread-badge-public');
  const pubCount = unreadStore['public'] || 0;
  if (pubCount > 0) {
    pubBadge.textContent = pubCount;
    pubBadge.style.display = 'inline-block';
  } else {
    pubBadge.style.display = 'none';
  }

  updateOnlineUsers(currentOnlineUsers, currentAllUsers);
}

// ── CHUYỂN ĐỔI KÊNH CHAT (PUBLIC VS DM) ────────────────────────────────────
function switchChannel(channel) {
  activeChannel = channel;
  unreadStore[channel] = 0;
  updateUnreadBadges();

  const iconEl = document.getElementById('chat-channel-icon');
  const nameEl = document.getElementById('chat-channel-name');
  const descEl = document.getElementById('chat-channel-desc');
  const inputEl = document.getElementById('chat-input');
  const publicItem = document.getElementById('channel-item-public');

  if (channel === 'public') {
    iconEl.textContent = '#';
    nameEl.textContent = 'Phòng chung';
    descEl.textContent = 'Tin nhắn công cộng tới toàn bộ người dùng';
    inputEl.placeholder = 'Nhập tin nhắn tới # Phòng chung... (Enter để gửi)';
    publicItem.classList.add('active');
  } else {
    iconEl.textContent = '@';
    nameEl.textContent = channel;
    descEl.textContent = 'Trò chuyện riêng tư trực tiếp';
    inputEl.placeholder = `Nhập tin nhắn riêng tới @${channel}... (Enter để gửi)`;
    publicItem.classList.remove('active');

    // Tự động chọn người nhận file sang người này nếu người đó đang online
    const recipientSelect = document.getElementById('file-recipient-select');
    if (recipientSelect && currentOnlineUsers.includes(channel)) {
      recipientSelect.value = channel;
    }
  }

  // Cập nhật trạng thái active trên danh sách người dùng
  document.querySelectorAll('.user-item').forEach(el => {
    const name = el.querySelector('.user-item-name')?.textContent || '';
    el.classList.toggle('active', name.startsWith(`@${channel}`));
  });

  // Render lại toàn bộ tin nhắn của kênh được chọn (bao gồm cả tin nhắn cũ đã lưu)
  renderCurrentChannelMessages();
}

function renderCurrentChannelMessages() {
  const container = document.getElementById('chat-messages-container');
  container.innerHTML = '';

  const messages = messagesStore[activeChannel] || [];

  if (messages.length === 0) {
    const welcome = document.createElement('div');
    welcome.className = 'system-bubble';
    if (activeChannel === 'public') {
      welcome.textContent = 'Chào mừng bạn đến với kênh thảo luận # Phòng chung!';
    } else {
      welcome.textContent = `Bắt đầu cuộc trò chuyện riêng với @${activeChannel}. Chỉ hai bạn nhìn thấy tin nhắn này.`;
    }
    container.appendChild(welcome);
    return;
  }

  messages.forEach(msg => {
    renderSingleMessage(msg);
  });
}

// ── GỬI TIN NHẮN CHAT ─────────────────────────────────────────────────────
async function sendChatMessage() {
  const inputEl = document.getElementById('chat-input');
  const content = inputEl.value.trim();
  if (!content) return;

  inputEl.value = '';

  try {
    if (activeChannel === 'public') {
      await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content })
      });
    } else {
      await fetch('/api/dm', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ to: activeChannel, content })
      });
    }
  } catch (e) {
    appendSystemNotice('Không thể gửi tin nhắn. Vui lòng kiểm tra lại kết nối mạng.');
  }
}

function renderSingleMessage(msg) {
  const container = document.getElementById('chat-messages-container');
  const bubble = document.createElement('div');
  bubble.className = `msg-bubble ${msg.isSelf ? 'outgoing' : 'incoming'}`;

  const timeStr = msg.timestamp ? new Date(msg.timestamp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '';
  const tagClass = msg.isDm ? 'tag-dm' : 'tag-bcast';
  const tagLabel = msg.isDm ? 'Trực tiếp' : 'Công cộng';

  let bodyHtml = '';
  if (msg.isFile) {
    const fileAction = msg.isSelf
      ? `<span class="badge-sent-file">Đã gửi</span>`
      : `<a href="/api/download/${encodeURIComponent(msg.filename)}" class="btn btn-sm btn-primary" download>Tải về</a>`;
    const subText = msg.isSelf
      ? `Đã gửi tới @${escapeHtml(msg.channel)}`
      : `Tệp tin nhận từ ${escapeHtml(msg.sender)}`;

    bodyHtml = `
      <div class="msg-content">
        <div class="file-bubble-wrap">
          <div class="file-bubble-left">
            <span>📁</span>
            <div class="file-bubble-info">
              <span class="file-bubble-title">${escapeHtml(msg.filename)}</span>
              <span class="file-bubble-sub">${subText}</span>
            </div>
          </div>
          ${fileAction}
        </div>
      </div>
    `;
  } else {
    bodyHtml = `<div class="msg-content">${escapeHtml(msg.content)}</div>`;
  }

  bubble.innerHTML = `
    <div class="msg-meta">
      <span class="msg-sender">${escapeHtml(msg.sender)}</span>
      <span class="msg-tag ${tagClass}">${tagLabel}</span>
      <span>${timeStr}</span>
    </div>
    ${bodyHtml}
  `;

  container.appendChild(bubble);
  container.scrollTop = container.scrollHeight;
}

function appendSystemNotice(text) {
  const container = document.getElementById('chat-messages-container');
  const notice = document.createElement('div');
  notice.className = 'system-bubble';
  notice.textContent = text;
  container.appendChild(notice);
  container.scrollTop = container.scrollHeight;
}

// ── TRUYỀN TỆP TIN (FILE TRANSFER) ────────────────────────────────────────
function handleFileSelected() {
  const picker = document.getElementById('file-picker');
  const btn = document.getElementById('btn-send-file');
  const infoBox = document.getElementById('file-info-box');

  if (picker.files && picker.files[0]) {
    selectedFile = picker.files[0];
    document.getElementById('file-name-label').textContent = selectedFile.name;
    document.getElementById('file-size-label').textContent = formatBytes(selectedFile.size);
    infoBox.style.display = 'block';
    btn.disabled = false;
  } else {
    selectedFile = null;
    infoBox.style.display = 'none';
    btn.disabled = true;
  }
}

async function startFileTransfer() {
  if (!selectedFile) return;

  const recipientSelect = document.getElementById('file-recipient-select');
  const toUser = recipientSelect.value;
  if (!toUser) {
    alert('Vui lòng chọn người nhận tệp từ danh sách.');
    return;
  }

  const btn = document.getElementById('btn-send-file');
  const progressWrap = document.getElementById('upload-progress-wrap');
  const progressBar = document.getElementById('upload-progress-bar');

  btn.disabled = true;
  btn.textContent = 'Đang tải lên và gửi tệp...';
  progressWrap.style.display = 'block';
  progressBar.style.width = '35%';

  try {
    const base64Data = await readFileAsBase64(selectedFile);
    progressBar.style.width = '70%';

    const res = await fetch('/api/upload', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        to: toUser,
        filename: selectedFile.name,
        data: base64Data
      })
    });
    const result = await res.json();

    if (result.ok) {
      progressBar.style.width = '100%';
      appendSystemNotice(`Đã gửi tệp "${selectedFile.name}" tới @${toUser} thành công!`);

      // Lưu tệp vào cuộc trò chuyện DM riêng với người nhận
      const sentFileMsg = {
        channel: toUser,
        sender: 'Bạn',
        rawSender: currentUser,
        content: `[Tệp đính kèm] ${selectedFile.name}`,
        isFile: true,
        filename: selectedFile.name,
        isDm: true,
        isSelf: true,
        timestamp: Math.floor(Date.now() / 1000)
      };
      if (!messagesStore[toUser]) messagesStore[toUser] = [];
      messagesStore[toUser].push(sentFileMsg);
      saveMessages();

      if (activeChannel === toUser) {
        renderSingleMessage(sentFileMsg);
      }

      setTimeout(() => {
        progressWrap.style.display = 'none';
        progressBar.style.width = '0%';
        document.getElementById('file-picker').value = '';
        handleFileSelected();
      }, 1500);
    } else {
      alert('Gửi tệp không thành công: ' + (result.error || 'Lỗi không xác định'));
      progressWrap.style.display = 'none';
    }
  } catch (err) {
    alert('Lỗi kết nối khi gửi tệp tin.');
    progressWrap.style.display = 'none';
  } finally {
    btn.disabled = false;
    btn.textContent = 'Gửi tệp tin';
  }
}

function readFileAsBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result;
      const base64 = result.split(',')[1];
      resolve(base64);
    };
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

// ── DANH SÁCH FILE ĐÃ TẢI VỀ ──────────────────────────────────────────────
async function fetchDownloads() {
  try {
    const res = await fetch('/api/downloads');
    const data = await res.json();
    renderDownloads(data.files || []);
  } catch (e) {}
}

function renderDownloads(files) {
  const container = document.getElementById('downloads-list');
  container.innerHTML = '';

  if (files.length === 0) {
    container.innerHTML = '<div class="empty-state">Chưa có tệp nào được tải về.</div>';
    return;
  }

  files.forEach(f => {
    const item = document.createElement('div');
    item.className = 'download-item';
    const senderText = f.sender ? `<span class="dl-sender">@${escapeHtml(f.sender)}</span>` : '';
    item.innerHTML = `
      <div class="dl-meta">
        <div class="dl-name" title="${escapeHtml(f.name)}">${escapeHtml(f.name)}</div>
        <div class="dl-size">
          <span>${formatBytes(f.size)}</span>
          ${senderText ? ` &bull; Gửi bởi ${senderText}` : ''}
        </div>
      </div>
      <div class="dl-actions">
        <a href="/api/download/${encodeURIComponent(f.name)}" class="btn btn-sm btn-ghost" download>Tải về</a>
        <button class="btn btn-sm btn-outline-danger" onclick="deleteDownloadedFile('${escapeHtml(f.name)}')">Xóa</button>
      </div>
    `;
    container.appendChild(item);
  });
}

async function deleteDownloadedFile(filename) {
  if (!confirm(`Bạn có chắc chắn muốn xóa tệp "${filename}" khỏi bộ lưu trữ?`)) {
    return;
  }
  try {
    const res = await fetch('/api/delete-file', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename })
    });
    const result = await res.json();
    if (result.ok) {
      appendSystemNotice(`Đã xóa tệp "${filename}" khỏi bộ nhớ lưu trữ.`);
      fetchDownloads();
    } else {
      alert('Không thể xóa tệp: ' + (result.error || 'Lỗi không xác định'));
    }
  } catch (e) {
    alert('Lỗi kết nối khi xóa tệp.');
  }
}

// ── TIỆN ÍCH ──────────────────────────────────────────────────────────────
function escapeHtml(text) {
  if (!text) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}
