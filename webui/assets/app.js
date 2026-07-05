"use strict";
// octo-mail webmail — a real single-page client driving the JMAP API.
// Strict TypeScript, compiled to committed app.js (make frontend) and embedded
// in the binary. Three-pane client: sidebar (mailboxes) · message list · reader,
// with a compose modal. Flow: sign in → Mailbox/get → Email/query → Email/get →
// compose (upload + Email/set create + EmailSubmission/set).
let authHeader = '';
let accountId = '';
let userEmail = '';
const jmapBase = '';
let mailboxes = [];
let currentMailbox = '';
let currentEmailId = '';
function $(id) {
    const e = document.getElementById(id);
    if (!e)
        throw new Error('missing element ' + id);
    return e;
}
function inp(id) { return $(id); }
// focusSibling moves keyboard focus to the next/prev message row (arrow keys).
function focusSibling(row, dir) {
    const rows = Array.from(document.querySelectorAll('.msg-row'));
    const i = rows.indexOf(row);
    const next = rows[i + dir];
    if (next)
        next.focus();
}
async function jmap(method, args) {
    const body = {
        using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail', 'urn:ietf:params:jmap:submission'],
        methodCalls: [[method, args, 'c0']],
    };
    const resp = await fetch(jmapBase + '/jmap/api', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': authHeader },
        body: JSON.stringify(body),
    });
    if (!resp.ok)
        throw new Error('jmap ' + method + ' status ' + resp.status);
    const data = await resp.json();
    const [name, ret] = data.methodResponses[0];
    if (name === 'error')
        throw new Error('jmap error: ' + JSON.stringify(ret));
    return ret;
}
// ---------- helpers ----------
function initials(s) {
    const at = s.indexOf('@');
    const local = at > 0 ? s.slice(0, at) : s;
    const parts = local.split(/[.\-_+]/).filter(Boolean);
    if (parts.length >= 2)
        return (parts[0][0] + parts[1][0]).toUpperCase();
    return (local.slice(0, 2) || '?').toUpperCase();
}
function displayName(a) {
    if (!a)
        return '(unknown)';
    if (a.name && a.name.trim())
        return a.name;
    return a.email || '(unknown)';
}
function relTime(iso) {
    if (!iso)
        return '';
    const t = new Date(iso).getTime();
    if (isNaN(t))
        return '';
    const diff = Date.now() - t;
    const min = Math.floor(diff / 60000);
    if (min < 1)
        return 'now';
    if (min < 60)
        return min + 'm';
    const hr = Math.floor(min / 60);
    if (hr < 24)
        return hr + 'h';
    const day = Math.floor(hr / 24);
    if (day < 7)
        return day + 'd';
    const d = new Date(t);
    return (d.getMonth() + 1) + '/' + d.getDate();
}
// absTime formats a full, sortable timestamp for the reader header
// (e.g. "2026-07-05 14:22"). Machine metadata → monospace + tabular in CSS.
function absTime(iso) {
    if (!iso)
        return '';
    const d = new Date(iso);
    if (isNaN(d.getTime()))
        return '';
    const p = (n) => String(n).padStart(2, '0');
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) +
        ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
}
function mailboxIcon(role, name) {
    const r = role || name.toLowerCase();
    if (r.includes('inbox'))
        return '⬇';
    if (r.includes('sent'))
        return '➤';
    if (r.includes('draft'))
        return '✎';
    if (r.includes('trash'))
        return '🗑';
    if (r.includes('junk'))
        return '⚠';
    if (r.includes('archive'))
        return '🗄';
    return '🗀';
}
// ---------- auth ----------
async function session() {
    const resp = await fetch(jmapBase + '/jmap/session', { headers: { 'Authorization': authHeader } });
    if (!resp.ok)
        throw new Error('sign-in failed (' + resp.status + ')');
    const s = await resp.json();
    accountId = s.primaryAccounts['urn:ietf:params:jmap:mail'];
}
async function doLogin() {
    const status = $('login-status');
    status.textContent = '';
    const btn = $('login-btn');
    userEmail = inp('user').value.trim();
    const pass = inp('pass').value;
    if (!userEmail || !pass) {
        status.textContent = 'enter email and password';
        return;
    }
    authHeader = 'Basic ' + btoa(userEmail + ':' + pass);
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>';
    try {
        await session();
        $('login-view').style.display = 'none';
        $('mail-view').style.display = 'grid';
        $('side-user').textContent = userEmail;
        $('side-avatar').textContent = initials(userEmail);
        await loadMailboxes();
    }
    catch (e) {
        status.textContent = String(e instanceof Error ? e.message : e);
    }
    finally {
        btn.disabled = false;
        btn.textContent = 'Sign in';
    }
}
function signOut() {
    authHeader = '';
    accountId = '';
    currentMailbox = '';
    currentEmailId = '';
    inp('pass').value = '';
    $('mail-view').style.display = 'none';
    $('login-view').style.display = 'grid';
}
// ---------- mailboxes ----------
async function loadMailboxes() {
    const mb = await jmap('Mailbox/get', { accountId });
    mailboxes = mb.list || [];
    // Order: Inbox first, then the rest alphabetically.
    mailboxes.sort((a, b) => {
        const ai = (a.role === 'inbox' || a.name === 'Inbox') ? 0 : 1;
        const bi = (b.role === 'inbox' || b.name === 'Inbox') ? 0 : 1;
        if (ai !== bi)
            return ai - bi;
        return a.name.localeCompare(b.name);
    });
    renderNav();
    const inbox = mailboxes.find(m => m.role === 'inbox' || m.name === 'Inbox') || mailboxes[0];
    if (inbox)
        await selectMailbox(inbox.id);
}
function renderNav() {
    const nav = $('nav');
    nav.innerHTML = '';
    for (const m of mailboxes) {
        const el = document.createElement('div');
        el.className = 'nav-item' + (m.id === currentMailbox ? ' active' : '');
        const count = (m.unreadEmails || 0) > 0 ? String(m.unreadEmails) : '';
        el.innerHTML =
            '<span class="ico">' + mailboxIcon(m.role, m.name) + '</span>' +
                '<span class="lbl"></span>' +
                '<span class="count">' + count + '</span>';
        el.querySelector('.lbl').textContent = m.name;
        el.tabIndex = 0;
        el.setAttribute('role', 'tab');
        el.setAttribute('aria-selected', m.id === currentMailbox ? 'true' : 'false');
        const go = () => { selectMailbox(m.id).catch(showListError); };
        el.onclick = go;
        el.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            go();
        } };
        nav.appendChild(el);
    }
}
async function selectMailbox(id) {
    currentMailbox = id;
    currentEmailId = '';
    renderNav();
    const mb = mailboxes.find(m => m.id === id);
    $('list-title').textContent = mb ? mb.name : 'Mailbox';
    closeReader();
    await loadList();
}
// ---------- message list ----------
function showListError(e) {
    $('list').innerHTML = '<div class="empty">' + String(e instanceof Error ? e.message : e) + '</div>';
}
async function loadList() {
    const list = $('list');
    list.innerHTML = '<div class="empty"><span class="spinner"></span></div>';
    const q = await jmap('Email/query', {
        accountId,
        filter: currentMailbox ? { inMailbox: currentMailbox } : {},
        sort: [{ property: 'receivedAt', isAscending: false }],
    });
    const ids = q.ids || [];
    $('list-sub').textContent = ids.length + (ids.length === 1 ? ' message' : ' messages');
    if (ids.length === 0) {
        list.innerHTML = '<div class="empty"><div class="big">🗋</div>No messages here</div>';
        return;
    }
    const g = await jmap('Email/get', {
        accountId, ids,
        properties: ['subject', 'from', 'to', 'preview', 'receivedAt', 'keywords'],
    });
    const emails = g.list || [];
    list.innerHTML = '';
    emails.forEach((em, i) => {
        list.appendChild(renderRow(em, i));
    });
}
function renderRow(em, i) {
    const row = document.createElement('div');
    const unread = !(em.keywords && em.keywords['$seen']);
    const junk = !!(em.keywords && em.keywords['$junk']);
    row.className = 'msg-row' + (unread ? ' unread' : '') + (em.id === currentEmailId ? ' active' : '');
    row.style.animationDelay = Math.min(i * 22, 300) + 'ms';
    const from = (em.from && em.from[0]) ? em.from[0] : undefined;
    const fromLabel = displayName(from);
    const av = document.createElement('div');
    av.className = 'av av-gradient';
    av.textContent = initials(from ? (from.email || fromLabel) : fromLabel);
    const content = document.createElement('div');
    content.className = 'content';
    const top = document.createElement('div');
    top.className = 'top';
    const fromEl = document.createElement('span');
    fromEl.className = 'from';
    fromEl.textContent = fromLabel;
    const timeEl = document.createElement('span');
    timeEl.className = 'time';
    timeEl.textContent = relTime(em.receivedAt);
    top.appendChild(fromEl);
    if (junk) {
        const t = document.createElement('span');
        t.className = 'tag-junk';
        t.textContent = 'junk';
        top.appendChild(t);
    }
    top.appendChild(timeEl);
    const subj = document.createElement('div');
    subj.className = 'subj';
    subj.textContent = em.subject || '(no subject)';
    const prev = document.createElement('div');
    prev.className = 'prev';
    prev.textContent = em.preview || '';
    content.appendChild(top);
    content.appendChild(subj);
    content.appendChild(prev);
    row.appendChild(av);
    row.appendChild(content);
    if (unread) {
        const d = document.createElement('div');
        d.className = 'dot';
        row.appendChild(d);
    }
    row.tabIndex = 0;
    row.setAttribute('role', 'option');
    row.setAttribute('aria-label', fromLabel + ': ' + (em.subject || '(no subject)'));
    const activate = () => {
        document.querySelectorAll('.msg-row').forEach(r => { r.classList.remove('active'); r.setAttribute('aria-selected', 'false'); });
        row.classList.add('active');
        row.setAttribute('aria-selected', 'true');
        // Optimistically reflect "read": drop unread emphasis + the dot.
        row.classList.remove('unread');
        const d = row.querySelector('.dot');
        if (d)
            d.remove();
        openMessage(em.id).catch(e => { $('reader-body').textContent = String(e); });
    };
    row.onclick = activate;
    row.onkeydown = (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            activate();
        }
        else if (e.key === 'ArrowDown') {
            e.preventDefault();
            focusSibling(row, 1);
        }
        else if (e.key === 'ArrowUp') {
            e.preventDefault();
            focusSibling(row, -1);
        }
    };
    return row;
}
// ---------- reader ----------
function closeReader() {
    $('reader').style.display = 'none';
    $('reader-empty').style.display = 'grid';
}
async function openMessage(id) {
    currentEmailId = id;
    const g = await jmap('Email/get', {
        accountId, ids: [id],
        properties: ['subject', 'from', 'to', 'preview', 'receivedAt', 'bodyStructure', 'bodyValues'],
        fetchAllBodyValues: true,
    });
    const em = (g.list || [])[0];
    if (!em)
        return;
    const from = (em.from && em.from[0]) ? em.from[0] : undefined;
    $('reader-empty').style.display = 'none';
    $('reader').style.display = 'flex';
    $('reader-subject').textContent = em.subject || '(no subject)';
    $('reader-from').textContent = displayName(from);
    $('reader-fromaddr').textContent = from && from.email ? from.email : '';
    $('reader-av').textContent = initials(from ? (from.email || displayName(from)) : '?');
    const to = (em.to || []).map(a => a.email || displayName(a)).join(', ');
    $('reader-date').textContent = absTime(em.receivedAt);
    $('reader-rcpt').textContent = to ? 'to ' + to : '';
    renderBody(em);
}
// renderBody chooses the best body part and renders it: the text/html part
// (sanitized) is preferred, falling back to the text/plain part as escaped text.
// This is how a multipart/alternative message shows as formatted HTML instead of
// raw markup.
function renderBody(em) {
    const el = $('reader-body');
    const parts = collectLeafParts(em.bodyStructure);
    const values = em.bodyValues || {};
    const htmlPart = parts.find(p => p.type === 'text/html' && p.partId && values[p.partId]);
    const textPart = parts.find(p => p.type === 'text/plain' && p.partId && values[p.partId]);
    el.className = 'reader-body scroll';
    if (htmlPart && htmlPart.partId) {
        el.classList.add('is-html');
        el.innerHTML = sanitizeHTML(values[htmlPart.partId].value);
        return;
    }
    // Plain text (or unknown): render as escaped, pre-wrapped text.
    let text = '';
    if (textPart && textPart.partId)
        text = values[textPart.partId].value;
    else
        for (const k of Object.keys(values))
            text += values[k].value;
    el.textContent = text || em.preview || '(no text content)';
}
// collectLeafParts flattens a JMAP bodyStructure into its leaf parts (those with
// a partId), preserving document order.
function collectLeafParts(node) {
    if (!node)
        return [];
    if (node.subParts && node.subParts.length) {
        return node.subParts.flatMap(collectLeafParts);
    }
    return node.partId ? [node] : [];
}
// sanitizeHTML removes script/style/dangerous constructs before the message HTML
// is inserted into the reader. Email HTML is untrusted; we parse it in an inert
// document, drop <script>/<style>/<iframe>/<object> and event-handler / dangerous
// URL attributes, allow-list image sources (remote http(s) and inline
// data:image/* except SVG), and force links to open safely in a new tab.
function sanitizeHTML(raw) {
    const doc = new DOMParser().parseFromString(raw, 'text/html');
    const banned = ['script', 'style', 'iframe', 'object', 'embed', 'link', 'meta', 'base', 'form'];
    doc.querySelectorAll(banned.join(',')).forEach(n => n.remove());
    doc.querySelectorAll('*').forEach(el => {
        for (const attr of Array.from(el.attributes)) {
            const name = attr.name.toLowerCase();
            const val = attr.value.trim();
            if (name.startsWith('on')) {
                el.removeAttribute(attr.name);
                continue;
            }
            if (name === 'href' && !safeLinkURL(val)) {
                el.removeAttribute(attr.name);
            }
            else if (name === 'src' && !safeImageURL(val)) {
                el.removeAttribute(attr.name);
            }
            else if (name === 'srcset') {
                el.removeAttribute(attr.name);
            } // avoid bypassing the src allow-list
        }
        if (el.tagName === 'A') {
            el.setAttribute('target', '_blank');
            el.setAttribute('rel', 'noopener noreferrer nofollow');
        }
        if (el.tagName === 'IMG') {
            el.setAttribute('loading', 'lazy');
            el.setAttribute('referrerpolicy', 'no-referrer');
        }
    });
    return doc.body.innerHTML;
}
// safeLinkURL allows http(s), mailto and protocol-relative hrefs; blocks
// javascript:/data:/vbscript: and anything else.
function safeLinkURL(v) {
    const s = v.toLowerCase();
    if (s.startsWith('http://') || s.startsWith('https://') || s.startsWith('mailto:') || s.startsWith('//'))
        return true;
    if (s.startsWith('#') || s.startsWith('/'))
        return true;
    return false;
}
// safeImageURL allows remote http(s) images and inline data:image/* — except
// SVG, which can carry scripts (a known XSS vector). This matches how major
// webmail clients treat inline images: bitmap data URIs render, SVG does not.
function safeImageURL(v) {
    const s = v.toLowerCase().trim();
    if (s.startsWith('http://') || s.startsWith('https://') || s.startsWith('//'))
        return true;
    if (s.startsWith('data:image/')) {
        return !s.startsWith('data:image/svg');
    }
    // cid: (inline attachment refs) aren't resolved to blobs yet — drop to avoid
    // broken-image icons; render support can be added when cid resolution lands.
    return false;
}
// ---------- compose ----------
function openCompose(prefillTo) {
    inp('to').value = prefillTo || '';
    inp('subject').value = '';
    inp('compose-text').value = '';
    $('send-status').textContent = '';
    $('send-status').className = 'status';
    $('compose-scrim').classList.add('open');
    inp('to').focus();
}
function closeCompose() { $('compose-scrim').classList.remove('open'); }
async function doSend() {
    const to = inp('to').value.trim();
    const subject = inp('subject').value;
    const text = inp('compose-text').value;
    const from = userEmail;
    const status = $('send-status');
    if (!to) {
        status.className = 'status';
        status.textContent = 'recipient required';
        return;
    }
    const btn = $('send-btn');
    btn.disabled = true;
    status.className = 'status';
    status.innerHTML = '<span class="spinner"></span> sending';
    const raw = 'From: ' + from + '\r\nTo: ' + to + '\r\nSubject: ' + subject + '\r\n\r\n' + text + '\r\n';
    try {
        const up = await fetch(jmapBase + '/jmap/upload/' + accountId + '/', {
            method: 'POST',
            headers: { 'Content-Type': 'message/rfc822', 'Authorization': authHeader },
            body: raw,
        });
        if (!up.ok)
            throw new Error('upload failed (' + up.status + ')');
        const blob = await up.json();
        const created = await jmap('Email/set', {
            accountId,
            create: { c1: { blobId: blob.blobId, keywords: { '$draft': true }, mailboxIds: {} } },
        });
        const emailId = created.created.c1.id;
        await jmap('EmailSubmission/set', {
            accountId,
            create: { s1: { emailId, envelope: { mailFrom: { email: from }, rcptTo: [{ email: to }] } } },
        });
        status.className = 'status ok';
        status.textContent = '✓ sent';
        setTimeout(() => { closeCompose(); loadList().catch(() => { }); }, 700);
    }
    catch (e) {
        status.className = 'status';
        status.textContent = String(e instanceof Error ? e.message : e);
    }
    finally {
        btn.disabled = false;
    }
}
// ---------- wiring ----------
function wire() {
    $('login-btn').onclick = () => { doLogin(); };
    inp('pass').addEventListener('keydown', e => { if (e.key === 'Enter')
        doLogin(); });
    inp('user').addEventListener('keydown', e => { if (e.key === 'Enter')
        inp('pass').focus(); });
    $('signout-btn').onclick = () => signOut();
    $('refresh-btn').onclick = () => { loadList().catch(showListError); };
    $('compose-open').onclick = () => openCompose();
    $('compose-close').onclick = () => closeCompose();
    $('compose-cancel').onclick = () => closeCompose();
    $('send-btn').onclick = () => { doSend(); };
    $('compose-scrim').addEventListener('click', e => { if (e.target === $('compose-scrim'))
        closeCompose(); });
    document.addEventListener('keydown', e => { if (e.key === 'Escape')
        closeCompose(); });
}
document.addEventListener('DOMContentLoaded', wire);
