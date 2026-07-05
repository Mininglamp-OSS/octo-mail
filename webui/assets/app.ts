// octo-mail webmail — a minimal but real single-page client driving the JMAP API.
// Strict TypeScript, compiled to committed app.js (see build.sh) and embedded in
// the binary. Flow: login -> Email/query INBOX -> Email/get (read) -> compose
// (upload + Email/set create + EmailSubmission/set send).
//
// This is intentionally small; it proves the product
// layer: a browser can log in and read/send mail through octo-mail with no external
// client.

interface JmapResponse {
	methodResponses: [string, any, string][]
}

let authHeader = ''
let accountId = ''
let jmapBase = ''

function $(id: string): HTMLElement {
	const e = document.getElementById(id)
	if (!e) throw new Error('missing element ' + id)
	return e
}

async function jmap(method: string, args: any): Promise<any> {
	const body = {
		using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
		methodCalls: [[method, args, 'c0']],
	}
	const resp = await fetch(jmapBase + '/jmap/api', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', 'Authorization': authHeader },
		body: JSON.stringify(body),
	})
	if (!resp.ok) throw new Error('jmap ' + method + ' status ' + resp.status)
	const data = await resp.json() as JmapResponse
	const [name, ret] = data.methodResponses[0]
	if (name === 'error') throw new Error('jmap error: ' + JSON.stringify(ret))
	return ret
}

async function session(): Promise<void> {
	const resp = await fetch(jmapBase + '/jmap/session', { headers: { 'Authorization': authHeader } })
	if (!resp.ok) throw new Error('login failed (' + resp.status + ')')
	const s = await resp.json()
	accountId = s.primaryAccounts['urn:ietf:params:jmap:mail']
}

async function doLogin(): Promise<void> {
	const user = (($('user') as HTMLInputElement).value)
	const pass = (($('pass') as HTMLInputElement).value)
	authHeader = 'Basic ' + btoa(user + ':' + pass)
	await session()
	$('login-view').style.display = 'none'
	$('mail-view').style.display = 'block'
	await loadInbox()
}

async function loadInbox(): Promise<void> {
	// Find the Inbox mailbox id.
	const mb = await jmap('Mailbox/get', { accountId })
	let inboxId = ''
	for (const m of mb.list) {
		if ((m.role === 'inbox') || (m.name === 'Inbox')) inboxId = m.id
	}
	const q = await jmap('Email/query', {
		accountId,
		filter: inboxId ? { inMailbox: inboxId } : {},
		sort: [{ property: 'receivedAt', isAscending: false }],
	})
	const ids: string[] = q.ids || []
	const list = $('list')
	list.innerHTML = ''
	if (ids.length === 0) {
		list.textContent = '(no messages)'
		return
	}
	const g = await jmap('Email/get', { accountId, ids })
	for (const em of g.list) {
		const row = document.createElement('div')
		row.className = 'row'
		const subj = em.subject || '(no subject)'
		const from = (em.from && em.from[0]) ? em.from[0].email : ''
		row.textContent = from + ' — ' + subj
		row.onclick = () => openMessage(em.id)
		list.appendChild(row)
	}
}

async function openMessage(id: string): Promise<void> {
	const g = await jmap('Email/get', { accountId, ids: [id] })
	const em = g.list[0]
	let body = ''
	if (em.bodyValues) {
		for (const k of Object.keys(em.bodyValues)) body += em.bodyValues[k].value
	}
	$('reader').style.display = 'block'
	$('reader-subject').textContent = em.subject || '(no subject)'
	$('reader-body').textContent = body || em.preview || ''
}

async function doSend(): Promise<void> {
	const to = (($('to') as HTMLInputElement).value)
	const subject = (($('subject') as HTMLInputElement).value)
	const text = (($('compose-body') as HTMLTextAreaElement).value)
	const from = (($('user') as HTMLInputElement).value)
	const raw = 'From: ' + from + '\r\nTo: ' + to + '\r\nSubject: ' + subject + '\r\n\r\n' + text + '\r\n'

	// Upload the raw message, create it as a draft, then submit it.
	const up = await fetch(jmapBase + '/jmap/upload/' + accountId + '/', {
		method: 'POST',
		headers: { 'Content-Type': 'message/rfc822', 'Authorization': authHeader },
		body: raw,
	})
	if (!up.ok) throw new Error('upload failed')
	const blob = await up.json()
	const created = await jmap('Email/set', {
		accountId,
		create: { c1: { blobId: blob.blobId, keywords: { '$draft': true } } },
	})
	const emailId = created.created.c1.id
	await jmap('EmailSubmission/set', {
		accountId,
		create: { s1: { emailId, envelope: { mailFrom: { email: from }, rcptTo: [{ email: to }] } } },
	})
	$('send-status').textContent = 'sent'
}

function wire(): void {
	jmapBase = ''
	$('login-btn').onclick = () => doLogin().catch(e => { $('login-status').textContent = String(e) })
	$('send-btn').onclick = () => doSend().catch(e => { $('send-status').textContent = String(e) })
	$('refresh-btn').onclick = () => loadInbox().catch(e => { $('list').textContent = String(e) })
}

document.addEventListener('DOMContentLoaded', wire)
