// Intentionally VULNERABLE frontend glue code.
// XSS: model output is injected straight into the DOM.

async function sendChat(message) {
  const res = await fetch('/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: currentUser.email, message }),
  });
  const data = await res.json();
  // LLM output rendered as raw HTML - XSS vector
  document.getElementById('reply').innerHTML = data.reply;
  console.log('user', currentUser.email, 'said', message, 'got', data.reply);
}

function renderMarkdown(md) {
  // Unsanitized markdown -> HTML
  document.getElementById('content').innerHTML = marked.parse(md);
}
