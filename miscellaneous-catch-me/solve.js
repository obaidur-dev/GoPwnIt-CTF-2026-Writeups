// Run in the browser console on the challenge page (F12 -> Console).
// It clicks all 50 buttons, reads the popup text, and tries atob() on each.
const out = [];
const btns = [...document.querySelectorAll('#nodes-grid > *')];
for (const [i, b] of btns.entries()) {
  b.click();
  await new Promise(r => setTimeout(r, 150));
  const raw = document.getElementById('inspector-payload-content').innerText.trim();
  let dec; try { dec = atob(raw) } catch (e) { dec = '(not base64)' }
  out.push({ n: i + 1, raw, dec });
  document.getElementById('inspector-close-btn').click();
}
console.table(out);
