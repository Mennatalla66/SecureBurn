const createBtn = document.getElementById("createBtn");
const statusBox = document.getElementById("status");
const resultBox = document.getElementById("result");
const shareLink = document.getElementById("shareLink");
const messageBox = document.getElementById("message");
const charCount = document.getElementById("charCount");

messageBox.addEventListener("input", () => {
  charCount.textContent = `${messageBox.value.length} / 10000`;
});

function toBase64Url(bytes) {
  let binary = "";
  bytes.forEach(byte => binary += String.fromCharCode(byte));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

createBtn.addEventListener("click", async () => {
  const message = messageBox.value;
  const expiresMinutes = Number(document.getElementById("expiry").value);
  resultBox.classList.add("hidden");

  if (!message.trim()) {
    statusBox.textContent = "Please enter a message first.";
    return;
  }
  if (!window.crypto || !crypto.subtle) {
    statusBox.textContent = "Secure encryption is unavailable. Use a modern browser over HTTPS or localhost.";
    return;
  }

  createBtn.disabled = true;
  statusBox.textContent = "Encrypting in your browser…";

  try {
    const key = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
    );
    const rawKey = new Uint8Array(await crypto.subtle.exportKey("raw", key));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-GCM", iv }, key, new TextEncoder().encode(message)
    ));
    const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
    const token = toBase64Url(tokenBytes);

    const response = await fetch("/api/messages", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ciphertext: toBase64Url(encrypted),
        iv: toBase64Url(iv),
        token,
        expires_minutes: expiresMinutes
      })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Could not create the message.");

    // URL fragments are not sent in HTTP requests to the server.
    shareLink.value = `${location.origin}/m/${data.message_id}#key=${toBase64Url(rawKey)}&token=${token}`;
    resultBox.classList.remove("hidden");
    statusBox.textContent = "Success — your encrypted message link is ready.";
    messageBox.value = "";
    charCount.textContent = "0 / 10000";
  } catch (error) {
    statusBox.textContent = error.message || "Something went wrong. Please try again.";
  } finally {
    createBtn.disabled = false;
  }
});

document.getElementById("copyBtn").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(shareLink.value);
    statusBox.textContent = "Link copied. Share it only with the intended recipient.";
  } catch {
    shareLink.focus();
    shareLink.select();
    statusBox.textContent = "Select and copy the link manually.";
  }
});
