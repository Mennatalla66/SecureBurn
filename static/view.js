function fromBase64Url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

(async () => {
  const messageId = document.body.dataset.messageId;
  const statusBox = document.getElementById("status");
  const messageBox = document.getElementById("messageBox");
  const params = new URLSearchParams(location.hash.slice(1));
  const keyString = params.get("key");
  const token = params.get("token");

  if (!keyString || !token) {
    statusBox.textContent = "The key or access token is missing. Open the complete secret link.";
    return;
  }

  // Remove the fragment from the address bar after reading it.
  history.replaceState(null, "", location.pathname);

  try {
    statusBox.textContent = "Checking access and retrieving the encrypted message…";
    const response = await fetch(`/api/messages/${encodeURIComponent(messageId)}`, {
      headers: { "X-Message-Token": token },
      cache: "no-store"
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Unable to retrieve the message.");

    statusBox.textContent = "Decrypting the message in your browser…";
    const key = await crypto.subtle.importKey(
      "raw", fromBase64Url(keyString), { name: "AES-GCM" }, false, ["decrypt"]
    );
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromBase64Url(data.iv) }, key, fromBase64Url(data.ciphertext)
    );
    document.getElementById("decryptedMessage").textContent = new TextDecoder().decode(decrypted);
    messageBox.classList.remove("hidden");
    statusBox.textContent = "Message opened successfully. This link cannot be used again.";
  } catch (error) {
    statusBox.textContent = error.message || "The link may be invalid, expired, or already used.";
  }
})();
