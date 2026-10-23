# SecureBurn — Self-Destructing Secret Messages

## Project purpose
A cryptography-course prototype that demonstrates browser-side message encryption, expiring links, one-time access, and server-side integrity verification.

## Technologies
- Python and Flask: web server and API.
- HTML and CSS: responsive user interface.
- JavaScript Web Crypto API: AES-256-GCM encryption and decryption in the browser.
- SQLite: stores encrypted payloads and message metadata.
- HMAC-SHA256: integrity check over the stored ciphertext, IV, and expiry metadata.
- GitHub: source-code repository.
- Render: optional web hosting.

## Security design
1. The browser encrypts the message with AES-256-GCM before sending data to the server.
2. The AES key is included in the URL fragment. URL fragments are not sent as part of the HTTP request, so the server does not receive the decryption key.
3. A separate random access token is sent to the server only as a request header. The database stores its SHA-256 hash, not the token itself.
4. HMAC-SHA256 verifies the stored ciphertext, IV, and expiry metadata using a server-side secret.
5. A successful retrieval marks the message as used. Expired messages are rejected and deleted when accessed after expiry.
6. Security response headers and request-size limits are configured.

## Important limitations
- This is an educational prototype, not a production-ready secure messaging service.
- AES-GCM already provides authenticated encryption. HMAC is included for a distinct server-side purpose: detecting unauthorized changes to the stored encrypted payload and expiry metadata.
- The link contains the decryption key. Anyone who obtains the full link may read the message before it is used or expires.
- A message can still be copied, photographed, or captured with a screenshot.
- Expiry is enforced when a message is requested; this version does not run a background cleanup job.
- SQLite files may not persist on free hosting instances. Use a persistent database for a serious deployment.
- Configure a strong SECRET_KEY environment variable on the hosting platform. Do not use the local fallback in a public deployment.
- Do not use this prototype for real sensitive information.

## Run on Windows
1. Open this folder in VS Code.
2. Open Terminal in the folder containing `app.py` and `requirements.txt`.
3. Create a virtual environment:
   `python -m venv .venv`
4. If PowerShell blocks activation, you can skip activation and run:
   `.\.venv\Scripts\python.exe -m pip install -r requirements.txt`
5. Start the app:
   `.\.venv\Scripts\python.exe app.py`
6. Open `http://127.0.0.1:5000`.

## Deploy
Push the project to GitHub. Create a Render Web Service from the repository:
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app`
- Set a strong `SECRET_KEY` environment variable.

## Evaluation checklist
- Functional test: create and open a message.
- One-time test: attempt to open the same link again.
- Expiry test: attempt access after expiry.
- Access control test: use an invalid token.
- Integrity test: alter stored ciphertext/IV/expiry in a controlled local test and confirm HMAC verification fails.
- Performance test: record message creation and retrieval time for several message sizes.
- Discuss limitations, key sharing, screenshots, deployment storage persistence, and ethical use in the report.
