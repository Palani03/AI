# AI for Detecting Evasive Malware — Demo (Safe, Simulated)

**Summary:**  
This repository contains a single-page, client-side demo that *simulates* AI-powered malware detection for presentation and educational purposes. **It does not analyze or execute real malware.** Use only benign sample files for demoing.

## Files
- `index.html` — main page (Bootstrap 5, Lottie, FontAwesome)
- `style.css` — custom styles
- `script.js` — client-side scan & chat simulation logic

## How to deploy to GitHub Pages (static)
1. Create a new GitHub repository (e.g., `ai-evasive-malware-demo`).
2. Add `index.html`, `style.css`, `script.js`, `README.md` to the repo and push to the `main` branch.
3. On GitHub go to **Settings > Pages**.
4. Under **Source**, choose `main` branch and `/ (root)`. Save.
5. GitHub Pages will publish the site at `https://<username>.github.io/<repo>/` within a minute or two.

## How to use (demo)
1. Open the published site.
2. Click **Choose File** or drag a file into the drop area (use a small benign file for demo).
3. Click **Scan (Simulated)** — progress bar will run and a simulated detection will be shown.
4. Use the Assistant to ask questions and optionally attach the last scan context.

## Notes & Ethics
- This project is purely a **demonstration**. It intentionally **simulates** malware detection to avoid any unsafe behavior.
- **Do not** upload sensitive or private files.
- For production detection tools, integrate safe static/dynamic analysis pipelines, secure inference APIs, EDR, and follow responsible disclosure practices.

## Customization ideas
- Replace simulated detection with a server-side static analyzer (only metadata) and/or integrate VirusTotal metadata (with proper API key and privacy considerations).
- Integrate a real AI inference API (Hugging Face, OpenAI) on the server-side for chat, ensuring keys are stored securely.
- Add accessibility improvements and localization.

## License
Use this demo for presentations and educational purposes.
