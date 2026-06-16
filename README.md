# BTEC Level 3 Computing Portfolio

A multi-page portfolio website for showcasing coursework, technical skills, project reflections, GitHub links, and development progress.

## Main pages

- Home / About Me
- Projects for Units 4, 6, 7, 8, 13, and 9/19
- Skills / Technologies
- Local Document Viewer
- Contact / Links

## Local document viewer

The document page does not use Google Docs, Microsoft Word Online, a CDN, or a file-upload server.

- **PDF:** displayed using the browser's built-in PDF viewer.
- **DOCX:** read directly from the DOCX ZIP structure using the browser's built-in decompression support and safe DOM construction.
- **DOC:** best-effort text extraction only. Legacy DOC is a binary format and exact layout cannot be reproduced reliably in a fully static browser-only site.

Selected files stay on the visitor's device. The website does not upload or store them.

## Run locally

Open `index.html`, or run a small local server:

```bash
python -m http.server 8000
```

Then visit `http://localhost:8000`.

## Edit project details

Project descriptions and links are in `projects.html`. Replace the GitHub profile links with the exact repository for each completed project when available.

## Deployment

The workflow in `.github/workflows/pages.yml` deploys the repository to GitHub Pages whenever the `main` branch changes.
