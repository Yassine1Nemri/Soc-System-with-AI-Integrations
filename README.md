# 🛡️ [Your Name] — Cybersecurity Portfolio

Personal portfolio site built to showcase cybersecurity skills, hands-on projects, and certifications for internship applications — a faster, more credible alternative to a plain PDF resume.

**Live site:** `[add your Vercel URL here after deploying]`

## Tech stack

| Layer | Choice |
|---|---|
| Framework | React 18 + Vite |
| Styling | Plain CSS (custom properties / design tokens) |
| Hosting | [Vercel](https://vercel.com) — free tier |
| Version control | Git + GitHub |

## Design

- Navy + signal-blue palette (`--navy #12294F`, `--signal #2F6FED`), grounded in a security "network" theme rather than a generic template
- Type: Space Grotesk (headings) + IBM Plex Sans (body) + IBM Plex Mono (skill tags, cert data)
- Signature detail: a faint animated network-graph backdrop in the hero
- Full token list lives in `src/styles/tokens.css`

## Sections

- **Hero** — name, title, CTA buttons (View Projects / Download CV)
- **About** — short bio
- **Skills** — tools, languages, core security concepts
- **Projects** — CTF write-ups, labs, tools you've built
- **Certifications** — hexagon badges with issuer + date
- **Contact** — email, LinkedIn, GitHub

## Getting started

```bash
git clone https://github.com/[your-username]/[repo-name].git
cd [repo-name]
npm install
npm run dev
```

Visit `http://localhost:5173`.

## Build

```bash
npm run build
```

## Deploy for free (Vercel)

1. Push this repo to GitHub
2. [vercel.com](https://vercel.com) → **New Project** → import the repo
3. Framework preset "Vite" is auto-detected → **Deploy**
4. Every push to `main` redeploys automatically

## Project structure

```
src/
  components/
    Navbar.jsx
    Hero.jsx
    About.jsx
    Skills.jsx
    Projects.jsx
    Certifications.jsx
    Contact.jsx
    Footer.jsx
  styles/
    tokens.css
  App.jsx
  main.jsx
public/
  resume.pdf
```

## Before sending this to recruiters

- [ ] Replace every `[bracketed placeholder]` with your real info
- [ ] Swap in real projects (link the GitHub repos)
- [ ] Add your resume as `public/resume.pdf`
- [ ] Update social links in Contact/Footer
- [ ] Check it on an actual phone, not just dev-tools mobile view

## License

MIT
