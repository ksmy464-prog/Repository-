<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://ai.google.dev/static/site-assets/images/share-ais-513315318.png" />
</div>

# YKSS AI Technology

Responsive AI chat app powered by the Google Gemini Interactions API.

## Run locally

**Prerequisites:**  Node.js

1. Install dependencies:
   `npm install`
2. Set `GEMINI_API_KEY` in `.env.local` to a Google AI Studio API key. Do not commit the key.
3. Start the app:
   `npm run dev`

## Deploy to Vercel

1. Import the GitHub repository into Vercel and use the Vite framework preset. The build command is `npm run build` and the output directory is `dist`.
2. In Vercel Project Settings, add `GEMINI_API_KEY` as an environment variable for Production and Preview. Add the key value from Google AI Studio there; do not put it in GitHub or in a `VITE_` variable.
3. Redeploy after adding or changing the environment variable. The `/api` endpoints and Gemini calls run server-side, so the API key is not sent to browsers.
4. Vercel assigns a `*.vercel.app` deployment URL. To use a custom domain, add it under the project's Domains settings and configure the DNS records Vercel provides.

The website adapts to mobile browsers. Separate native Android and iOS applications are not included.
