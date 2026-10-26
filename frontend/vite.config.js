import path from 'node:path'
import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

/**
 * Runs the Vercel server functions in api/ (e.g. POST /api/chat) inside `npm run dev`,
 * so the AI Analyst works locally. On Vercel the platform serves them instead.
 *
 * Settings come from frontend/.env, then python-engine/.env (GROQ_API_KEY, GROQ_MODEL),
 * so the Groq key does not have to be copied into the frontend folder.
 */
function localApi() {
  return {
    name: 'local-api',
    apply: 'serve',
    configureServer(server) {
      const env = {
        ...loadEnv(server.config.mode, path.resolve(import.meta.dirname, '../python-engine'), ''),
        ...loadEnv(server.config.mode, import.meta.dirname, ''),
      }
      for (const key of ['GROQ_API_KEY', 'GROQ_MODEL', 'VITE_FIREBASE_API_KEY']) {
        if (!process.env[key] && env[key]) process.env[key] = env[key]
      }

      server.middlewares.use('/api', async (req, res, next) => {
        const name = (req.url || '').split('?')[0].replace(/^\/+/, '')
        if (!/^[a-z0-9-]+$/i.test(name)) return next()
        let handler
        try {
          handler = (await server.ssrLoadModule(`/api/${name}.js`)).default
        } catch {
          return next()   // no such function: fall through to Vite's 404
        }

        // Give req/res the small part of Vercel's API the functions use
        let raw = ''
        for await (const chunk of req) raw += chunk
        try { req.body = raw ? JSON.parse(raw) : undefined } catch { req.body = raw }
        res.status = (code) => { res.statusCode = code; return res }
        res.json = (data) => {
          res.setHeader('Content-Type', 'application/json')
          res.end(JSON.stringify(data))
          return res
        }

        try {
          await handler(req, res)
        } catch (err) {
          server.config.logger.error(`[api/${name}] ${err.stack || err}`)
          if (!res.writableEnded) res.status(500).json({ error: 'Local API error.' })
        }
      })
    },
  }
}

export default defineConfig({
  plugins: [react(), tailwindcss(), localApi()],
})
