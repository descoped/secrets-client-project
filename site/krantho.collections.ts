import { join } from 'node:path'
import { defineCollection, defineDocumentArchetype } from '@krantho/schema'
import { z } from 'zod'

// The documentation is the markdown in the repository's docs/ folder, the same files GitHub shows. A collection reads
// one folder, so each folder of docs/ is a collection of its own: docs/ itself (README.md is the documentation's home
// page) and docs/providers/. Each path ends in a slash: every page is a folder in the static output.
const fields = z.object({
  title: z.string(),
  description: z.string(),
  order: z.number().describe("The page's place in the sidebar").optional(),
  section: z.string().describe("The group of the sidebar the page is indented under, in its folder's group").optional(),
})

const docsCollection = (name: string, folder: string, path: string, indexFile?: string) =>
  defineCollection({
    name,
    source: 'filesystem',
    directory: join(process.cwd(), '..', 'docs', folder),
    ...(indexFile ? { indexFile } : {}),
    path,
    archetype: defineDocumentArchetype({ id: `site/${name}`, label: name, fields }),
  })

const docs = docsCollection('docs', '', '/docs/:slug/', 'README.md')
const providers = docsCollection('providers', 'providers', '/docs/providers/:slug/')

// The landing page, one document (home), rendered at /: its fields are the hero, and the `##` sections of its body
// the rows below it, in the order of the section contract. The `###` headings of a section are its columns.
const landing = defineCollection({
  name: 'landing',
  source: 'filesystem',
  directory: join(process.cwd(), 'content', 'landing'),
  path: '/',
  sections: [
    'The problem',
    'How the secrets client solves it',
    'Your secret lives in guarded memory',
    'Use the value, then it is gone',
    'TLS that never touches the heap',
    'Credentials get the same care',
    'One API, the backend you choose',
    'Proven by dumping the heap',
    'Add it to your project',
    'Read your first secret',
    'Learn how it works',
  ],
  archetype: defineDocumentArchetype({
    id: 'site/landing',
    label: 'Landing',
    fields: z.object({
      title: z.string(),
      description: z.string(),
      eyebrow: z.string(),
      headline: z.string(),
      subline: z.string(),
      'primary-label': z.string(),
      'primary-href': z.string(),
      'secondary-label': z.string(),
      'secondary-href': z.string(),
    }),
  }),
})

export const collections = { docs, providers, landing }
