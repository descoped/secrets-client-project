import { defineKranthoConfig } from '@krantho/config'

const description =
  'A Java library that reads and writes secrets through one API, from Google Secret Manager, AWS Secrets Manager, ' +
  'files the platform mounts or a local file, and keeps every value and every credential off the Java heap.'

/**
 * The site of the secrets client: a landing page and the documentation. The documentation pages are the markdown files
 * in ../docs, the same files GitHub shows in the repository. The Pages workflow sets KRANTHO_SITE_BASE_URL to the
 * address Pages serves the site at; its path is the path every page is served under.
 */
export default defineKranthoConfig({
  site: {
    domain: 'localhost',
    name: 'Secrets Client',
    description,
    language: 'en',
    baseUrl: 'http://localhost:3000',
  },
  // The folder whose git history dates each page
  paths: { contentDir: '../docs' },
  // The markdown files are the content: no database, every page written at build
  persistence: { provider: 'filesystem' },
  cache: { pages: 'none' },
  // The docs hold names such as @ProviderName: no @field substitution
  content: { atNotation: false },
  // The structured data each page carries
  seo: {
    identity: 'SoftwareApplication',
    // What the site is about, with only what the repository says; on every page's graph
    site: {
      entities: [
        {
          '@type': 'SoftwareApplication',
          properties: {
            name: 'Descoped Secrets Client',
            description,
            applicationCategory: 'DeveloperApplication',
            operatingSystem: 'Linux, macOS',
            programmingLanguage: 'Java',
            license: 'https://www.apache.org/licenses/LICENSE-2.0',
            author: { '@type': 'Organization', name: 'Descoped', url: 'https://descoped.io' },
          },
        },
      ],
    },
    collections: { docs: ['TechArticle'], providers: ['TechArticle'] },
  },
})
