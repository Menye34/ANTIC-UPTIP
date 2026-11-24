import { useState } from 'react'
import type { ExecutionDetails } from '../services/testing'

type Observation = ExecutionDetails['observations'][number]

const categories = [
  { id: 'cgi', title: 'CGI directory observations' },
  { id: 'headers', title: 'Missing security headers' },
  { id: 'listing', title: 'Directory listing observations' },
  { id: 'other', title: 'Other observations' },
] as const

const headerNames = [
  'content-security-policy',
  'strict-transport-security',
  'permissions-policy',
  'referrer-policy',
  'x-content-type-options',
] as const

function missingHeader(message: string): string | null {
  const lower = message.toLowerCase()

  if (!/\b(missing|not set|not defined|absent)\b/i.test(message)) {
    return null
  }

  return headerNames.find(header => lower.includes(header)) ?? null
}

function categoryFor(observation: Observation) {
  const message = String(observation.data.message ?? '').toLowerCase()

  if (message.includes('cgi directory found')) return 'cgi'

  if (missingHeader(message)) return 'headers'

  if (
    message.includes('directory indexing') ||
    message.includes('directory listing') ||
    message.includes('directory browsing')
  ) return 'listing'

  return 'other'
}

function titleFor(observation: Observation) {
  const message = String(observation.data.message ?? '').trim()
  const header = missingHeader(message)

  if (header) {
    return `${header.toUpperCase()} header missing`
  }

  const withoutUrl = message.split(/\s+See:\s+https?:\/\//i)[0].trim()

  return withoutUrl || message
}

export default function NiktoObservations({
  observations,
}: {
  observations: Observation[]
}) {
  const [search, setSearch] = useState('')

  const normalized = observations.filter(
    observation =>
      observation.type === 'http_server_test' &&
      typeof observation.data.message === 'string' &&
      typeof observation.data.path === 'string'
  )

  const query = search.trim().toLowerCase()

  const filtered = normalized.filter(observation =>
    [
      observation.data.message,
      observation.data.path,
      observation.data.test_id,
    ]
      .filter(value => typeof value === 'string')
      .join(' ')
      .toLowerCase()
      .includes(query)
  )

  const groups = categories
    .map(category => ({
      ...category,
      observations: filtered.filter(
        observation => categoryFor(observation) === category.id
      ),
    }))
    .filter(category => category.observations.length > 0)

  return (
    <div className="testing-nikto-results">
      <h4>Normalized Nikto Observations ({normalized.length})</h4>

      <div className="testing-result-metrics testing-nikto-metrics">
        <div>
          <strong>{normalized.length}</strong>
          <span>Total observations</span>
        </div>
        <div>
          <strong>
            {categories.filter(category =>
              normalized.some(
                observation => categoryFor(observation) === category.id
              )
            ).length}
          </strong>
          <span>Observation categories</span>
        </div>
      </div>

      <label className="testing-nikto-search">
        Search observations
        <input
          type="search"
          value={search}
          onChange={event => setSearch(event.target.value)}
          placeholder="Search message, path, or Nikto test ID"
        />
      </label>

      <div className="testing-nikto-groups">
        {groups.map(group => (
          <details className="testing-nikto-group" key={group.id}>
            <summary>
              <span>{group.title}</span>
              <span className="testing-nikto-count">
                {group.observations.length}
              </span>
            </summary>

            <ul className="testing-nikto-list">
              {group.observations.map(observation => {
                const message = String(observation.data.message)
                const testId = observation.data.test_id
                const references = observation.data.references

                return (
                  <li key={observation.id}>
                    <div className="testing-nikto-observation-heading">
                      <strong>{titleFor(observation)}</strong>
                    </div>

                    <p>Affected path: {String(observation.data.path)}</p>

                    {observation.partial && <p>Partial result</p>}

                    <details className="testing-nikto-observation-details">
                      <summary>Technical details</summary>

                      <div className="testing-nikto-technical-content">
                        <p><strong>Original Nikto message</strong></p>
                        <p>{message}</p>

                        {typeof testId === 'string' && (
                          <p>Nikto test ID: {testId}</p>
                        )}

                        {Array.isArray(references) &&
                          references.length > 0 && (
                            <p>
                              References: {
                                references
                                  .filter(
                                    (reference): reference is string =>
                                      typeof reference === 'string'
                                  )
                                  .join(', ')
                              }
                            </p>
                          )}

                        <p>Evidence ID: {observation.evidence_id}</p>
                      </div>
                    </details>
                  </li>
                )
              })}
            </ul>
          </details>
        ))}
      </div>

      {query && filtered.length === 0 && (
        <p>No observations match your search.</p>
      )}
    </div>
  )
}
