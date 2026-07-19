import { fireEvent, render, screen, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { makeAlert } from '../test/factories.ts'
import type { TimelineBucket } from '../types/stats.ts'
import { AlertTable } from './AlertTable.tsx'
import { EventTime } from './EventTime.tsx'
import { ProvenanceBanner } from './ProvenanceBanner.tsx'
import { LiveFeedStatus } from './StatusBadges.tsx'
import { SummaryCards } from './SummaryCards.tsx'
import { TrafficTimelineChart } from './charts/TrafficTimelineChart.tsx'
import { EmptyState, ErrorState } from './states.tsx'

describe('ProvenanceBanner', () => {
  it('maps each single provenance to its unmissable text label', () => {
    const { rerender } = render(<ProvenanceBanner provenance="synthetic" present={[]} />)
    expect(screen.getByText('SYNTHETIC')).toBeInTheDocument()
    rerender(<ProvenanceBanner provenance="replay" present={[]} />)
    expect(screen.getByText('REPLAYED')).toBeInTheDocument()
    rerender(<ProvenanceBanner provenance="live" present={[]} />)
    expect(screen.getByText('LIVE-LAB')).toBeInTheDocument()
  })

  it('lists present provenances as chips in All mode', () => {
    render(<ProvenanceBanner provenance="all" present={['synthetic', 'live']} />)
    expect(screen.getByText('ALL')).toBeInTheDocument()
    expect(screen.getByText('SYNTHETIC')).toBeInTheDocument()
    expect(screen.getByText('LIVE-LAB')).toBeInTheDocument()
  })

  it('shows a placeholder when no provenance is present', () => {
    render(<ProvenanceBanner provenance="all" present={[]} />)
    expect(screen.getByText('no traffic yet')).toBeInTheDocument()
  })
})

describe('EventTime (AC6)', () => {
  it('renders synthetic time as a non-time span with provenance label and no wall-clock exposure', () => {
    render(<EventTime alert={makeAlert({ source_type: 'synthetic', created_at: 1000 })} />)
    const el = screen.getByText(/t = 1000\.0s/)
    expect(el.tagName).toBe('SPAN') // not a <time> element
    expect(el).toHaveTextContent('SYNTHETIC event time') // provenance label present
    expect(el.textContent).not.toMatch(/ago|just now/) // never relative
    expect(el.hasAttribute('datetime')).toBe(false) // no wall-clock dateTime attribute
    expect(el.getAttribute('title') ?? '').not.toMatch(/1970|UTC|\d{4}-\d{2}-\d{2}/) // no 1970/calendar title
  })

  it('renders replay time the same way (raw event seconds, no calendar)', () => {
    render(<EventTime alert={makeAlert({ source_type: 'replay', created_at: 2500 })} />)
    const el = screen.getByText(/t = 2500\.0s/)
    expect(el.tagName).toBe('SPAN')
    expect(el).toHaveTextContent('REPLAYED event time')
    expect(el.hasAttribute('datetime')).toBe(false)
    expect(el.getAttribute('title') ?? '').not.toMatch(/1970/)
  })

  it('renders live time as a <time> with a relative label and valid ISO dateTime', () => {
    const twoMinutesAgo = Date.now() / 1000 - 120
    render(<EventTime alert={makeAlert({ source_type: 'live', created_at: twoMinutesAgo })} />)
    const el = screen.getByText(/ago|just now/)
    expect(el.tagName).toBe('TIME')
    expect(el.getAttribute('datetime')).toMatch(/^\d{4}-\d{2}-\d{2}T/) // valid ISO
  })

  it('renders an out-of-range finite live timestamp as a raw fallback, never "just now"', () => {
    // 1e20 s is finite (passes runtime validation) but far beyond Date's range;
    // formatRelative would have computed a negative delta and shown "just now".
    let container!: HTMLElement
    expect(() => {
      container = render(
        <EventTime alert={makeAlert({ source_type: 'live', created_at: 1e20 })} />,
      ).container
    }).not.toThrow()
    const el = container.querySelector('.event-time') as HTMLElement
    expect(el.tagName).toBe('SPAN') // not a <time>
    expect(el.hasAttribute('datetime')).toBe(false)
    expect(el.textContent).toContain('t = 1e+20s') // raw event time
    expect(el.textContent).toContain('LIVE-LAB event time') // provenance label
    expect(el.textContent).not.toMatch(/ago|just now/) // never relative
  })

  it('labels a representable future live timestamp with future wording, not "just now"', () => {
    const twoMinutesAhead = Date.now() / 1000 + 120
    render(<EventTime alert={makeAlert({ source_type: 'live', created_at: twoMinutesAhead })} />)
    const el = screen.getByText(/in 2 minutes/)
    expect(el.tagName).toBe('TIME') // representable: still a valid <time>
    expect(el.getAttribute('datetime')).toMatch(/^\d{4}-\d{2}-\d{2}T/)
    expect(el.textContent).not.toMatch(/just now|ago/)
  })
})

describe('SummaryCards', () => {
  it('shows distinct alerts and triggers totals (never conflated)', () => {
    render(
      <SummaryCards
        totals={{
          alert_count: 3,
          alert_occurrence_total: 7,
          event_count: 1200,
          byte_count: 76800,
        }}
      />,
    )
    const alerts = screen.getByText('Alerts').closest('.stat-tile')
    const triggers = screen.getByText('Triggers').closest('.stat-tile')
    expect(alerts).not.toBeNull()
    expect(triggers).not.toBeNull()
    expect(within(alerts as HTMLElement).getByText('3')).toBeInTheDocument()
    expect(within(triggers as HTMLElement).getByText('7')).toBeInTheDocument()
  })
})

describe('AlertTable', () => {
  const alerts = [
    makeAlert({ alert_id: 'a', detector_id: 'portscan', severity: 'medium' }),
    makeAlert({ alert_id: 'b', detector_id: 'synflood', severity: 'critical' }),
  ]

  it('renders a row per alert and selects on the details button', () => {
    const onSelect = vi.fn()
    render(<AlertTable alerts={alerts} selectedId={null} onSelect={onSelect} />)
    expect(screen.getAllByRole('row')).toHaveLength(3) // header + 2 rows
    fireEvent.click(screen.getAllByRole('button', { name: 'Details' })[0])
    expect(onSelect).toHaveBeenCalledWith('a')
  })

  it('sorts by severity over the loaded rows', () => {
    render(<AlertTable alerts={alerts} selectedId={null} onSelect={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: /Severity/ }))
    const rows = screen.getAllByRole('row').slice(1) // drop header
    // critical (b) should sort above medium (a)
    expect(within(rows[0]).getByText('critical')).toBeInTheDocument()
  })
})

describe('states', () => {
  it('renders an empty state message', () => {
    render(<EmptyState>No alerts match the current scope.</EmptyState>)
    expect(screen.getByText('No alerts match the current scope.')).toBeInTheDocument()
  })

  it('renders an error state with a retry action', () => {
    const onRetry = vi.fn()
    render(<ErrorState message="Could not load alerts." onRetry={onRetry} />)
    expect(screen.getByRole('alert')).toHaveTextContent('Could not load alerts.')
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(onRetry).toHaveBeenCalledOnce()
  })
})

describe('TrafficTimelineChart', () => {
  const buckets: TimelineBucket[] = [
    { bucket_ts: 1000, protocol: 'TCP', source_type: 'synthetic', packet_count: 5, byte_count: 1 },
    { bucket_ts: 1001, protocol: 'TCP', source_type: 'synthetic', packet_count: 6, byte_count: 1 },
    {
      bucket_ts: 1_700_000_000,
      protocol: 'TCP',
      source_type: 'live',
      packet_count: 3,
      byte_count: 1,
    },
  ]

  it('renders one chart per provenance with its own axis in All mode', () => {
    const { container } = render(<TrafficTimelineChart buckets={buckets} provenance="all" />)
    expect(container.querySelectorAll('.timeline-single')).toHaveLength(2)
    expect(screen.getByText(/independent event-time axes/)).toBeInTheDocument()
  })

  it('renders a single chart when one provenance is selected', () => {
    const { container } = render(
      <TrafficTimelineChart buckets={buckets} provenance="synthetic" />,
    )
    expect(container.querySelectorAll('.timeline-single')).toHaveLength(1)
  })

  it('renders a safe fallback for a finite live bucket_ts outside Date range', () => {
    // 1e20 is finite (accepted by runtime validation) but 1e20 * 1000 ms is far
    // beyond Date's representable range; the formatter must not throw.
    const outOfRange: TimelineBucket[] = [
      { bucket_ts: 1e20, protocol: 'TCP', source_type: 'live', packet_count: 3, byte_count: 1 },
    ]
    let container!: HTMLElement
    expect(() => {
      container = render(<TrafficTimelineChart buckets={outOfRange} provenance="live" />).container
    }).not.toThrow()
    // The accessible data table shows the raw event-seconds fallback…
    expect(within(container).getByText(`${(1e20).toFixed(0)}s`)).toBeInTheDocument()
    // …and never an invalid/Invalid-Date calendar string.
    expect(container.textContent ?? '').not.toMatch(/Invalid Date|NaN|1970/)
  })
})

describe('LiveFeedStatus', () => {
  it('exposes a polite live region that updates when loaded/total change', () => {
    const { rerender } = render(<LiveFeedStatus loaded={0} total={0} />)
    const region = screen.getByRole('status')
    expect(region).toHaveAttribute('aria-live', 'polite')
    expect(region).toHaveAttribute('aria-atomic', 'true')
    expect(region).toHaveTextContent('0 alerts loaded, 0 total in scope.')
    rerender(<LiveFeedStatus loaded={2} total={5} />)
    expect(screen.getByRole('status')).toHaveTextContent('2 alerts loaded, 5 total in scope.')
  })
})
