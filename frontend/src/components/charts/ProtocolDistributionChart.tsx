import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

import type { ProtocolCount } from '../../types/stats.ts'
import { formatBytes, formatInt } from '../../utils/format.ts'

/**
 * Protocol distribution — a single-hue magnitude chart (identity is the protocol
 * label, length is the packet count), with a visually-hidden data table as the
 * accessible text alternative.
 */
export function ProtocolDistributionChart({ data }: { data: ProtocolCount[] }) {
  const rows = data.map((row) => ({
    protocol: row.protocol,
    packets: row.packet_count,
    bytes: row.byte_count,
  }))
  return (
    <section className="chart-card" aria-label="Protocol distribution">
      <h3>Protocol distribution</h3>
      {rows.length === 0 ? (
        <p className="muted">No traffic recorded yet.</p>
      ) : (
        <>
          <div className="chart chart-magnitude" aria-hidden="true">
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={rows} margin={{ top: 8, right: 8, bottom: 4, left: 4 }}>
                <CartesianGrid strokeDasharray="2 3" vertical={false} />
                <XAxis dataKey="protocol" tickLine={false} axisLine={false} />
                <YAxis tickLine={false} axisLine={false} width={48} />
                <Tooltip cursor={{ fillOpacity: 0.08 }} />
                <Bar dataKey="packets" fill="currentColor" radius={[4, 4, 0, 0]} maxBarSize={64} />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <table className="sr-only">
            <caption>Protocol distribution</caption>
            <thead>
              <tr>
                <th scope="col">Protocol</th>
                <th scope="col">Packets</th>
                <th scope="col">Bytes</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.protocol}>
                  <th scope="row">{row.protocol}</th>
                  <td>{formatInt(row.packets)}</td>
                  <td>{formatBytes(row.bytes)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </section>
  )
}
