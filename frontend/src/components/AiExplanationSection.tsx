import type { Alert } from '../types/alert.ts'

/**
 * The optional AI-explanation section — INERT until the Phase 7 AI layer exists.
 * Today ai_status is always "none" and ai_explanation is null. When populated
 * later, the text is rendered as plain text (never as HTML) and clearly labelled
 * as AI-generated or a deterministic fallback.
 */
export function AiExplanationSection({ alert }: { alert: Alert }) {
  if (alert.ai_status === 'none' || alert.ai_explanation === null) {
    return (
      <section className="ai-section ai-section-inert" aria-label="AI explanation">
        <h4>AI Security Analyst</h4>
        <p className="ai-inert-note">
          AI explanations arrive in a later phase and are not enabled. The deterministic
          detection engine remains authoritative.
        </p>
      </section>
    )
  }
  const generated = alert.ai_status === 'generated'
  return (
    <section className="ai-section" aria-label="AI explanation">
      <h4>
        AI Security Analyst{' '}
        <span className="ai-tag">{generated ? 'AI-generated' : 'deterministic fallback'}</span>
      </h4>
      <p className="ai-text">{alert.ai_explanation}</p>
    </section>
  )
}
