import { useQuery } from '@tanstack/react-query';
import { fetchExplanation } from '../../api/client';
import { useInvestigationStore } from '../../store/investigationStore';

export default function ExplanationPanel() {
  const selectedAlert = useInvestigationStore((state) => state.selectedAlert);

  const explanationQuery = useQuery({
    queryKey: ['alert-explanation', selectedAlert?.alert_id],
    queryFn: () => fetchExplanation(selectedAlert?.alert_id ?? ''),
    enabled: !!selectedAlert?.alert_id
  });

  if (!selectedAlert) {
    return <div className="explanation-state">Select an alert to inspect its reasoning and investigative guidance.</div>;
  }

  if (explanationQuery.isLoading) {
    return <div className="explanation-state">Generating analyst-facing explanation…</div>;
  }

  if (!explanationQuery.data) {
    return <div className="explanation-state">Explanation is currently unavailable for this alert.</div>;
  }

  const explanation = explanationQuery.data;

  return (
    <div className="explanation">
      <div className="explanation__summary">
        <strong>{selectedAlert.title}</strong>
        <p>{explanation.summary}</p>
      </div>

      <section className="explanation__section">
        <h3>Reasoning Chain</h3>
        <ol className="ordered-list">
          {explanation.reasoning_chain.map((step, index) => {
            const text = typeof step === 'string' ? step : `${step.title}: ${step.detail}`;
            return <li key={index}>{text}</li>;
          })}
        </ol>
      </section>

      <section className="explanation__section">
        <h3>ATT&CK Tactics</h3>
        <div className="tag-list">
          {explanation.attack_tactics.map((tactic) => (
            <span key={tactic} className="tag">
              {tactic}
            </span>
          ))}
        </div>
      </section>

      <section className="explanation__section">
        <h3>Confidence Summary</h3>
        <p>{explanation.confidence_explanation ?? explanation.confidence_summary}</p>
      </section>

      <section className="explanation__section">
        <h3>Next Steps</h3>
        <ul className="ordered-list ordered-list--unordered">
          {explanation.next_steps.map((step) => (
            <li key={step}>{step}</li>
          ))}
        </ul>
      </section>
    </div>
  );
}