import {render, screen} from '@testing-library/react';
import {describe, expect, it} from 'vitest';
import {ArtifactEvidence} from './artifact_evidence';
describe('retained vulnerability evidence', () => {
  it('shows exact counters including increases and provenance', () => {
    render(<ArtifactEvidence value={{before: 2, after: 7, source_digest: 'sha256:source', target_digest: 'sha256:target', scope: 'retained_image_patch'}}/>);
    expect(screen.getByText('2')).toBeInTheDocument();
    expect(screen.getByText('7')).toBeInTheDocument();
    expect(screen.getByText('sha256:target')).toBeInTheDocument();
    expect(screen.getByText(/fresh assessment/)).toBeInTheDocument();
  });
  it('does not imply zero when evidence is unavailable', () => {
    render(<ArtifactEvidence/>);
    expect(screen.getByText(/comparison unavailable/)).toBeInTheDocument();
    expect(screen.queryByText('0')).not.toBeInTheDocument();
  });
});
