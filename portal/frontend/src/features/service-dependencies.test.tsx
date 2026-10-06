import {afterEach, expect, it} from 'vitest';
import {cleanup, render, screen} from '@testing-library/react';
import {Page} from './service-dependencies';
afterEach(cleanup);
const data = {view:{service:{id:1,service_key:'sample',name:'Sample'}},can:{},dependency_rows:[],dependency_all_total:null};
it.each(['pending','building'])('shows %s assessment without assessed zeros or empty evidence', status => {
  render(<Page data={{...data,dependency_projection_status:status} as any}/>);
  expect(screen.getByRole('status')).toHaveTextContent('background assessment');
  expect(screen.getByRole('link',{name:'Refresh assessment'})).toBeInTheDocument();
  expect(screen.queryByText(/No matching SBOM/)).not.toBeInTheDocument();
  expect(screen.getAllByText('Unknown').length).toBeGreaterThan(0);
});
it('offers an explicit retry after projection failure', () => {
  render(<Page data={{...data,dependency_projection_status:'failed',dependency_projection_error:'Failed to build'} as any}/>);
  expect(screen.getByRole('alert')).toHaveTextContent('Failed to build');
  expect(screen.getByRole('link',{name:'Retry assessment'})).toHaveAttribute('href','/services/sample?dependencies=true&dependency_retry=true');
});
it('renders assessed zero counts only for ready evidence', () => {
  render(<Page data={{...data,dependency_projection_status:'ready',dependency_all_total:0} as any}/>);
  expect(screen.getByText('0')).toBeInTheDocument();
  expect(screen.getByText(/No matching SBOM/)).toBeInTheDocument();
});