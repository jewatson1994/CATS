import {afterEach, expect, it} from 'vitest';
import {cleanup, render, screen} from '@testing-library/react';
import {Page} from './service_activity';
afterEach(cleanup);
it('renders server activity pagination links and page metadata', () => {
  render(<Page data={{view: {service: {id:7, service_key:'sample', name:'Sample'}, version:'1'},
    can:{}, events:[], page:2, page_count:20, total_items:1000,
    pagination_base:'/services/sample?activity=true&page_size=50'} as any}/>);
  expect(screen.getByLabelText('Activity pages')).toHaveTextContent('Page 2 of 20');
  expect(screen.getByRole('link', {name:'Previous'})).toHaveAttribute('href', '/services/sample?activity=true&page_size=50&page=1');
  expect(screen.getByRole('link', {name:'Next'})).toHaveAttribute('href', '/services/sample?activity=true&page_size=50&page=3');
});
