import { render, screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import { Page } from './login';

it('keeps local and organizational sign-in in the current tab', () => {
  render(<Page data={{ local_available: true, oidc_available: true, next: '/services', csrf_token: 'csrf' }} />);
  const form = screen.getByRole('button', { name: 'Sign in' }).closest('form')!;
  expect(form.getAttribute('method')).toBe('post');
  expect(form.getAttribute('action')).toBe('/login');
  expect(form.hasAttribute('target')).toBe(false);
  const link = screen.getByRole('link', { name: /Sign in with/ });
  expect(link.getAttribute('href')).toBe('/auth/oidc/login?next=%2Fservices');
  expect(link.hasAttribute('target')).toBe(false);
});
