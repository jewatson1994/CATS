import {Callout, PageHeader} from '../components/ui';
import {AccountNav} from './account_shared';

export function Page({ data }: { data: any }) {
  const signedIn = Boolean(data.current_user);
  const form = <form method="post" action="/account/password" className="account-form"><input type="hidden" name="csrf_token" value={data.csrf_token || ''} />
    <label>Current password<input type="password" name="current_password" autoComplete="current-password" required /></label>
    <label>New password<input type="password" name="new_password" autoComplete="new-password" minLength={14} required aria-describedby="password-rule" /></label>
    <label>Confirm new password<input type="password" name="confirmation" autoComplete="new-password" minLength={14} required /></label>
    <button>Update password</button></form>;
  const error = data.error && <Callout tone="danger" title="Password not changed">{data.error}</Callout>;
  // Without a session (for example a required change before first use) keep the focused card.
  if (!signedIn) return <section className="auth-card"><h1>Change password</h1><p id="password-rule">Use at least 14 characters.</p>{data.error && <p className="error" role="alert">{data.error}</p>}{form}</section>;
  return <div className="account-page">
    <PageHeader eyebrow="Account" title="Change password" description="Update the password for your local CATS sign-in."/>
    <AccountNav selected="password"/>
    <section className="panel padded account-panel">{error}
      <p id="password-rule" className="account-rule"><strong>Requirement:</strong> at least 14 characters. Longer passphrases are stronger and easier to remember.</p>
      {form}
    </section>
  </div>;
}
