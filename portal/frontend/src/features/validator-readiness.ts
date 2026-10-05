type Data = Record<string, any>;
type Input = {validator: Data; preflight?: Data; payload: Data; warningsAccepted: boolean; credentials: {authentication: boolean; sudo: boolean}; operation: string; upgradeConfirmed: boolean; permission: boolean; busy: boolean};
export function provisioningReadiness(input: Input) {
  const {validator, preflight, payload, credentials} = input;
  const facts = preflight?.facts || {};
  const supported = ['supported', 'supported_with_warnings'].includes(preflight?.status);
  const platform = facts.os === 'ubuntu' ? `Ubuntu ${facts.os_version} ${facts.architecture}` : 'this host';
  const compatible = payload.available === true && (!payload.platforms || payload.platforms.some((item: Data) => ['os', 'os_version', 'architecture'].every(key => item[key] === facts[key])));
  const checks = [
    {id: 'fingerprint', title: 'SSH fingerprint trusted', ready: !!validator.ssh_fingerprint, reason: 'Discover and confirm the SSH fingerprint through a trusted VM console.'},
    {id: 'connection', title: 'Authenticated connection tested', ready: supported, reason: 'Complete authenticated Test Connection successfully.'},
    {id: 'preflight', title: 'Host preflight supported', ready: supported && preflight?.supported !== false && !Object.values(preflight?.checks || {}).includes(false), reason: 'Host preflight must pass all required checks on Ubuntu Server 22.04 or 24.04 LTS.'},
    {id: 'warnings', title: 'Preflight warnings acknowledged', ready: !preflight?.warnings?.length || input.warningsAccepted, reason: 'Acknowledge the preflight warnings before provisioning.'},
    {id: 'credentials', title: 'Bootstrap credentials entered', ready: credentials.authentication, reason: 'Enter temporary bootstrap credentials again after Test Connection.'},
    {id: 'sudo', title: 'Sudo credentials available', ready: facts.sudo_password_required !== true || credentials.sudo, reason: 'Enter the sudo password required by this host.'},
    {id: 'api_port', title: 'Validator API port available', ready: preflight?.checks?.api_port !== false && (facts.api_port_available !== false || facts.existing_service === true), reason: 'The validator API port is unavailable. Resolve the port conflict before provisioning.'},
    {id: 'payload', title: 'Compatible installation payload verified', ready: compatible, reason: `No compatible verified ${platform} validator payload is configured. ${payload.reason || 'Configure the trusted offline installation payload in HQ.'}`},
    {id: 'upgrade', title: input.operation === 'upgrade' ? 'Upgrade explicitly confirmed' : 'Upgrade confirmation not required', ready: input.operation !== 'upgrade' || input.upgradeConfirmed, reason: 'Explicitly confirm the upgrade using the verified installation payload.'},
    {id: 'permission', title: 'Operation permission granted', ready: input.permission, reason: 'Administrator permission for this operation is required.'},
    {id: 'busy', title: 'No operation in progress', ready: !input.busy, reason: 'Wait for the current request or provisioning attempt to finish.'},
  ];
  const durable = validator.provisioning_readiness?.checks;
  if (durable) for (const check of checks) {
    const backend = durable[check.id === 'connection' ? 'connectionTest' : check.id === 'api_port' ? 'apiPort' : check.id];
    if (backend?.ready === false && !['credentials', 'warnings', 'upgrade', 'busy', 'permission'].includes(check.id)) {
      check.ready = false;
      check.reason = backend.reason || check.reason;
    }
  }
  return {ready: checks.every(check => check.ready), checks};
}
