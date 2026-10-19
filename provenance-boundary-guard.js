/**
 * Research-inspired provenance boundary for a trusted same-process host.
 * This is not a prompt-injection detector, JS taint tracker, or sandbox. The host
 * alone must retain the policy/registration API; do not expose it as an agent tool.
 * Serialized handoffs require this instance's trusted registry/transport. They are
 * not cryptographic attestations and cannot be authenticated by another instance.
 */
export function createProvenanceBoundaryGuard({ taskId, allowedActions } = {}) {
  const label = value => typeof value === 'string' && value.trim().length > 0;
  const clone = value => JSON.parse(JSON.stringify(value));
  const freeze = value => { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; };
  const actionCopy = action => {
    if (!action || !['tool', 'operation', 'destination'].every(key => label(action[key]))) throw new TypeError('An exact tool, operation, and destination are required');
    return { tool: action.tool, operation: action.operation, destination: action.destination };
  };
  if (!label(taskId) || !Array.isArray(allowedActions) || !allowedActions.length) throw new TypeError('Task and allowed actions are required');
  const same = (a, b) => ['tool', 'operation', 'destination'].every(key => a[key] === b[key]);
  const policyId = globalThis.crypto?.randomUUID?.() ?? `policy-${Date.now()}-${Math.random()}`;
  const policy = freeze({ policyId, taskId, allowedActions: allowedActions.map(actionCopy) });
  const records = new WeakMap();
  const sources = new Set();
  const handoffs = new Map();
  let sequence = 0;
  const get = handle => {
    const record = handle && typeof handle === 'object' ? records.get(handle) : null;
    if (!record) throw new TypeError('Unknown or forged handle; use this host registry');
    return record;
  };
  const put = record => { const handle = Object.freeze({}); records.set(handle, freeze(record)); return handle; };
  const requireData = handle => { const record = get(handle); if (record.channel !== 'data') throw new TypeError('Expected a data handle'); return record; };
  const api = {
    policy() { return clone(policy); },
    authorizeInstruction(text, action) {
      if (!label(text)) throw new TypeError('Host instruction must be nonempty');
      const scope = actionCopy(action);
      if (!policy.allowedActions.some(item => same(item, scope))) throw new Error('Instruction scope is outside original host policy');
      return put({ id: `instruction-${++sequence}`, channel: 'control', trust: 'host-instruction', text, action: scope, taskId });
    },
    registerData(text, { sourceId, kind = 'external' } = {}) {
      if (typeof text !== 'string' || !label(sourceId) || sources.has(sourceId) || !['external', 'agent'].includes(kind)) throw new TypeError('Unique nonempty sourceId and external/agent data are required');
      sources.add(sourceId);
      return put({ id: `data-${++sequence}`, channel: 'data', trust: 'untrusted', text, sourceIds: [sourceId], kind, taskId });
    },
    deriveData(text, inputs) {
      if (typeof text !== 'string' || !Array.isArray(inputs) || !inputs.length) throw new TypeError('Derived data requires text and at least one registered source');
      const parents = inputs.map(requireData);
      return put({ id: `data-${++sequence}`, channel: 'data', trust: 'untrusted', text, sourceIds: [...new Set(parents.flatMap(item => item.sourceIds))].sort(), parentIds: parents.map(item => item.id), kind: 'derived', taskId });
    },
    inspect(handle) { return clone(get(handle)); },
    exportHandoff({ authorization, data } = {}) {
      const control = get(authorization);
      if (control.channel !== 'control') throw new TypeError('Data cannot become control authority');
      if (!Array.isArray(data) || !data.length) throw new TypeError('Handoff requires registered data');
      const values = data.map(requireData);
      const ticket = `handoff-${++sequence}`;
      const serialized = JSON.stringify({ ticket, policy, control, data: values });
      handoffs.set(ticket, { serialized, authorization, data: [...data] });
      return serialized;
    },
    receiveHandoff(serialized) {
      let envelope;
      try { envelope = JSON.parse(serialized); } catch { throw new TypeError('Malformed handoff'); }
      const saved = handoffs.get(envelope?.ticket);
      if (!saved || serialized !== saved.serialized) throw new Error('Unknown, tampered, or replayed handoff');
      handoffs.delete(envelope.ticket);
      return { authorization: saved.authorization, data: [...saved.data], policy: clone(policy) };
    },
    check({ authorization, action, data = [] } = {}) {
      try {
        const instruction = get(authorization);
        if (instruction.channel !== 'control') return { allowed: false, reason: 'Data cannot authorize an action' };
        const proposed = actionCopy(action);
        if (!same(instruction.action, proposed) || !policy.allowedActions.some(item => same(item, proposed))) return { allowed: false, reason: 'Action does not match host instruction and original exact-destination policy' };
        if (!Array.isArray(data)) throw new TypeError('Data must be registered handles');
        data.forEach(requireData);
        return { allowed: true, reason: 'Host instruction and original policy match; data remains untrusted' };
      } catch (error) { return { allowed: false, reason: error.message }; }
    },
    async run(request, execute) {
      const decision = api.check(request);
      if (!decision.allowed) return decision;
      if (typeof execute !== 'function') throw new TypeError('Executor is required');
      // Snapshot all mutable parameters before the executor can suspend or callers mutate.
      const dispatched = freeze({ taskId, action: actionCopy(request.action), params: clone(request.params ?? {}), data: request.data?.map(handle => clone(requireData(handle))) ?? [] });
      return { ...decision, result: await execute(dispatched) };
    },
  };
  return Object.freeze(api);
}
