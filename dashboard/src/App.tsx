import { useState, useEffect, useRef, useCallback, type ReactElement } from 'react';
import {
  Shield, ShieldAlert, Cpu, Activity, Network, FileCode,
  CheckCircle, AlertTriangle, Lock, Unlock, GitBranch,
  Terminal, Eye, Ban, Zap, ArrowRight, Box, Globe, HardDrive, RefreshCw,
  FolderOpen, Search, ShieldCheck, ShieldX, Trash2, Download
} from 'lucide-react';
import './App.css';
import './filemon.css';

// ─── Types ───────────────────────────────────────────────────────────────────

interface Finding {
  id: string;
  type: string;
  severity: string;
  path: string;
  desc: string;
}

interface GraphNode {
  id: string;
  label: string;
  type: 'entrypoint' | 'capability' | 'blocked' | 'sandboxed' | 'safe';
  capability?: string;
  confidence?: number;
}

interface GraphEdge {
  from: string;
  to: string;
  label: string;
}

interface Policy {
  id: string;
  name: string;
  description: string;
  tier: number;
  enabled: boolean;
  triggeredCount: number;
  lastTriggered: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

interface FileEvent {
  id: string;
  path: string;
  agent: string;
  accessType: 'read' | 'write' | 'exec' | 'delete' | 'network';
  status: 'allowed' | 'blocked' | 'pending';
  ts: string;
  size?: string;
}

// ─── Static data ─────────────────────────────────────────────────────────────

const GRAPH_NODES: GraphNode[] = [
  { id: 'n1', label: 'Agent Entry',       type: 'entrypoint' },
  { id: 'n2', label: 'FilesystemRead',    type: 'capability',  capability: 'FilesystemRead',  confidence: 0.91 },
  { id: 'n3', label: 'NetworkAccess',     type: 'blocked',     capability: 'NetworkAccess',   confidence: 0.87 },
  { id: 'n4', label: 'ProcessSpawn',      type: 'blocked',     capability: 'ProcessSpawn',    confidence: 0.95 },
  { id: 'n5', label: 'SecretAccess',      type: 'blocked',     capability: 'SecretAccess',    confidence: 0.78 },
  { id: 'n6', label: 'MCP Tool Invoke',   type: 'sandboxed',   capability: 'McpTool',         confidence: 0.83 },
  { id: 'n7', label: 'git pre-commit',    type: 'blocked',     capability: 'GitHookExec',     confidence: 0.99 },
  { id: 'n8', label: 'Sandbox Kernel',    type: 'sandboxed' },
  { id: 'n9', label: 'Policy Enforcer',   type: 'safe' },
];

const GRAPH_EDGES: GraphEdge[] = [
  { from: 'n1', to: 'n2', label: 'reads' },
  { from: 'n1', to: 'n3', label: 'attempts' },
  { from: 'n1', to: 'n4', label: 'attempts' },
  { from: 'n1', to: 'n5', label: 'attempts' },
  { from: 'n1', to: 'n6', label: 'invokes' },
  { from: 'n1', to: 'n7', label: 'executes' },
  { from: 'n6', to: 'n8', label: 'routed to' },
  { from: 'n3', to: 'n9', label: 'blocked by' },
  { from: 'n4', to: 'n9', label: 'blocked by' },
  { from: 'n7', to: 'n9', label: 'blocked by' },
];

const POLICIES: Policy[] = [
  {
    id: 'p1',
    name: 'Hostile-by-Default Routing',
    description: 'All agent requests are denied by default unless explicitly routed and approved by the governance engine.',
    tier: 0, enabled: true, triggeredCount: 142, lastTriggered: '02:04:11',
    severity: 'critical',
  },
  {
    id: 'p2',
    name: 'ProcessSpawn Escalation',
    description: 'Any attempt to spawn a child process triggers mandatory human review before execution is permitted.',
    tier: 2, enabled: true, triggeredCount: 7, lastTriggered: '01:58:42',
    severity: 'critical',
  },
  {
    id: 'p3',
    name: 'NetworkAccess Restriction',
    description: 'Outbound network calls from AI agents are blocked unless the session holds explicit NetworkAccess capability approval.',
    tier: 2, enabled: true, triggeredCount: 23, lastTriggered: '02:01:09',
    severity: 'high',
  },
  {
    id: 'p4',
    name: 'Git Hook Execution Block',
    description: 'All git lifecycle hooks (.git/hooks/*) are treated as untrusted code and blocked from executing during AI sessions.',
    tier: 1, enabled: true, triggeredCount: 4, lastTriggered: '01:55:30',
    severity: 'critical',
  },
  {
    id: 'p5',
    name: 'MCP Tool Sandbox Isolation',
    description: 'MCP tool invocations are automatically routed through the gVisor/firecracker execution kernel for isolation.',
    tier: 3, enabled: true, triggeredCount: 18, lastTriggered: '02:03:55',
    severity: 'high',
  },
  {
    id: 'p6',
    name: 'Secret Access Interception',
    description: 'Access to environment secrets, API keys, and credential stores is intercepted and logged with mandatory audit trail.',
    tier: 1, enabled: true, triggeredCount: 2, lastTriggered: '01:44:17',
    severity: 'high',
  },
  {
    id: 'p7',
    name: 'Latency Hard Limit',
    description: 'Any API response taking over 2.0 seconds triggers a latency warning and is logged for performance review.',
    tier: 3, enabled: true, triggeredCount: 0, lastTriggered: 'Never',
    severity: 'medium',
  },
  {
    id: 'p8',
    name: 'AST Deterministic Parsing',
    description: 'All agent-supplied code is parsed via deterministic AST analysis before any execution is permitted.',
    tier: 1, enabled: true, triggeredCount: 89, lastTriggered: '02:04:05',
    severity: 'medium',
  },
];

// ─── Node type config ─────────────────────────────────────────────────────────

const nodeConfig = {
  entrypoint: { color: 'var(--accent-secondary)', icon: <Terminal size={14} />, label: 'Entry' },
  capability:  { color: 'var(--accent-primary)',   icon: <Zap size={14} />,      label: 'Allowed' },
  blocked:     { color: 'var(--accent-danger)',    icon: <Ban size={14} />,      label: 'Blocked' },
  sandboxed:   { color: 'var(--accent-warning)',   icon: <Box size={14} />,      label: 'Sandboxed' },
  safe:        { color: '#9a9a9d',                 icon: <Shield size={14} />,   label: 'Enforcer' },
};

// ─── Sub-views ────────────────────────────────────────────────────────────────

const OverviewTab = ({ riskScore, findings }: { riskScore: number; findings: Finding[] }) => (
  <div className="dashboard-grid animate-fade-in">
    {/* Risk Score */}
    <div className="card glass-panel score-card">
      <h2 className="card-title">Aggregated Risk Score</h2>
      <div className="score-display">
        <div className="score-ring">
          <span className="score-value text-gradient font-mono">{riskScore}</span>
          <span className="score-max">/ 100</span>
        </div>
        <div className="score-details">
          <div className="detail-item">
            <span className="detail-label">Severity Level</span>
            <span className="badge badge-danger">Critical</span>
          </div>
          <div className="detail-item">
            <span className="detail-label">Hostile By Default</span>
            <span className="badge badge-success">Enforced</span>
          </div>
          <div className="detail-item">
            <span className="detail-label">Implicit Execution</span>
            <span className="badge badge-success">Denied</span>
          </div>
        </div>
      </div>
    </div>

    {/* Execution Context */}
    <div className="card glass-panel telemetry-card">
      <h2 className="card-title">Execution Context</h2>
      <div className="telemetry-grid">
        <div className="telemetry-item">
          <Activity size={20} color="var(--accent-secondary)" />
          <div className="t-info"><span className="t-val font-mono">142</span><span className="t-label">Nodes Analyzed</span></div>
        </div>
        <div className="telemetry-item">
          <Network size={20} color="var(--accent-primary)" />
          <div className="t-info"><span className="t-val font-mono">3</span><span className="t-label">Capabilities Extracted</span></div>
        </div>
        <div className="telemetry-item">
          <FileCode size={20} color="var(--text-secondary)" />
          <div className="t-info"><span className="t-val font-mono">24</span><span className="t-label">Files Scanned</span></div>
        </div>
      </div>
      <div className="ai-insight">
        <Cpu size={16} color="var(--accent-warning)" />
        <p><strong>Tier 1 Semantic Insight:</strong> High probability of orchestration poisoning via git hooks. Recommend sandbox isolation.</p>
      </div>
    </div>

    {/* Findings */}
    <div className="card glass-panel findings-card">
      <div className="card-header">
        <h2 className="card-title">Security Findings</h2>
        <span className="badge badge-warning">{findings.length} Detected</span>
      </div>
      <div className="findings-list">
        {findings.map((f) => (
          <div className="finding-item" key={f.id}>
            <div className="finding-icon">
              {f.severity === 'Critical'
                ? <ShieldAlert size={20} color="var(--accent-danger)" />
                : <AlertTriangle size={20} color="var(--accent-warning)" />}
            </div>
            <div className="finding-content">
              <div className="finding-top">
                <span className="finding-type font-mono">{f.type}</span>
                <span className={`badge badge-${f.severity === 'Critical' ? 'danger' : 'warning'}`}>{f.severity}</span>
              </div>
              <p className="finding-path font-mono">{f.path}</p>
              <p className="finding-desc">{f.desc}</p>
            </div>
          </div>
        ))}
      </div>
    </div>

    {/* Active policies mini-list */}
    <div className="card glass-panel policies-card">
      <h2 className="card-title">Active Policy Enforcements</h2>
      <ul className="policy-list">
        <li><CheckCircle size={16} color="var(--accent-primary)" /><span>Blocked unprompted `cargo build` in hook.</span></li>
        <li><CheckCircle size={16} color="var(--accent-primary)" /><span>Isolated MCP tool invocation in gVisor sandbox.</span></li>
        <li><CheckCircle size={16} color="var(--accent-primary)" /><span>Denied capability `NetworkAccess` for `sync.ts`.</span></li>
      </ul>
    </div>
  </div>
);

// ── Execution Graph Tab ────────────────────────────────────────────────────────

const GraphTab = () => {
  const [selected, setSelected] = useState<GraphNode | null>(null);

  const typeCount = {
    blocked:   GRAPH_NODES.filter(n => n.type === 'blocked').length,
    sandboxed: GRAPH_NODES.filter(n => n.type === 'sandboxed').length,
    allowed:   GRAPH_NODES.filter(n => n.type === 'capability').length,
  };

  return (
    <div className="graph-layout animate-fade-in">
      {/* Legend + Stats row */}
      <div className="graph-stats-row">
        <div className="graph-stat-card glass-panel">
          <Ban size={20} color="var(--accent-danger)" />
          <div><span className="graph-stat-num font-mono">{typeCount.blocked}</span><span className="graph-stat-label">Blocked</span></div>
        </div>
        <div className="graph-stat-card glass-panel">
          <Box size={20} color="var(--accent-warning)" />
          <div><span className="graph-stat-num font-mono">{typeCount.sandboxed}</span><span className="graph-stat-label">Sandboxed</span></div>
        </div>
        <div className="graph-stat-card glass-panel">
          <CheckCircle size={20} color="var(--accent-primary)" />
          <div><span className="graph-stat-num font-mono">{typeCount.allowed}</span><span className="graph-stat-label">Allowed</span></div>
        </div>
        <div className="graph-stat-card glass-panel">
          <Eye size={20} color="var(--accent-secondary)" />
          <div><span className="graph-stat-num font-mono">{GRAPH_EDGES.length}</span><span className="graph-stat-label">Edges Traced</span></div>
        </div>
      </div>

      <div className="graph-body">
        {/* Visual graph */}
        <div className="graph-canvas glass-panel">
          <div className="graph-title">
            <GitBranch size={16} color="var(--accent-primary)" />
            <span>Capability Execution Graph</span>
            <span className="badge badge-warning">142 nodes total</span>
          </div>

          {/* Agent entrypoint */}
          <div className="graph-section entrypoint-section">
            <div
              className="graph-node node-entrypoint"
              onClick={() => setSelected(GRAPH_NODES[0])}
            >
              <Terminal size={18} />
              <span>Agent Entry</span>
            </div>
          </div>

          {/* Arrow */}
          <div className="graph-arrow-down"><ArrowRight size={16} style={{ transform: 'rotate(90deg)' }} /></div>

          {/* Capability nodes */}
          <div className="graph-section capability-section">
            {GRAPH_NODES.filter(n => n.type !== 'entrypoint' && n.type !== 'safe').map(node => {
              const cfg = nodeConfig[node.type];
              return (
                <div
                  key={node.id}
                  className={`graph-node node-${node.type}`}
                  onClick={() => setSelected(node)}
                >
                  {cfg.icon}
                  <span>{node.label}</span>
                  {node.confidence && (
                    <span className="node-confidence font-mono">{(node.confidence * 100).toFixed(0)}%</span>
                  )}
                </div>
              );
            })}
          </div>

          {/* Arrow */}
          <div className="graph-arrow-down"><ArrowRight size={16} style={{ transform: 'rotate(90deg)' }} /></div>

          {/* Policy enforcer */}
          <div className="graph-section entrypoint-section">
            <div
              className="graph-node node-safe"
              onClick={() => setSelected(GRAPH_NODES.find(n => n.type === 'safe')!)}
            >
              <Shield size={18} />
              <span>Policy Enforcer</span>
            </div>
          </div>

          {/* Legend */}
          <div className="graph-legend">
            {Object.entries(nodeConfig).map(([type]) => (
              <div key={type} className="legend-item">
                <span className={`legend-dot legend-dot--${type}`} />
                <span>{nodeConfig[type as keyof typeof nodeConfig].label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Detail panel */}
        <div className="graph-detail glass-panel">
          <h3 className="detail-heading">
            <Eye size={16} color="var(--accent-primary)" /> Node Inspector
          </h3>
          {selected ? (
            <div className="node-detail-content">
              <div className={`node-detail-header node-detail-header--${selected.type}`} data-type={selected.type}>
                <span className={`node-icon node-icon--${selected.type}`}>{nodeConfig[selected.type].icon}</span>
                <strong>{selected.label}</strong>
                <span className={`badge node-badge--${selected.type}`}>
                  {nodeConfig[selected.type].label}
                </span>
              </div>
              <div className="node-detail-rows">
                <div className="node-detail-row">
                  <span className="ndr-label">Node ID</span>
                  <span className="ndr-val font-mono">{selected.id}</span>
                </div>
                <div className="node-detail-row">
                  <span className="ndr-label">Type</span>
                  <span className="ndr-val">{selected.type}</span>
                </div>
                {selected.capability && (
                  <div className="node-detail-row">
                    <span className="ndr-label">Capability</span>
                    <span className="ndr-val font-mono">{selected.capability}</span>
                  </div>
                )}
                {selected.confidence && (
                  <div className="node-detail-row">
                    <span className="ndr-label">Confidence</span>
                    <div className="confidence-bar-wrap">
                      <progress
                        className={`confidence-bar confidence-bar--${selected.type}`}
                        value={Math.round(selected.confidence * 100)}
                        max={100}
                        aria-label={`Confidence: ${(selected.confidence * 100).toFixed(0)}%`}
                      />
                      <span className="font-mono">{(selected.confidence * 100).toFixed(0)}%</span>
                    </div>
                  </div>
                )}
                <div className="node-detail-row">
                  <span className="ndr-label">Edges</span>
                  <span className="ndr-val font-mono">
                    {GRAPH_EDGES.filter(e => e.from === selected.id || e.to === selected.id).length}
                  </span>
                </div>
                <div className="node-detail-row">
                  <span className="ndr-label">Decision</span>
                  <span className={`badge badge-${selected.type === 'blocked' ? 'danger' : selected.type === 'sandboxed' ? 'warning' : 'success'}`}>
                    {selected.type === 'blocked' ? 'DENIED' : selected.type === 'sandboxed' ? 'ISOLATED' : 'PERMITTED'}
                  </span>
                </div>
              </div>
              <div className="node-edges-section">
                <p className="ndr-label">Connected edges</p>
                {GRAPH_EDGES.filter(e => e.from === selected.id || e.to === selected.id).map((e, i) => (
                  <div key={i} className="edge-row font-mono">
                    <span>{e.from}</span>
                    <ArrowRight size={12} />
                    <span>{e.to}</span>
                    <span className="edge-label">{e.label}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="node-detail-empty">
              <Eye size={32} color="var(--border-color)" />
              <p>Click a node to inspect its properties</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// ── Policy Modal ──────────────────────────────────────────────────────────────

const BLANK_POLICY: Omit<Policy, 'id'> = {
  name: '', description: '', tier: 1, enabled: true,
  triggeredCount: 0, lastTriggered: 'Never', severity: 'medium',
};

const PolicyModal = ({
  initial, onSave, onClose,
}: {
  initial?: Policy;
  onSave: (p: Omit<Policy, 'id'>) => void;
  onClose: () => void;
}) => {
  const [form, setForm] = useState<Omit<Policy, 'id'>>(
    initial ? { ...initial } : { ...BLANK_POLICY }
  );
  const isEdit = !!initial;

  const field = <K extends keyof typeof form>(key: K, val: typeof form[K]) =>
    setForm(prev => ({ ...prev, [key]: val }));

  const valid = form.name.trim().length > 0 && form.description.trim().length > 0;

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-box glass-panel animate-fade-in" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h2 className="modal-title">
            {isEdit ? '✏️ Edit Policy' : '＋ New Policy'}
          </h2>
          <button className="modal-close" onClick={onClose} aria-label="Close">✕</button>
        </div>

        <div className="modal-body">
          {/* Name */}
          <div className="form-group">
            <label className="form-label" htmlFor="policy-name">Policy Name *</label>
            <input
              id="policy-name"
              className="form-input"
              placeholder="e.g. FileSystem Write Block"
              value={form.name}
              onChange={e => field('name', e.target.value)}
            />
          </div>

          {/* Description */}
          <div className="form-group">
            <label className="form-label" htmlFor="policy-desc">Description *</label>
            <textarea
              id="policy-desc"
              className="form-input form-textarea"
              placeholder="Describe what this policy enforces…"
              rows={3}
              value={form.description}
              onChange={e => field('description', e.target.value)}
            />
          </div>

          {/* Severity + Tier row */}
          <div className="form-row">
            <div className="form-group">
              <label className="form-label" htmlFor="policy-severity">Severity</label>
              <select
                id="policy-severity"
                className="form-input form-select"
                aria-label="Policy severity"
                value={form.severity}
                onChange={e => field('severity', e.target.value as Policy['severity'])}
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="policy-tier">Tier (0 – 3)</label>
              <select
                id="policy-tier"
                className="form-input form-select"
                aria-label="Policy tier"
                value={form.tier}
                onChange={e => field('tier', Number(e.target.value))}
              >
                {[0, 1, 2, 3].map(t => <option key={t} value={t}>Tier {t}</option>)}
              </select>
            </div>
          </div>

          {/* Enabled toggle */}
          <div className="form-group form-group--inline">
            <label className="form-label">Enabled by default</label>
            <button
              className={`toggle-btn ${form.enabled ? 'toggle-on' : 'toggle-off'}`}
              onClick={() => field('enabled', !form.enabled)}
              type="button"
            >
              {form.enabled ? <Lock size={13} /> : <Unlock size={13} />}
              {form.enabled ? 'ON' : 'OFF'}
            </button>
          </div>
        </div>

        <div className="modal-footer">
          <button className="modal-btn modal-btn--cancel" onClick={onClose}>Cancel</button>
          <button
            className={`modal-btn modal-btn--save ${!valid ? 'modal-btn--disabled' : ''}`}
            disabled={!valid}
            onClick={() => { if (valid) { onSave(form); onClose(); } }}
          >
            {isEdit ? 'Save Changes' : 'Add Policy'}
          </button>
        </div>
      </div>
    </div>
  );
};

// ── Delete Confirm ─────────────────────────────────────────────────────────────

const DeleteConfirm = ({ name, onConfirm, onClose }: { name: string; onConfirm: () => void; onClose: () => void }) => (
  <div className="modal-backdrop" onClick={onClose}>
    <div className="modal-box modal-box--sm glass-panel animate-fade-in" onClick={e => e.stopPropagation()}>
      <div className="modal-header">
        <h2 className="modal-title">🗑 Delete Policy</h2>
        <button className="modal-close" onClick={onClose} aria-label="Close">✕</button>
      </div>
      <div className="modal-body">
        <p className="delete-confirm-text">
          Are you sure you want to delete <strong>"{name}"</strong>?
          <br />This action cannot be undone.
        </p>
      </div>
      <div className="modal-footer">
        <button className="modal-btn modal-btn--cancel" onClick={onClose}>Cancel</button>
        <button className="modal-btn modal-btn--delete" onClick={() => { onConfirm(); onClose(); }}>
          Delete
        </button>
      </div>
    </div>
  </div>
);

// ── Policies Tab ──────────────────────────────────────────────────────────────

const PoliciesTab = () => {
  const [policies, setPolicies] = useState<Policy[]>(POLICIES);
  const [filter, setFilter]     = useState<string>('all');
  const [modal, setModal]       = useState<'add' | 'edit' | 'delete' | null>(null);
  const [target, setTarget]     = useState<Policy | null>(null);

  // ── CRUD helpers ─────────────────────────────────────────────────────────────
  const toggle = (id: string) =>
    setPolicies(prev => prev.map(p => p.id === id ? { ...p, enabled: !p.enabled } : p));

  const addPolicy = (form: Omit<Policy, 'id'>) =>
    setPolicies(prev => [...prev, { ...form, id: Math.random().toString(36).substr(2, 9) }]);

  const editPolicy = (id: string, form: Omit<Policy, 'id'>) =>
    setPolicies(prev => prev.map(p => p.id === id ? { ...p, ...form } : p));

  const deletePolicy = (id: string) =>
    setPolicies(prev => prev.filter(p => p.id !== id));

  const openEdit   = (p: Policy) => { setTarget(p); setModal('edit'); };
  const openDelete = (p: Policy) => { setTarget(p); setModal('delete'); };

  // ── Derived ──────────────────────────────────────────────────────────────────
  const filtered      = filter === 'all' ? policies : policies.filter(p => p.severity === filter);
  const enabledCount  = policies.filter(p => p.enabled).length;
  const totalTriggers = policies.reduce((s, p) => s + p.triggeredCount, 0);

  return (
    <>
      {/* ── Modals ─────────────────────────────────────────────────────────── */}
      {modal === 'add' && (
        <PolicyModal onSave={addPolicy} onClose={() => setModal(null)} />
      )}
      {modal === 'edit' && target && (
        <PolicyModal
          initial={target}
          onSave={form => editPolicy(target.id, form)}
          onClose={() => setModal(null)}
        />
      )}
      {modal === 'delete' && target && (
        <DeleteConfirm
          name={target.name}
          onConfirm={() => deletePolicy(target.id)}
          onClose={() => setModal(null)}
        />
      )}

      <div className="policies-layout animate-fade-in">
        {/* Top stats */}
        <div className="policy-stats-row">
          <div className="policy-stat glass-panel">
            <Lock size={20} color="var(--accent-primary)" />
            <div><span className="graph-stat-num font-mono">{enabledCount}/{policies.length}</span><span className="graph-stat-label">Rules Active</span></div>
          </div>
          <div className="policy-stat glass-panel">
            <RefreshCw size={20} color="var(--accent-warning)" />
            <div><span className="graph-stat-num font-mono">{totalTriggers}</span><span className="graph-stat-label">Total Triggers</span></div>
          </div>
          <div className="policy-stat glass-panel">
            <Zap size={20} color="var(--accent-danger)" />
            <div><span className="graph-stat-num font-mono">{policies.filter(p => p.severity === 'critical').length}</span><span className="graph-stat-label">Critical Rules</span></div>
          </div>
          <div className="policy-stat glass-panel">
            <Globe size={20} color="var(--accent-secondary)" />
            <div><span className="graph-stat-num font-mono">Tiers 0–3</span><span className="graph-stat-label">Coverage</span></div>
          </div>
        </div>

        {/* Filter bar + Add button */}
        <div className="policy-filter-bar glass-panel">
          <span className="filter-label">Filter by severity:</span>
          {['all', 'critical', 'high', 'medium', 'low'].map(f => (
            <button key={f} className={`filter-btn ${filter === f ? 'active' : ''}`} onClick={() => setFilter(f)}>
              {f.toUpperCase()}
            </button>
          ))}
          <button className="add-policy-btn" onClick={() => setModal('add')}>
            <span className="add-policy-icon">＋</span> Add Policy
          </button>
        </div>

        {/* Policy cards */}
        <div className="policy-cards-grid">
          {filtered.map(policy => (
            <div key={policy.id} className={`policy-card glass-panel ${!policy.enabled ? 'policy-disabled' : ''}`}>
              {/* Header row */}
              <div className="policy-card-header">
                <div className="policy-card-title-row">
                  <span className={`policy-dot policy-dot--${policy.severity}`} />
                  <strong className="policy-name">{policy.name}</strong>
                  <span className={`badge policy-badge--${policy.severity}`}>
                    {policy.severity.toUpperCase()}
                  </span>
                </div>
                {/* Action cluster */}
                <div className="policy-actions">
                  <button
                    className="action-btn action-btn--edit"
                    title="Edit policy"
                    onClick={() => openEdit(policy)}
                    aria-label={`Edit ${policy.name}`}
                  >✏️</button>
                  <button
                    className="action-btn action-btn--delete"
                    title="Delete policy"
                    onClick={() => openDelete(policy)}
                    aria-label={`Delete ${policy.name}`}
                  >🗑</button>
                  <button
                    className={`toggle-btn ${policy.enabled ? 'toggle-on' : 'toggle-off'}`}
                    onClick={() => toggle(policy.id)}
                    title={policy.enabled ? 'Disable' : 'Enable'}
                  >
                    {policy.enabled ? <Lock size={14} /> : <Unlock size={14} />}
                    {policy.enabled ? 'ON' : 'OFF'}
                  </button>
                </div>
              </div>

              <p className="policy-desc">{policy.description}</p>

              <div className="policy-meta">
                <div className="meta-item">
                  <HardDrive size={12} color="var(--text-secondary)" />
                  <span>Tier {policy.tier}</span>
                </div>
                <div className="meta-item">
                  <Activity size={12} color="var(--text-secondary)" />
                  <span>{policy.triggeredCount} triggers</span>
                </div>
                <div className="meta-item">
                  <RefreshCw size={12} color="var(--text-secondary)" />
                  <span>Last: {policy.lastTriggered}</span>
                </div>
              </div>
            </div>
          ))}

          {/* Empty-state when filter returns nothing */}
          {filtered.length === 0 && (
            <div className="policy-empty">
              <span>No policies match this filter.</span>
              <button className="add-policy-btn" onClick={() => setModal('add')}>＋ Add one</button>
            </div>
          )}
        </div>
      </div>
    </>
  );
};


// ── File Monitor Tab ──────────────────────────────────────────────────────────

const ACCESS_ICONS: Record<string, ReactElement> = {
  read:    <FileCode  size={14} />,
  write:   <HardDrive size={14} />,
  exec:    <Terminal  size={14} />,
  delete:  <Trash2    size={14} />,
  network: <Globe     size={14} />,
};
const DEMO_FILES: FileEvent[] = [
  { id: 'f1',  path: 'src/orchestrator/router.py',         agent: 'aegis-core',   accessType: 'read',    status: 'allowed', ts: '02:04:09', size: '12 KB' },
  { id: 'f2',  path: '.git/hooks/pre-commit',              agent: 'git-hook',     accessType: 'exec',    status: 'blocked', ts: '02:04:11', size: '2 KB'  },
  { id: 'f3',  path: 'tools/sync.ts',                      agent: 'mcp-client',   accessType: 'network', status: 'blocked', ts: '02:01:09', size: '—'     },
  { id: 'f4',  path: 'python/aegis-ai/.env',               agent: 'llm-provider', accessType: 'read',    status: 'blocked', ts: '01:58:42', size: '1 KB'  },
  { id: 'f5',  path: 'src/os/kernel.py',                   agent: 'aegis-core',   accessType: 'read',    status: 'allowed', ts: '01:55:30', size: '8 KB'  },
  { id: 'f6',  path: 'dashboard/dist/index.html',          agent: 'dev-server',   accessType: 'read',    status: 'allowed', ts: '01:44:17', size: '4 KB'  },
  { id: 'f7',  path: '/etc/passwd',                        agent: 'unknown',      accessType: 'read',    status: 'blocked', ts: '01:43:05', size: '2 KB'  },
  { id: 'f8',  path: 'src/telemetry.py',                   agent: 'aegis-core',   accessType: 'write',   status: 'allowed', ts: '01:40:22', size: '6 KB'  },
  { id: 'f9',  path: 'node_modules/.bin/vite',             agent: 'npm',          accessType: 'exec',    status: 'allowed', ts: '01:35:10', size: '—'     },
  { id: 'f10', path: 'memory/session_handoff/current.md',  agent: 'aegis-core',   accessType: 'write',   status: 'pending', ts: '01:30:01', size: '18 KB' },
];

const FileMonitorTab = () => {
  const [files, setFiles]         = useState<FileEvent[]>(DEMO_FILES);
  const [search, setSearch]       = useState('');
  const [statusFilter, setStatus] = useState<'all' | 'allowed' | 'blocked' | 'pending'>('all');
  const [typeFilter, setType]     = useState<string>('all');
  const liveRef                   = useRef<boolean>(true);

  // Simulate live file events via demo ticker
  useEffect(() => {
    const LIVE_EVENTS: Omit<FileEvent, 'id' | 'ts'>[] = [
      { path: 'src/llm/provider.py',          agent: 'llm-provider', accessType: 'read',    status: 'allowed', size: '9 KB' },
      { path: '/tmp/aegis_sandbox_xyz',       agent: 'sandbox',      accessType: 'write',   status: 'allowed', size: '—'   },
      { path: 'secrets/api_keys.json',        agent: 'unknown',      accessType: 'read',    status: 'blocked', size: '3 KB' },
      { path: 'src/orchestrator/governance.py', agent: 'aegis-core', accessType: 'read',    status: 'allowed', size: '14 KB' },
      { path: '/bin/bash',                    agent: 'unknown',      accessType: 'exec',    status: 'blocked', size: '—'   },
    ];
    let i = 0;
    const id = setInterval(() => {
      if (!liveRef.current) return;
      const base = LIVE_EVENTS[i % LIVE_EVENTS.length];
      setFiles(prev => [{
        ...base,
        id: Math.random().toString(36).substr(2, 9),
        ts: new Date().toTimeString().slice(0, 8),
      }, ...prev].slice(0, 200));
      i++;
    }, 3500);
    return () => { liveRef.current = false; clearInterval(id); };
  }, []);

  const toggle = useCallback((id: string, action: 'allowed' | 'blocked') => {
    setFiles(prev => prev.map(f => f.id === id ? { ...f, status: action } : f));
  }, []);

  const clearAll = () => setFiles([]);

  const exportCSV = () => {
    const rows = ['Path,Agent,Type,Status,Time,Size', ...files.map(f =>
      `"${f.path}",${f.agent},${f.accessType},${f.status},${f.ts},${f.size ?? ''}`)].join('\n');
    const blob = new Blob([rows], { type: 'text/csv' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a'); a.href = url; a.download = 'aegis_file_monitor.csv'; a.click();
    URL.revokeObjectURL(url);
  };

  const filtered = files.filter(f => {
    const matchSearch = f.path.toLowerCase().includes(search.toLowerCase()) ||
                        f.agent.toLowerCase().includes(search.toLowerCase());
    const matchStatus = statusFilter === 'all' || f.status === statusFilter;
    const matchType   = typeFilter   === 'all' || f.accessType === typeFilter;
    return matchSearch && matchStatus && matchType;
  });

  const counts = {
    allowed: files.filter(f => f.status === 'allowed').length,
    blocked: files.filter(f => f.status === 'blocked').length,
    pending: files.filter(f => f.status === 'pending').length,
  };

  return (
    <div className="filemon-layout animate-fade-in">
      {/* Stats row */}
      <div className="filemon-stats">
        <div className="filemon-stat glass-panel">
          <FolderOpen size={20} color="var(--accent-primary)" />
          <div><span className="graph-stat-num font-mono">{files.length}</span><span className="graph-stat-label">Total Events</span></div>
        </div>
        <div className="filemon-stat glass-panel">
          <ShieldCheck size={20} color="var(--accent-primary)" />
          <div><span className="graph-stat-num font-mono">{counts.allowed}</span><span className="graph-stat-label">Allowed</span></div>
        </div>
        <div className="filemon-stat glass-panel">
          <ShieldX size={20} color="var(--accent-danger)" />
          <div><span className="graph-stat-num font-mono">{counts.blocked}</span><span className="graph-stat-label">Blocked</span></div>
        </div>
        <div className="filemon-stat glass-panel">
          <Eye size={20} color="var(--accent-warning)" />
          <div><span className="graph-stat-num font-mono">{counts.pending}</span><span className="graph-stat-label">Pending Review</span></div>
        </div>
      </div>

      {/* Toolbar */}
      <div className="filemon-toolbar glass-panel">
        {/* Search */}
        <div className="filemon-search">
          <Search size={14} color="var(--text-secondary)" />
          <input
            className="filemon-search-input"
            placeholder="Search path or agent…"
            aria-label="Search path or agent"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        {/* Status filter */}
        <div className="filemon-filters">
          {(['all','allowed','blocked','pending'] as const).map(s => (
            <button key={s} className={`filter-btn ${statusFilter === s ? 'active' : ''}`} onClick={() => setStatus(s)}>
              {s.toUpperCase()}
            </button>
          ))}
        </div>
        {/* Access type filter */}
        <div className="filemon-filters">
          {['all','read','write','exec','delete','network'].map(t => (
            <button key={t} className={`filter-btn filter-btn--sm ${typeFilter === t ? 'active' : ''}`} onClick={() => setType(t)}>
              {t}
            </button>
          ))}
        </div>
        {/* Actions */}
        <div className="filemon-actions">
          <button className="fmon-action-btn" onClick={exportCSV} title="Export to CSV">
            <Download size={14} /> Export
          </button>
          <button className="fmon-action-btn fmon-action-btn--danger" onClick={clearAll} title="Clear log">
            <Trash2 size={14} /> Clear
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="filemon-table-wrap glass-panel">
        <table className="filemon-table">
          <thead>
            <tr>
              <th>File Path</th>
              <th>Agent</th>
              <th>Access</th>
              <th>Size</th>
              <th>Time</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={7} className="filemon-empty">No events match the current filter.</td></tr>
            ) : filtered.map(f => (
              <tr key={f.id} className={`filemon-row filemon-row--${f.status}`}>
                <td className="filemon-path font-mono">
                  <span className="filemon-access-icon" data-type={f.accessType}>{ACCESS_ICONS[f.accessType]}</span>
                  <span title={f.path}>{f.path.length > 45 ? '…' + f.path.slice(-43) : f.path}</span>
                </td>
                <td className="filemon-agent font-mono">{f.agent}</td>
                <td>
                  <span className={`filemon-type-badge filemon-type--${f.accessType}`}>{f.accessType}</span>
                </td>
                <td className="filemon-size font-mono">{f.size ?? '—'}</td>
                <td className="filemon-ts font-mono">{f.ts}</td>
                <td>
                  <span className={`filemon-status filemon-status--${f.status}`}>
                    {f.status === 'allowed' ? <ShieldCheck size={13}/> : f.status === 'blocked' ? <ShieldX size={13}/> : <Eye size={13}/>}
                    {f.status}
                  </span>
                </td>
                <td className="filemon-row-actions">
                  <button
                    className="fmon-row-btn fmon-row-btn--allow"
                    disabled={f.status === 'allowed'}
                    onClick={() => toggle(f.id, 'allowed')}
                    title="Allow this access"
                  >
                    <ShieldCheck size={13} /> Allow
                  </button>
                  <button
                    className="fmon-row-btn fmon-row-btn--block"
                    disabled={f.status === 'blocked'}
                    onClick={() => toggle(f.id, 'blocked')}
                    title="Block this access"
                  >
                    <ShieldX size={13} /> Block
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};


const App = () => {
  const [activeTab, setActiveTab] = useState('overview');
  const [backendStatus, setBackendStatus] = useState('Checking...');
  const [isOnline, setIsOnline] = useState(false);
  const [riskScore, setRiskScore] = useState(82);
  const [findings, setFindings] = useState<Finding[]>([
    { id: '1', type: 'McpToolInvocation', severity: 'High',     path: 'tools/sync.ts',         desc: 'Implicit network access via MCP tool' },
    { id: '2', type: 'GitHookExecution',  severity: 'Critical', path: '.git/hooks/pre-commit',  desc: 'Hidden git hook attempting to execute node payload' },
  ]);

  useEffect(() => {
    const checkHealth = async () => {
      try {
        const res = await fetch('http://127.0.0.1:8000/health');
        if (res.ok) {
          const data = await res.json();
          setBackendStatus(`System Online (${data.tier})`);
          setIsOnline(true);
        } else { setBackendStatus('System Offline'); setIsOnline(false); }
      } catch { setBackendStatus('System Offline'); setIsOnline(false); }
    };
    checkHealth();
    const id = setInterval(checkHealth, 5000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    let ws: WebSocket;
    let reconnectTimeout: number;
    let backoff = 1000;

    const connectWS = () => {
      ws = new WebSocket('ws://127.0.0.1:8000/ws/telemetry');
      
      ws.onopen = () => {
        backoff = 1000;
      };

      ws.onmessage = (event) => {
        const payload = JSON.parse(event.data);
        if (payload.event === 'OrchestrationRouted' || payload.event === 'SandboxSpawn') {
          const f: Finding = {
            id:       Math.random().toString(36).substr(2, 9),
            type:     payload.event,
            severity: payload.event === 'SandboxSpawn' ? 'Critical' : 'Medium',
            path:     payload.data.session_id || payload.data.execution_id || 'System Kernel',
            desc:     `Autonomous capability requested: ${JSON.stringify(payload.data.requested_capabilities || payload.data.capabilities)}`,
          };
          setFindings(prev => [f, ...prev].slice(0, 5));
          setRiskScore(prev => Math.min(100, prev + 2));
        }
      };

      ws.onclose = () => {
        reconnectTimeout = window.setTimeout(() => {
          backoff = Math.min(backoff * 1.5, 30000);
          connectWS();
        }, backoff);
      };

      ws.onerror = () => {
        ws.close();
      };
    };

    connectWS();

    return () => {
      clearTimeout(reconnectTimeout);
      if (ws) {
        ws.onclose = null; // Prevent reconnect on unmount
        ws.close();
      }
    };
  }, []);

  return (
    <div className="app-container">
      <header className="top-nav glass-panel animate-fade-in delay-100">
        <div className="logo-container">
          <Shield className="logo-icon" size={28} color="var(--accent-primary)" />
          <h1 className="logo-text">AEGIS <span className="logo-subtext">Command Center</span></h1>
        </div>
        <div className="nav-links">
          <button className={`nav-btn ${activeTab === 'overview' ? 'active' : ''}`} onClick={() => setActiveTab('overview')}>Overview</button>
          <button className={`nav-btn ${activeTab === 'graph'   ? 'active' : ''}`} onClick={() => setActiveTab('graph')}>Execution Graph</button>
          <button className={`nav-btn ${activeTab === 'policy'  ? 'active' : ''}`} onClick={() => setActiveTab('policy')}>Policies</button>
          <button className={`nav-btn ${activeTab === 'files' ? 'active' : ''}`} onClick={() => setActiveTab('files')}>
            <FolderOpen size={14} className="nav-icon" />File Monitor
          </button>
        </div>
        <div className="status-indicator">
          <span className={`status-dot ${isOnline ? 'pulsing bg-primary' : 'bg-danger'}`} />
          <span className={`status-text font-mono ${isOnline ? 'text-primary' : 'text-danger'}`}>{backendStatus}</span>
        </div>
      </header>

      {!isOnline && (
        <div className="ws-disconnect-banner">
          <AlertTriangle size={16} className="ws-disconnect-icon" />
          Connection Lost. Reconnecting to telemetry stream...
        </div>
      )}


      <main className="main-content">
        {activeTab === 'overview' && <OverviewTab riskScore={riskScore} findings={findings} />}
        {activeTab === 'graph'    && <GraphTab />}
        {activeTab === 'policy'   && <PoliciesTab />}
        {activeTab === 'files'    && <FileMonitorTab />}
      </main>
    </div>
  );
};

export default App;
