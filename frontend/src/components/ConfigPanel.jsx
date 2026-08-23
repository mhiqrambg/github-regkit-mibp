import React, { useEffect, useState } from 'react'
import { Search, Save, Mail, Shield } from 'lucide-react'
import { api } from '../api.js'
import { Button, Card, Input } from './ui.jsx'

/* ───────────────────── fields ───────────────────── */

const MAILCX_FIELDS = [
  { key: 'mailcx_domain', label: 'Mail.cx Domain', group: 'Mail Provider', hasDomainDropdown: true },
]

const LITENSI_FIELDS = [
  { key: 'litensi_api_id', label: 'Litensi API ID', group: 'Mail Provider' },
  { key: 'litensi_api_key', label: 'Litensi API Key', secret: true, group: 'Mail Provider', wide: true },
  { key: 'litensi_site', label: 'Site (e.g. github.com)', group: 'Mail Provider' },
  { key: 'litensi_zone', label: 'Zone (blank = auto cheapest)', group: 'Mail Provider', hasZoneChecker: true, wide: true },
]

const REG_FIELDS = [
  { key: 'register_count', label: 'Register Count', type: 'number', group: 'Registration' },
  { key: 'delay_sec', label: 'Delay between accounts (seconds)', type: 'number', group: 'Registration' },
  { key: 'max_username_tries', label: 'Max username tries', type: 'number', group: 'Registration' },
  { key: 'otp_timeout_sec', label: 'OTP timeout (seconds)', type: 'number', group: 'Registration' },
  { key: 'proxy', label: 'Proxy (http://user:pass@host:port)', secret: true, group: 'Registration', wide: true },
  { key: 'headless', label: 'Headless (no browser window, less stable)', type: 'checkbox', group: 'Registration', wide: true },
]

const ADV_FIELDS = [
  { key: 'browser_profile_dir', label: 'Browser profile dir (DataDome trust)', group: 'Advanced', wide: true },
  { key: 'proxy_hard_block_retries', label: 'Proxy retries after DataDome hard block', type: 'number', group: 'Advanced' },
  { key: 'proxy_rate_limit_retries', label: 'IP rotation/retries after rate limit', type: 'number', group: 'Advanced' },
  { key: 'fresh_profile', label: 'Fresh browser per account — incognito-like with cloned DataDome cookie', type: 'checkbox', group: 'Advanced', wide: true },
]

const POST_FIELDS = [
  { key: 'repo_name', label: 'Repository name', group: 'Post-Signup Stages' },
  { key: 'create_repo', label: 'Create first repository after signup', type: 'checkbox', group: 'Post-Signup Stages', wide: true },
  { key: 'enable_2fa', label: 'Enable TOTP 2FA and save secret', type: 'checkbox', group: 'Post-Signup Stages', wide: true },
  { key: 'set_profile_status', label: 'Set profile status after 2FA', type: 'checkbox', group: 'Post-Signup Stages', wide: true },
  { key: 'profile_status', label: 'Profile status (blank = On vacation)', group: 'Post-Signup Stages' },
  { key: 'complete_profile', label: 'Complete name, bio, and location after 2FA', type: 'checkbox', group: 'Post-Signup Stages', wide: true },
  { key: 'profile_name', label: 'Profile name (blank = Random User)', group: 'Post-Signup Stages' },
  { key: 'profile_location', label: 'Profile location (blank = Random User)', group: 'Post-Signup Stages' },
  { key: 'profile_bio', label: 'Profile bio (blank = ZenQuotes)', group: 'Post-Signup Stages', wide: true },
]

const GROUP_COLUMN = {
  'Mail Provider': 'left',
  'Registration': 'left',
  'Advanced': 'right',
  'Post-Signup Stages': 'right',
}

/* ───────────────────── main component ───────────────────── */

export default function ConfigPanel() {
  const [cfg, setCfg] = useState(null)
  const [saved, setSaved] = useState('')
  const [busy, setBusy] = useState(false)

  // zone-check modal
  const [zoneOpen, setZoneOpen] = useState(false)
  const [zoneLoading, setZoneLoading] = useState(false)
  const [zoneData, setZoneData] = useState(null)
  const [zoneError, setZoneError] = useState('')

  // mailcx domains
  const [mailcxDomains, setMailcxDomains] = useState([])

  useEffect(() => {
    api.get('/api/config').then((d) => setCfg(d.config)).catch(() => {})
  }, [])

  // fetch mail.cx domains on mount
  useEffect(() => {
    api.post('/api/mailcx/domains', {})
      .then((d) => setMailcxDomains(d.domains || []))
      .catch(() => {})
  }, [])

  if (!cfg) return <div style={{ color: 'var(--muted)', padding: 20 }}>Loading configuration...</div>

  const provider = cfg.mail_provider || 'mailcx'

  function set(key, value) {
    setCfg((c) => ({ ...c, [key]: value }))
    setSaved('')
  }

  async function save() {
    setBusy(true)
    try {
      const patch = {
        mail_provider: provider,
        mailcx_domain: cfg.mailcx_domain ?? '',
        litensi_api_id: cfg.litensi_api_id ?? '',
        litensi_api_key: cfg.litensi_api_key ?? '',
        litensi_site: cfg.litensi_site ?? '',
        litensi_zone: cfg.litensi_zone ?? '',
      }
      // collect fields from each group
      for (const f of [...REG_FIELDS, ...ADV_FIELDS, ...POST_FIELDS]) {
        if (f.type === 'checkbox') patch[f.key] = !!cfg[f.key]
        else if (f.type === 'number') patch[f.key] = Number(cfg[f.key] ?? 0)
        else patch[f.key] = cfg[f.key] ?? ''
      }
      const d = await api.put('/api/config', patch)
      setCfg(d.config)
      setSaved('✓ Configuration saved')
    } catch (e) {
      setSaved('✗ ' + e.message)
    } finally {
      setBusy(false)
    }
  }

  async function checkZones() {
    setZoneOpen(true)
    setZoneLoading(true)
    setZoneError('')
    setZoneData(null)
    try {
      const d = await api.post('/api/litensi/zones', {
        litensi_api_id: String(cfg.litensi_api_id ?? ''),
        litensi_api_key: String(cfg.litensi_api_key ?? ''),
        litensi_site: String(cfg.litensi_site ?? ''),
      })
      setZoneData(d)
    } catch (e) {
      setZoneError(e.message || 'Unable to retrieve zone list')
    } finally {
      setZoneLoading(false)
    }
  }

  function useZone(zone) {
    set('litensi_zone', zone)
    setZoneOpen(false)
  }

  // build mail provider card fields based on provider
  const providerFields = provider === 'litensi' ? LITENSI_FIELDS : MAILCX_FIELDS

  const leftGroups = ['Mail Provider', 'Registration']
  const rightGroups = ['Advanced', 'Post-Signup Stages']

  return (
    <div style={styles.wrap} className="config-layout">
      <div style={styles.columns} className="cfg-columns">
        <div style={styles.col}>
          {/* ── Mail Provider card ── */}
          <Card style={styles.card}>
            <div style={styles.groupTitle}>Mail Provider</div>

            {/* radio toggle */}
            <div style={styles.providerRow}>
              <label style={styles.radioLabel}>
                <input
                  type="radio" name="mail_provider" value="mailcx"
                  checked={provider === 'mailcx'}
                  onChange={() => set('mail_provider', 'mailcx')}
                  style={styles.radio}
                />
                <Mail size={16} style={{ color: provider === 'mailcx' ? 'var(--accent)' : 'var(--muted)' }} />
                <span style={{ color: provider === 'mailcx' ? 'var(--text)' : 'var(--muted)' }}>
                  Mail.cx <span style={styles.badge}>Free</span>
                </span>
              </label>
              <label style={styles.radioLabel}>
                <input
                  type="radio" name="mail_provider" value="litensi"
                  checked={provider === 'litensi'}
                  onChange={() => set('mail_provider', 'litensi')}
                  style={styles.radio}
                />
                <Shield size={16} style={{ color: provider === 'litensi' ? 'var(--accent)' : 'var(--muted)' }} />
                <span style={{ color: provider === 'litensi' ? 'var(--text)' : 'var(--muted)' }}>
                  Litensi <span style={styles.badgePaid}>Paid</span>
                </span>
              </label>
            </div>

            {/* provider-specific fields */}
            <div style={styles.fieldsGrid} className="cfg-fields">
              {provider === 'litensi' ? (
                LITENSI_FIELDS.map((f) => (
                  <div key={f.key} style={f.wide ? styles.fieldWide : styles.fieldHalf}
                    className={f.wide ? 'cfg-field-wide' : 'cfg-field-half'}>
                    <Field
                      f={f} value={cfg[f.key]}
                      onChange={(v) => set(f.key, v)}
                      onCheckZones={f.hasZoneChecker ? checkZones : null}
                    />
                  </div>
                ))
              ) : (
                <>
                  <div style={styles.fieldWide} className="cfg-field-wide">
                    <label style={styles.field}>
                      <span style={styles.label}>Mail.cx Domain</span>
                      <select
                        style={styles.select}
                        value={cfg.mailcx_domain || ''}
                        onChange={(e) => set('mailcx_domain', e.target.value)}
                      >
                        <option value="">Auto (random from available)</option>
                        {mailcxDomains.map((d) => (
                          <option key={d} value={d}>{d}</option>
                        ))}
                      </select>
                    </label>
                  </div>
                </>
              )}
            </div>
          </Card>

          {/* ── Registration card ── */}
          <GroupCard name="Registration" fields={REG_FIELDS} cfg={cfg} set={set} />
        </div>

        <div style={styles.col}>
          <GroupCard name="Advanced" fields={ADV_FIELDS} cfg={cfg} set={set} />
          <GroupCard name="Post-Signup Stages" fields={POST_FIELDS} cfg={cfg} set={set} />
        </div>
      </div>

      <Card style={styles.saveBar}>
        <Button variant="primary" size="lg" onClick={save} disabled={busy}>
          <Save size={16} />
          {busy ? 'Saving...' : 'Save configuration'}
        </Button>
        {saved && (
          <span style={{ fontSize: 13, color: saved.startsWith('✓') ? 'var(--ok)' : 'var(--danger)' }}>{saved}</span>
        )}
      </Card>

      {zoneOpen && (
        <ZoneModal
          loading={zoneLoading} error={zoneError} data={zoneData}
          currentZone={cfg.litensi_zone ?? ''}
          onClose={() => setZoneOpen(false)} onUse={useZone} onRefresh={checkZones}
        />
      )}

      <style>{layoutCSS}</style>
    </div>
  )
}

/* ───────────────────── sub-components ───────────────────── */

function GroupCard({ name, fields, cfg, set }) {
  return (
    <Card style={styles.card}>
      <div style={styles.groupTitle}>{name}</div>
      <div style={styles.fieldsGrid} className="cfg-fields">
        {fields.map((f) => (
          <div key={f.key} style={f.wide ? styles.fieldWide : styles.fieldHalf}
            className={f.wide ? 'cfg-field-wide' : 'cfg-field-half'}>
            <Field f={f} value={cfg[f.key]} onChange={(v) => set(f.key, v)} />
          </div>
        ))}
      </div>
    </Card>
  )
}

function Field({ f, value, onChange, onCheckZones }) {
  if (f.type === 'checkbox') {
    return (
      <label style={{ ...styles.field, flexDirection: 'row', alignItems: 'center', gap: 10 }}>
        <Input
          type="checkbox" checked={!!value} onChange={(e) => onChange(e.target.checked)}
          style={{ width: 16, height: 16, accentColor: 'var(--accent)' }}
        />
        <span style={{ fontSize: 13, color: 'var(--text)' }}>{f.label}</span>
      </label>
    )
  }
  return (
    <label style={styles.field}>
      <span style={styles.label}>{f.label}</span>
      <div style={styles.inputRow}>
        <Input
          type={f.type === 'number' ? 'number' : 'text'}
          value={value ?? ''} onChange={(e) => onChange(e.target.value)}
          style={{ flex: 1, minWidth: 0 }}
        />
        {onCheckZones && <Button type="button" onClick={onCheckZones} title="Retrieve Litensi zones"><Search size={15} /> Zones</Button>}
      </div>
    </label>
  )
}

function ZoneModal({ loading, error, data, currentZone, onClose, onUse, onRefresh }) {
  const zones = (data?.zones || []).slice().sort((a, b) => {
    const sa = a.stock > 0 ? 0 : 1
    const sb = b.stock > 0 ? 0 : 1
    if (sa !== sb) return sa - sb
    return a.price - b.price
  })

  return (
    <div style={styles.modalBackdrop} onClick={onClose}>
      <div className="glass" style={styles.modal} onClick={(e) => e.stopPropagation()}>
        <div style={styles.modalHead}>
          <div>
            <div style={styles.modalTitle}>Litensi Zones</div>
            <div style={styles.modalSub}>
              {data?.site ? <>Site: <b style={{ color: 'var(--text)' }}>{data.site}</b></> : 'Available zones'}
            </div>
          </div>
          <button className="glass-btn" onClick={onClose} style={{ padding: '6px 12px' }}>✕</button>
        </div>

        <div style={styles.modalBody}>
          {loading && <div style={styles.center}>Loading zones...</div>}
          {!loading && error && (
            <div style={styles.errorBox}>
              <div style={{ color: 'var(--danger)', fontWeight: 600, marginBottom: 6 }}>⚠ Failed</div>
              <div style={{ fontSize: 12.5, color: 'var(--muted)', wordBreak: 'break-word' }}>{error}</div>
            </div>
          )}
          {!loading && !error && zones.length === 0 && (
            <div style={styles.center}>No zones available.</div>
          )}
          {!loading && !error && zones.length > 0 && (
            <>
              <div style={styles.legend}>
                <span>Total: <b>{zones.length}</b></span>
                <span style={{ color: 'var(--ok)' }}>Available: <b>{zones.filter((z) => z.stock > 0).length}</b></span>
                {data.cheapest && <span style={{ color: 'var(--accent)' }}>Cheapest: <b>{data.cheapest}</b></span>}
              </div>
              <div style={styles.tableWrap}>
                <table style={styles.table}>
                  <thead>
                    <tr>
                      <th style={styles.th}>Zone</th>
                      <th style={{ ...styles.th, textAlign: 'right' }}>Price</th>
                      <th style={{ ...styles.th, textAlign: 'right' }}>Stock</th>
                      <th style={styles.th}></th>
                    </tr>
                  </thead>
                  <tbody>
                    {zones.map((z) => {
                      const isCurrent = currentZone === z.zone
                      const isCheapest = data.cheapest === z.zone
                      const outOfStock = z.stock <= 0
                      return (
                        <tr key={z.zone} style={outOfStock ? { opacity: 0.5 } : undefined}>
                          <td style={styles.td}>
                            <div style={styles.zoneCell}>
                              <span style={{ fontWeight: 700 }}>{z.zone || '—'}</span>
                              {isCurrent && <span className="badge accent" style={styles.tag}>current</span>}
                              {isCheapest && !isCurrent && <span className="badge accent" style={styles.tag}>cheapest</span>}
                            </div>
                          </td>
                          <td style={{ ...styles.td, textAlign: 'right', fontVariantNumeric: 'tabular-nums' }}>
                            {formatPrice(z.price)}
                          </td>
                          <td style={{ ...styles.td, textAlign: 'right', fontVariantNumeric: 'tabular-nums' }}>
                            <span style={{ color: outOfStock ? 'var(--danger)' : 'var(--ok)', fontWeight: 600 }}>
                              {formatPrice(Math.round(z.stock))}
                            </span>
                          </td>
                          <td style={{ ...styles.td, textAlign: 'right' }}>
                            <button className="glass-btn" disabled={outOfStock} onClick={() => onUse(z.zone)}
                              style={{ padding: '6px 12px', fontSize: 12 }}>Use</button>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>

        <div style={styles.modalFoot}>
          <button className="glass-btn" onClick={onRefresh} disabled={loading}>⟳ Refresh</button>
          {!loading && !error && zones.length > 0 && (
            <button className="glass-btn primary" onClick={() => onUse('')} title="Clear zone, auto cheapest">
              Clear (automatic)
            </button>
          )}
          <div style={{ flex: 1 }} />
          <button className="glass-btn" onClick={onClose}>Close</button>
        </div>
      </div>
      <style>{modalCSS}</style>
    </div>
  )
}

function formatPrice(n) {
  if (!Number.isFinite(n)) return '—'
  try { return new Intl.NumberFormat('id-ID', { maximumFractionDigits: 0 }).format(n) }
  catch { return String(n) }
}

/* ───────────────────── styles ───────────────────── */

const styles = {
  wrap: { display: 'flex', flexDirection: 'column', gap: 14, maxWidth: 1200, width: '100%', margin: '0 auto' },
  columns: { display: 'grid', gridTemplateColumns: '1fr', gap: 14, alignItems: 'start' },
  col: { display: 'flex', flexDirection: 'column', gap: 14, minWidth: 0 },
  card: { padding: 22, minWidth: 0 },
  groupTitle: {
    fontSize: 11.5, fontWeight: 700, letterSpacing: 1.2, textTransform: 'uppercase',
    color: 'var(--accent)', marginBottom: 16,
  },
  fieldsGrid: { display: 'grid', gap: '14px 16px' },
  fieldHalf: { minWidth: 0 },
  fieldWide: { minWidth: 0 },
  field: { display: 'flex', flexDirection: 'column', gap: 7, fontSize: 13, color: 'var(--muted)' },
  label: { fontWeight: 500 },
  inputRow: { display: 'flex', gap: 8, alignItems: 'stretch', flexWrap: 'wrap' },
  select: {
    flex: 1, minWidth: 0, padding: '10px 12px', fontSize: 13,
    background: 'var(--bg-input)', color: 'var(--text)', border: '1px solid var(--border)',
    borderRadius: 8, outline: 'none', cursor: 'pointer',
  },
  saveBar: {
    padding: 18, display: 'flex', alignItems: 'center', gap: 14,
    position: 'sticky', bottom: 0, flexWrap: 'wrap', zIndex: 5,
  },
  providerRow: {
    display: 'flex', gap: 10, marginBottom: 18, flexWrap: 'wrap',
  },
  radioLabel: {
    display: 'flex', alignItems: 'center', gap: 8, padding: '10px 16px',
    borderRadius: 10, cursor: 'pointer',
    border: '1px solid var(--border)', background: 'var(--bg-input)',
    transition: 'all 0.15s ease', fontSize: 13.5,
  },
  radio: { accentColor: 'var(--accent)', width: 16, height: 16 },
  badge: {
    fontSize: 9.5, fontWeight: 700, padding: '2px 6px', borderRadius: 4,
    background: 'rgba(var(--ok-rgb), 0.15)', color: 'var(--ok)', marginLeft: 4,
  },
  badgePaid: {
    fontSize: 9.5, fontWeight: 700, padding: '2px 6px', borderRadius: 4,
    background: 'rgba(var(--accent-2-rgb), 0.15)', color: 'var(--accent)', marginLeft: 4,
  },
  // modal
  modalBackdrop: {
    position: 'fixed', inset: 0, zIndex: 100,
    background: 'rgba(0,0,0,0.55)', backdropFilter: 'blur(4px)',
    display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16,
    animation: 'fadeIn 0.2s ease',
  },
  modal: { width: '100%', maxWidth: 640, maxHeight: '85vh', display: 'flex', flexDirection: 'column', padding: 0, overflow: 'hidden' },
  modalHead: {
    padding: '18px 22px 14px', display: 'flex', justifyContent: 'space-between',
    alignItems: 'flex-start', gap: 12, borderBottom: '1px solid var(--glass-border)',
  },
  modalTitle: { fontSize: 17, fontWeight: 800, letterSpacing: -0.3 },
  modalSub: { fontSize: 12.5, color: 'var(--muted)', marginTop: 4 },
  modalBody: { padding: '16px 22px', overflow: 'auto', flex: 1 },
  modalFoot: {
    padding: '14px 22px', display: 'flex', gap: 10, flexWrap: 'wrap',
    borderTop: '1px solid var(--glass-border)', background: 'var(--bg-input)',
  },
  center: { textAlign: 'center', padding: '32px 12px', color: 'var(--muted)', fontSize: 13.5 },
  errorBox: {
    padding: '14px 16px', borderRadius: 12,
    background: 'rgba(var(--danger-rgb),0.09)', border: '1px solid rgba(var(--danger-rgb),0.3)',
  },
  legend: { display: 'flex', gap: 16, flexWrap: 'wrap', fontSize: 12.5, color: 'var(--muted)', marginBottom: 12 },
  tableWrap: { overflowX: 'auto', margin: '0 -4px' },
  table: { width: '100%', borderCollapse: 'collapse', fontSize: 13 },
  th: {
    textAlign: 'left', fontWeight: 700, fontSize: 11, color: 'var(--muted)',
    textTransform: 'uppercase', letterSpacing: 0.5, padding: '8px 10px',
    borderBottom: '1px solid var(--glass-border)', position: 'sticky', top: 0,
    background: 'rgba(23,33,43,0.97)',
  },
  td: { padding: '10px', borderBottom: '1px solid var(--border)', verticalAlign: 'middle' },
  zoneCell: { display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' },
  tag: { fontSize: 10, padding: '2px 8px' },
}

const layoutCSS = `
  @media (min-width: 1024px) { .cfg-columns { grid-template-columns: 1fr 1fr !important; } }
  @media (max-width: 1023px) { .cfg-columns { grid-template-columns: 1fr !important; } }
  @media (min-width: 560px) {
    .cfg-fields { grid-template-columns: 1fr 1fr; }
    .cfg-field-half { grid-column: span 1; }
    .cfg-field-wide { grid-column: 1 / -1; }
  }
  @media (max-width: 559px) {
    .cfg-fields { grid-template-columns: 1fr; }
    .cfg-field-half, .cfg-field-wide { grid-column: 1 / -1; }
  }
`

const modalCSS = `
  @keyframes fadeIn { from { opacity: 0 } to { opacity: 1 } }
  @media (max-width: 520px) { .glass-btn { font-size: 12px; } }
`
