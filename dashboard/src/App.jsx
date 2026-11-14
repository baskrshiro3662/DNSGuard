import { useMemo, useRef, useState } from 'react'
import {
  Shield, LayoutDashboard, Activity, AlertTriangle, FileText, Settings,
  Network, Database, ShieldAlert, Download, Search, Filter, Globe,
  Lock, RefreshCw, Eye, X, Save, SlidersHorizontal
} from 'lucide-react'
import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, PieChart, Pie, Cell, BarChart, Bar
} from 'recharts'
import './App.css'

const COLORS = {
  HIGH: '#a92e43',
  MEDIUM: '#c16b43',
  LOW: '#c9a84e'
}

const sampleCSV = `timestamp,sourceIp,domain,recordType,responseCode,riskScore,severity,reasons
2026-11-04T10:00:25Z,192.168.1.14,abcdefghijklmnopqrstuvwxyz1234567890.example.com,TXT,NOERROR,100,HIGH,"Unusually long domain; High entropy; TXT record"
2026-11-04T10:05:25Z,192.168.1.20,suspicious.example.com,TXT,NOERROR,85,HIGH,"TXT record; Repeated query"
2026-11-04T10:10:25Z,192.168.1.25,random123.example.com,A,NOERROR,55,MEDIUM,"High entropy; Repeated query"
2026-11-04T10:15:25Z,192.168.1.14,normal.example.com,A,NOERROR,20,LOW,"Normal query"
2026-11-04T10:20:25Z,192.168.1.30,longsubdomain.example.com,TXT,NOERROR,75,HIGH,"Long domain; TXT record"
2026-11-04T10:25:25Z,192.168.1.25,abcxyz.example.com,A,NOERROR,45,MEDIUM,"High entropy"
2026-11-04T10:30:25Z,192.168.1.40,normal2.example.com,A,NOERROR,10,LOW,"Normal query"
`

const navigation = [
  { label: 'Overview', icon: LayoutDashboard },
  { label: 'DNS Analytics', icon: Activity },
  { label: 'Threat Alerts', icon: AlertTriangle },
  { label: 'Reports', icon: FileText },
  { label: 'Configuration', icon: Settings }
]

function parseCSV(text) {
  const rows = []
  let row = []
  let field = ''
  let quoted = false

  for (let i = 0; i < text.length; i++) {
    const char = text[i]
    const next = text[i + 1]

    if (char === '"' && quoted && next === '"') {
      field += '"'
      i++
    } else if (char === '"') {
      quoted = !quoted
    } else if (char === ',' && !quoted) {
      row.push(field.trim())
      field = ''
    } else if ((char === '\n' || char === '\r') && !quoted) {
      if (char === '\r' && next === '\n') i++
      row.push(field.trim())
      if (row.some(value => value !== '')) rows.push(row)
      row = []
      field = ''
    } else {
      field += char
    }
  }

  row.push(field.trim())
  if (row.some(value => value !== '')) rows.push(row)
  if (!rows.length) return []

  const headers = rows[0].map(h => h.replace(/^\uFEFF/, '').trim())

  return rows.slice(1).map(values => {
    const record = {}
    headers.forEach((header, index) => {
      record[header] = values[index] ?? ''
    })
    return record
  })
}

function normalizeRecords(records) {
  return records.map(record => ({
    timestamp: record.timestamp || '',
    sourceIp: record.sourceIp || record.source_ip || '',
    domain: record.domain || '',
    recordType: record.recordType || record.record_type || '',
    responseCode: record.responseCode || record.response_code || '',
    riskScore: Number(record.riskScore || record.risk_score || 0),
    severity: String(record.severity || 'LOW').toUpperCase(),
    reasons: record.reasons || record.reason || ''
  }))
}

function formatTime(timestamp) {
  if (!timestamp) return 'Unknown'
  const date = new Date(timestamp)
  return Number.isNaN(date.getTime())
    ? timestamp
    : date.toLocaleString()
}

function App() {
  const [activePage, setActivePage] = useState('Overview')
  const [records, setRecords] = useState([])
  const [analysisSummary, setAnalysisSummary] = useState(null)
  const [message, setMessage] = useState('Import your DNSGuard CSV report or load sample data.')
  const [fileName, setFileName] = useState('')
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState('ALL')
  const [selectedRecord, setSelectedRecord] = useState(null)
  const [settings, setSettings] = useState({
    highThreshold: 70,
    mediumThreshold: 40,
    longDomainThreshold: 45,
    entropyThreshold: 4.0,
    repeatedQueryThreshold: 10,
    enableLongDomain: true,
    enableEntropy: true,
    enableTXT: true,
    enableRepeated: true
  })

  const fileRef = useRef(null)

  const metrics = useMemo(() => ({
    total: analysisSummary?.recordsAnalyzed ?? records.length,
    alerts: analysisSummary?.totalAlerts ?? records.filter(r => r.severity === 'HIGH' || r.severity === 'MEDIUM').length,
    high: analysisSummary?.high ?? records.filter(r => r.severity === 'HIGH').length,
    rules: 8
  }), [records, analysisSummary])

  const severityData = useMemo(() => [
    { name: 'High', value: analysisSummary?.high ?? records.filter(r => r.severity === 'HIGH').length, color: COLORS.HIGH },
    { name: 'Medium', value: analysisSummary?.medium ?? records.filter(r => r.severity === 'MEDIUM').length, color: COLORS.MEDIUM },
    { name: 'Low', value: analysisSummary?.low ?? records.filter(r => r.severity === 'LOW').length, color: COLORS.LOW }
  ].filter(item => item.value > 0), [records, analysisSummary])

  const activityData = useMemo(() => {
    const grouped = {}
    records.forEach((record, index) => {
      const label = record.timestamp
        ? record.timestamp.slice(11, 16) || `#${index + 1}`
        : `#${index + 1}`
      grouped[label] = (grouped[label] || 0) + 1
    })
    return Object.entries(grouped).map(([time, alerts]) => ({ time, alerts }))
  }, [records])

  const ruleData = useMemo(() => {
    const counts = {}
    records.forEach(record => {
      String(record.reasons).split(/[;]+/).forEach(reason => {
        const clean = reason.trim()
        if (clean) counts[clean] = (counts[clean] || 0) + 1
      })
    })
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 7)
      .map(([name, count]) => ({
        name: name.length > 30 ? `${name.slice(0, 27)}...` : name,
        count
      }))
  }, [records])

  const sourceData = useMemo(() => {
    const counts = {}
    records.forEach(record => {
      if (record.sourceIp) {
        counts[record.sourceIp] = (counts[record.sourceIp] || 0) + 1
      }
    })
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([ip, alerts]) => ({ ip, alerts }))
  }, [records])

  const recordTypes = useMemo(() => {
    const counts = {}
    records.forEach(r => {
      const type = r.recordType || 'Unknown'
      counts[type] = (counts[type] || 0) + 1
    })
    return Object.entries(counts)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count)
  }, [records])

  const responseCodes = useMemo(() => {
    const counts = {}
    records.forEach(r => {
      const code = r.responseCode || 'Unknown'
      counts[code] = (counts[code] || 0) + 1
    })
    return Object.entries(counts)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count)
  }, [records])

  const topDomains = useMemo(() => {
    const counts = {}
    records.forEach(r => {
      if (r.domain) counts[r.domain] = (counts[r.domain] || 0) + 1
    })
    return Object.entries(counts)
      .map(([domain, count]) => ({ domain, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8)
  }, [records])

  const averageRisk = records.length
    ? Math.round(records.reduce((sum, r) => sum + r.riskScore, 0) / records.length)
    : 0

  const filteredRecords = useMemo(() => {
    const term = search.toLowerCase().trim()
    return records.filter(record => {
      const matchesSeverity = severityFilter === 'ALL' || record.severity === severityFilter
      const matchesSearch = !term || [
        record.sourceIp, record.domain, record.recordType,
        record.responseCode, record.reasons, record.severity
      ].join(' ').toLowerCase().includes(term)
      return matchesSeverity && matchesSearch
    })
  }, [records, search, severityFilter])

  function loadSample() {
    const parsed = normalizeRecords(parseCSV(sampleCSV))
    setRecords(parsed)
    setAnalysisSummary(null)
    setFileName('Sample DNS alerts')
    setMessage(`Sample data loaded successfully: ${parsed.length} records.`)
    setSearch('')
    setSeverityFilter('ALL')
  }

  async function importCSV(event) {
    const file = event.target.files?.[0]
    if (!file) return

    setMessage(`Analyzing ${file.name} with DNSGuard engine...`)

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'text/csv' },
        body: file
      })

      const result = await response.json()

      if (!response.ok) {
        throw new Error(result.error || result.message || `API error: ${response.status}`)
      }

      if (!Array.isArray(result.alerts)) {
        throw new Error('Invalid response received from DNSGuard API.')
      }

      const parsed = normalizeRecords(result.alerts).map(record => ({
        ...record,
        reasons: Array.isArray(record.reasons)
          ? record.reasons.join('; ')
          : String(record.reasons || ''),
        ruleIds: record.ruleIds || []
      }))

      setRecords(parsed)
      setAnalysisSummary({
        recordsAnalyzed: Number(result.recordsAnalyzed) || 0,
        totalAlerts: Number(result.totalAlerts) || 0,
        high: Number(result.high) || 0,
        medium: Number(result.medium) || 0,
        low: Number(result.low) || 0
      })
      setFileName(file.name)
      setMessage(
        `DNSGuard analysis complete: ${result.recordsAnalyzed} records analyzed, ${result.totalAlerts} alerts detected.`
      )
      setSearch('')
      setSeverityFilter('ALL')
      setSelectedRecord(null)
    } catch (error) {
      setMessage(`Analysis failed: ${error.message}`)
    } finally {
      event.target.value = ''
    }
  }

  function exportCSV() {
    if (!records.length) {
      setMessage('Load sample data or import a CSV before exporting.')
      return
    }

    const headers = ['timestamp', 'sourceIp', 'domain', 'recordType', 'responseCode', 'riskScore', 'severity', 'reasons']
    const escape = value => `"${String(value ?? '').replace(/"/g, '""')}"`
    const csv = [
      headers.join(','),
      ...records.map(record => headers.map(header => escape(record[header])).join(','))
    ].join('\n')

    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }))
    const link = document.createElement('a')
    link.href = url
    link.download = 'dnsguard-report.csv'
    link.click()
    URL.revokeObjectURL(url)
  }

  function updateSetting(key, value) {
    setSettings(previous => ({ ...previous, [key]: value }))
  }

  const cards = [
    { title: 'Records analyzed', value: metrics.total, description: 'Rows in imported report', icon: Database },
    { title: 'Security alerts', value: metrics.alerts, description: 'All detected severity levels', icon: ShieldAlert },
    { title: 'High severity', value: metrics.high, description: 'Prioritize for investigation', icon: AlertTriangle },
    { title: 'Detection rules', value: metrics.rules, description: 'Configured DNS detection rules', icon: Shield }
  ]

  const tooltipStyle = {
    backgroundColor: '#160d10',
    border: '1px solid #57303a',
    borderRadius: '6px',
    color: '#eee5e6'
  }

  function Empty({ children = 'Import a CSV or load sample data to view results.' }) {
    return <div className="empty-chart">{children}</div>
  }

  function renderOverviewPage() {
    return (
      <>
        <div className="metrics-grid">
          {cards.map(({ title, value, description, icon: Icon }) => (
            <div className="metric-card" key={title}>
              <div className="metric-top">
                <span>{title}</span>
                <div className="metric-icon"><Icon size={15} /></div>
              </div>
              <div className="metric-value">{value}</div>
              <div className="metric-change">{description}</div>
            </div>
          ))}
        </div>

        <div className="charts-grid">
          <section className="panel">
            <div className="panel-heading">
              <div><h3>Alert activity</h3><p>Alerts grouped by timestamp</p></div>
              <span className="panel-tag">TIMELINE</span>
            </div>
            <div className="chart-area">
              {activityData.length ? (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={activityData}>
                    <defs>
                      <linearGradient id="alertFill" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#a92e43" stopOpacity={0.4} />
                        <stop offset="100%" stopColor="#a92e43" stopOpacity={0.02} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid stroke="#382129" strokeDasharray="3 4" vertical={false} />
                    <XAxis dataKey="time" tick={{ fill: '#a18e95', fontSize: 10 }} />
                    <YAxis allowDecimals={false} tick={{ fill: '#a18e95', fontSize: 10 }} />
                    <Tooltip contentStyle={tooltipStyle} cursor={false} />
                    <Area dataKey="alerts" name="Records" stroke="#b43b50" fill="url(#alertFill)" strokeWidth={2} />
                  </AreaChart>
                </ResponsiveContainer>
              ) : <Empty />}
            </div>
          </section>

          <section className="panel">
            <div className="panel-heading">
              <div><h3>Severity distribution</h3><p>Breakdown of imported alerts</p></div>
              <span className="panel-tag">SEVERITY</span>
            </div>
            <div className="severity-content">
              {severityData.length ? (
                <>
                  <div className="donut-wrap">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie data={severityData} dataKey="value" nameKey="name"
                          innerRadius="66%" outerRadius="90%" paddingAngle={2}
                          stroke="#130d0f" strokeWidth={2}>
                          {severityData.map(item => (
                            <Cell key={item.name} fill={item.color} stroke="#130d0f" strokeWidth={2} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={tooltipStyle} cursor={false} />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="legend">
                    {severityData.map(item => (
                      <div className="legend-item" key={item.name}>
                        <span className="legend-dot" style={{ background: item.color }} />
                        {item.name}<strong>{item.value}</strong>
                      </div>
                    ))}
                  </div>
                </>
              ) : <Empty>No severity data available</Empty>}
            </div>
          </section>
        </div>

        <div className="lower-grid">
          <section className="panel">
            <div className="panel-heading">
              <div><h3>Detection rule activity</h3><p>Alert counts by detection reason</p></div>
              <span className="panel-tag">RULES</span>
            </div>
            <div className="bar-chart">
              {ruleData.length ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={ruleData} layout="vertical" margin={{ left: 8, right: 15 }}>
                    <CartesianGrid stroke="#382129" strokeDasharray="3 4" horizontal={false} />
                    <XAxis type="number" allowDecimals={false} tick={{ fill: '#a18e95', fontSize: 9 }} />
                    <YAxis type="category" dataKey="name" width={125} tick={{ fill: '#cbb9bf', fontSize: 9 }} />
                    <Tooltip cursor={{ fill: '#29171d', opacity: 0.35 }} contentStyle={tooltipStyle} />
                    <Bar dataKey="count" fill="#a92e43" stroke="#a92e43" radius={[0, 3, 3, 0]} barSize={14} />
                  </BarChart>
                </ResponsiveContainer>
              ) : <Empty>No detection rule data available</Empty>}
            </div>
          </section>

          <section className="panel">
            <div className="panel-heading">
              <div><h3>Top source IPs</h3><p>Sources with the most alerts</p></div>
              <span className="panel-tag">SOURCES</span>
            </div>
            <div className="source-list">
              {sourceData.length ? sourceData.map(source => (
                <div className="source-row" key={source.ip}>
                  <div className="source-info"><Network size={14} /><strong>{source.ip}</strong></div>
                  <strong>{source.alerts}</strong>
                  <div className="source-bar">
                    <span style={{ width: `${source.alerts / sourceData[0].alerts * 100}%` }} />
                  </div>
                </div>
              )) : <Empty>No source IP data available</Empty>}
            </div>
            <button className="export-button" onClick={exportCSV}><Download size={14} /> Export report CSV</button>
          </section>
        </div>
      </>
    )
  }

  function renderAnalyticsPage() {
    return (
      <div className="page-stack">
        <div className="metrics-grid">
          <div className="metric-card"><div className="metric-top">Total DNS records analyzed <Globe size={16} /></div><div className="metric-value">{metrics.total}</div><div className="metric-change">Imported query records</div></div>
          <div className="metric-card"><div className="metric-top">Average risk score <Activity size={16} /></div><div className="metric-value">{averageRisk}<small>/100</small></div><div className="metric-change">Across imported records</div></div>
          <div className="metric-card"><div className="metric-top">Unique source IPs <Network size={16} /></div><div className="metric-value">{sourceData.length}</div><div className="metric-change">Distinct reporting sources</div></div>
          <div className="metric-card"><div className="metric-top">DNS record types <Database size={16} /></div><div className="metric-value">{recordTypes.length}</div><div className="metric-change">Types found in report</div></div>
        </div>

        <div className="charts-grid">
          <section className="panel">
            <div className="panel-heading"><div><h3>DNS query type distribution</h3><p>Records grouped by DNS type</p></div><span className="panel-tag">QUERY TYPES</span></div>
            <div className="bar-chart">
              {recordTypes.length ? <ResponsiveContainer width="100%" height="100%">
                <BarChart data={recordTypes}>
                  <CartesianGrid stroke="#382129" strokeDasharray="3 4" vertical={false} />
                  <XAxis dataKey="name" tick={{ fill: '#cbb9bf', fontSize: 10 }} />
                  <YAxis allowDecimals={false} tick={{ fill: '#a18e95', fontSize: 9 }} />
                  <Tooltip contentStyle={tooltipStyle} cursor={false} />
                  <Bar dataKey="count" fill="#a92e43" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer> : <Empty>No DNS query type data available</Empty>}
            </div>
          </section>

          <section className="panel">
            <div className="panel-heading"><div><h3>Response code distribution</h3><p>DNS resolver response codes</p></div><span className="panel-tag">RESPONSES</span></div>
            <div className="bar-chart">
              {responseCodes.length ? <ResponsiveContainer width="100%" height="100%">
                <BarChart data={responseCodes}>
                  <CartesianGrid stroke="#382129" strokeDasharray="3 4" vertical={false} />
                  <XAxis dataKey="name" tick={{ fill: '#cbb9bf', fontSize: 10 }} />
                  <YAxis allowDecimals={false} tick={{ fill: '#a18e95', fontSize: 9 }} />
                  <Tooltip contentStyle={tooltipStyle} cursor={false} />
                  <Bar dataKey="count" fill="#c16b43" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer> : <Empty>No response code data available</Empty>}
            </div>
          </section>
        </div>

        <section className="panel">
          <div className="panel-heading"><div><h3>Most queried domains</h3><p>Domains ranked by record count</p></div><span className="panel-tag">DOMAINS</span></div>
          {topDomains.length ? (
            <div className="data-table-wrap">
              <table className="data-table">
                <thead><tr><th>Domain</th><th>Query count</th><th>Share</th></tr></thead>
                <tbody>{topDomains.map(item => (
                  <tr key={item.domain}>
                    <td className="domain-cell">{item.domain}</td>
                    <td>{item.count}</td>
                    <td>{records.length ? Math.round(item.count / records.length * 100) : 0}%</td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          ) : <Empty>No domain data available</Empty>}
        </section>
      </div>
    )
  }

  function renderAlertsPage() {
    return (
      <section className="panel">
        <div className="panel-heading">
          <div><h3>Threat alert investigation</h3><p>Search and inspect imported DNS records</p></div>
          <span className="panel-tag">{filteredRecords.length} RESULTS</span>
        </div>
        <div className="table-toolbar">
          <div className="search-box"><Search size={15} /><input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search IP, domain, reason..." /></div>
          <div className="filter-box"><Filter size={15} /><select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}>
            <option value="ALL">All severities</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select></div>
        </div>
        {filteredRecords.length ? (
          <div className="data-table-wrap">
            <table className="data-table">
              <thead><tr><th>Severity</th><th>Risk</th><th>Source IP</th><th>Domain</th><th>Type</th><th>Timestamp</th><th>Details</th></tr></thead>
              <tbody>{filteredRecords.map((record, index) => (
                <tr key={`${record.timestamp}-${record.sourceIp}-${index}`}>
                  <td><span className={`severity-pill ${record.severity.toLowerCase()}`}>{record.severity}</span></td>
                  <td>{record.riskScore}</td>
                  <td>{record.sourceIp || '—'}</td>
                  <td className="domain-cell">{record.domain || '—'}</td>
                  <td>{record.recordType || '—'}</td>
                  <td>{formatTime(record.timestamp)}</td>
                  <td><button className="icon-button" title="View alert" onClick={() => setSelectedRecord(record)}><Eye size={15} /></button></td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        ) : <Empty>No matching alerts. Import a CSV or change the filters.</Empty>}
        {selectedRecord && (
          <div className="modal-backdrop" onClick={() => setSelectedRecord(null)}>
            <div className="detail-modal" onClick={e => e.stopPropagation()}>
              <div className="panel-heading"><h3>Alert details</h3><button className="icon-button" onClick={() => setSelectedRecord(null)}><X size={17} /></button></div>
              <div className="detail-grid">
                <div><label>Severity</label><strong>{selectedRecord.severity}</strong></div>
                <div><label>Risk score</label><strong>{selectedRecord.riskScore}/100</strong></div>
                <div><label>Source IP</label><strong>{selectedRecord.sourceIp || '—'}</strong></div>
                <div><label>DNS type</label><strong>{selectedRecord.recordType || '—'}</strong></div>
                <div className="detail-wide"><label>Domain</label><strong>{selectedRecord.domain || '—'}</strong></div>
                <div className="detail-wide"><label>Detection reasons</label><p>{selectedRecord.reasons || 'No reason supplied.'}</p></div>
                <div className="detail-wide"><label>Timestamp</label><strong>{formatTime(selectedRecord.timestamp)}</strong></div>
              </div>
            </div>
          </div>
        )}
      </section>
    )
  }

  function renderReportsPage() {
    return (
      <div className="page-stack">
        <section className="panel">
          <div className="panel-heading">
            <div><h3>DNSGuard report center</h3><p>Summary of the currently imported report</p></div>
            <button className="primary-button" onClick={exportCSV}><Download size={14} /> Export CSV</button>
          </div>
          <div className="report-summary">
            <div><span>Report source</span><strong>{fileName || 'No report loaded'}</strong></div>
            <div><span>Records analyzed</span><strong>{metrics.total}</strong></div>
            <div><span>Security alerts</span><strong>{metrics.alerts}</strong></div>
            <div><span>Average risk</span><strong>{averageRisk}/100</strong></div>
          </div>
        </section>

        <section className="panel">
          <div className="panel-heading"><div><h3>Severity summary</h3><p>Record distribution by severity</p></div><span className="panel-tag">REPORT SUMMARY</span></div>
          {severityData.length ? (
            <div className="report-severity">
              {['HIGH', 'MEDIUM', 'LOW'].map(level => {
                const count = level === 'HIGH'
                  ? (analysisSummary?.high ?? records.filter(r => r.severity === level).length)
                  : level === 'MEDIUM'
                    ? (analysisSummary?.medium ?? records.filter(r => r.severity === level).length)
                    : (analysisSummary?.low ?? records.filter(r => r.severity === level).length)
                const percent = metrics.alerts ? Math.round(count / metrics.alerts * 100) : 0
                return <div className="report-severity-row" key={level}>
                  <div><span className={`severity-pill ${level.toLowerCase()}`}>{level}</span><strong>{count} records</strong><span>{percent}%</span></div>
                  <div className="source-bar"><span style={{ width: `${percent}%`, background: COLORS[level] }} /></div>
                </div>
              })}
            </div>
          ) : <Empty>No report data available.</Empty>}
        </section>

        <section className="panel">
          <div className="panel-heading"><div><h3>Report actions</h3><p>Export the currently loaded DNSGuard records</p></div></div>
          <div className="report-actions">
            <button className="secondary-button" onClick={exportCSV}><Download size={15} /> Download CSV report</button>
            <button className="secondary-button" onClick={() => { setActivePage('Threat Alerts'); setSearch(''); setSeverityFilter('ALL') }}><Eye size={15} /> Review all alerts</button>
          </div>
        </section>
      </div>
    )
  }

  function renderConfigurationPage() {
    const toggle = (key, label, description) => (
      <div className="setting-row" key={key}>
        <div><strong>{label}</strong><p>{description}</p></div>
        <label className="switch">
          <input type="checkbox" checked={settings[key]} onChange={e => updateSetting(key, e.target.checked)} />
          <span />
        </label>
      </div>
    )

    const numberSetting = (key, label, description, min, max, step = 1) => (
      <label className="number-setting" key={key}>
        <span><strong>{label}</strong><small>{description}</small></span>
        <input type="number" min={min} max={max} step={step} value={settings[key]}
          onChange={e => updateSetting(key, Number(e.target.value))} />
      </label>
    )

    return (
      <div className="page-stack">
        <section className="panel">
          <div className="panel-heading"><div><h3><SlidersHorizontal size={16} /> Dashboard detection settings</h3><p>Local interface settings for reference and planning</p></div><span className="panel-tag">LOCAL SETTINGS</span></div>
          <div className="settings-list">
            {numberSetting('highThreshold', 'High severity threshold', 'Risk score used for high severity', 1, 100)}
            {numberSetting('mediumThreshold', 'Medium severity threshold', 'Risk score used for medium severity', 1, 100)}
            {numberSetting('longDomainThreshold', 'Long domain threshold', 'Domain length threshold in characters', 1, 253)}
            {numberSetting('entropyThreshold', 'Entropy threshold', 'Entropy threshold in bits per character', 0, 8, 0.1)}
            {numberSetting('repeatedQueryThreshold', 'Repeated query threshold', 'Repeated query count threshold', 1, 1000)}
          </div>
        </section>

        <section className="panel">
          <div className="panel-heading"><div><h3>Detection rule visibility</h3><p>Enable or disable rule indicators in this dashboard configuration</p></div><span className="panel-tag">RULE CONTROLS</span></div>
          <div className="settings-list">
            {toggle('enableLongDomain', 'Long domain detection', 'Display long-domain rule as enabled')}
            {toggle('enableEntropy', 'High entropy detection', 'Display entropy rule as enabled')}
            {toggle('enableTXT', 'Unusual TXT record detection', 'Display TXT rule as enabled')}
            {toggle('enableRepeated', 'Repeated query detection', 'Display repeated-query rule as enabled')}
          </div>
        </section>

        <div className="notice">
          <Lock size={14} /> These settings are saved only in the current dashboard session. They do not change DNSGuard v1.0.0 Java detection thresholds or its source code.
        </div>
        <div className="report-actions">
          <button className="secondary-button" onClick={() => setSettings({
            highThreshold: 70, mediumThreshold: 40, longDomainThreshold: 45,
            entropyThreshold: 4, repeatedQueryThreshold: 10,
            enableLongDomain: true, enableEntropy: true, enableTXT: true, enableRepeated: true
          })}><RefreshCw size={14} /> Reset settings</button>
          <span className="settings-status"><Save size={14} /> Changes applied to dashboard session</span>
        </div>
      </div>
    )
  }

  const pageDescriptions = {
    Overview: 'Monitor DNS activity, suspicious patterns, and detection results.',
    'DNS Analytics': 'Explore DNS query types, domains, sources, and response codes.',
    'Threat Alerts': 'Search, filter, and investigate suspicious DNS records.',
    Reports: 'Review report summaries and export your DNSGuard results.',
    Configuration: 'Adjust local dashboard settings and rule visibility.'
  }

  return (
    <div className="dashboard">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon"><Shield size={21} /></div>
          <div><h2>DNSGuard</h2><span>THREAT INTELLIGENCE</span></div>
        </div>

        <div className="nav-label">WORKSPACE</div>
        <nav className="navigation">
          {navigation.map(({ label, icon: Icon }) => (
            <button key={label} className={`nav-item ${activePage === label ? 'active' : ''}`}
              onClick={() => setActivePage(label)}>
              <Icon size={15} /><span>{label}</span>
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="version">DNSGuard v1.0.0<br />Java detection engine<br /><span>● Local dashboard</span></div>
        </div>
      </aside>

      <main className="main-content">
        <section className="page-content">
          <header className="page-heading">
            <div>
              <div className="eyebrow">SECURITY OPERATIONS CENTER</div>
              <h1>{activePage === 'Overview' ? 'Threat Overview' : activePage}</h1>
              <p>{pageDescriptions[activePage]}</p>
            </div>
            <div className="heading-actions">
              <span className="connection"><span className="status-dot" /> Dashboard ready</span>
              <button className="secondary-button" onClick={loadSample}>Load sample</button>
              <button className="primary-button" onClick={() => fileRef.current?.click()}>
                + Import alert CSV
              </button>
              <input ref={fileRef} type="file" accept=".csv,text/csv" hidden onChange={importCSV} />
            </div>
          </header>

          <div className="notice">{message}{fileName && <span> · {fileName}</span>}</div>

          {activePage === 'Overview' && renderOverviewPage()}
          {activePage === 'DNS Analytics' && renderAnalyticsPage()}
          {activePage === 'Threat Alerts' && renderAlertsPage()}
          {activePage === 'Reports' && renderReportsPage()}
          {activePage === 'Configuration' && renderConfigurationPage()}

          <footer className="dashboard-footer">
            <span>DNSGuard v1.0.0 · DNS Exfiltration Detection</span>
            <span>{records.length} alerts displayed</span>
          </footer>
        </section>
      </main>
    </div>
  )
}

export default App