/**
 * NETRA – Network Event & Threat Response Analyst
 * Frontend Client Logic v1.0.0
 * Developed by MintFire
 */

// ─── Socket.IO Connection ──────────────────────────────────────────
const socket = io();

// ─── CSRF Token ────────────────────────────────────────────────────
const CSRF_TOKEN = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';

// ─── Data Stores ────────────────────────────────────────────────────
const MAX_HISTORY = 30;
const cpuHistory = [];
const memHistory = [];
const netSentHistory = [];
const netRecvHistory = [];
const packetSentHistory = [];
const packetRecvHistory = [];
const timeLabels = [];

// ─── Chart.js Global Config ────────────────────────────────────────
Chart.defaults.color = '#5a6a85';
Chart.defaults.borderColor = 'rgba(0, 240, 255, 0.06)';
Chart.defaults.font.family = "'JetBrains Mono', monospace";
Chart.defaults.font.size = 11;
Chart.defaults.plugins.legend.labels.usePointStyle = true;
Chart.defaults.plugins.legend.labels.pointStyleWidth = 10;
Chart.defaults.animation.duration = 600;

const CHART_COLORS = {
    cyan: '#00f0ff',
    cyanDim: 'rgba(0, 240, 255, 0.1)',
    green: '#00ff88',
    greenDim: 'rgba(0, 255, 136, 0.1)',
    red: '#ff3366',
    redDim: 'rgba(255, 51, 102, 0.1)',
    yellow: '#ffaa00',
    yellowDim: 'rgba(255, 170, 0, 0.1)',
    purple: '#a855f7',
    purpleDim: 'rgba(168, 85, 247, 0.1)',
    orange: '#ff6600',
};

function gradientFill(ctx, colorTop, colorBot) {
    const g = ctx.createLinearGradient(0, 0, 0, 250);
    g.addColorStop(0, colorTop);
    g.addColorStop(1, colorBot);
    return g;
}

// ─── Chart Instances ───────────────────────────────────────────────
let cpuChart, memChart, netChart, diskChart;
let bandwidthChart, packetChart, trafficDistChart;
let topCpuChart, topMemChart;
let cpuCoreChart, memBreakdownChart, swapChart;
let connTypeChart, connStatusChart;

function initCharts() {
    // CPU History
    const cpuCtx = document.getElementById('cpuChart')?.getContext('2d');
    if (cpuCtx) {
        cpuChart = new Chart(cpuCtx, {
            type: 'line',
            data: {
                labels: timeLabels,
                datasets: [{
                    label: 'CPU %',
                    data: cpuHistory,
                    borderColor: CHART_COLORS.cyan,
                    backgroundColor: gradientFill(cpuCtx, 'rgba(0, 240, 255, 0.15)', 'rgba(0, 240, 255, 0)'),
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { min: 0, max: 100, ticks: { callback: v => v + '%' } },
                    x: { display: false }
                },
                plugins: { legend: { display: false } }
            }
        });
    }

    // Memory History
    const memCtx = document.getElementById('memChart')?.getContext('2d');
    if (memCtx) {
        memChart = new Chart(memCtx, {
            type: 'line',
            data: {
                labels: timeLabels,
                datasets: [{
                    label: 'Memory %',
                    data: memHistory,
                    borderColor: CHART_COLORS.green,
                    backgroundColor: gradientFill(memCtx, 'rgba(0, 255, 136, 0.15)', 'rgba(0, 255, 136, 0)'),
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { min: 0, max: 100, ticks: { callback: v => v + '%' } },
                    x: { display: false }
                },
                plugins: { legend: { display: false } }
            }
        });
    }

    // Network Throughput
    const netCtx = document.getElementById('netChart')?.getContext('2d');
    if (netCtx) {
        netChart = new Chart(netCtx, {
            type: 'line',
            data: {
                labels: timeLabels,
                datasets: [
                    {
                        label: '↑ Sent',
                        data: netSentHistory,
                        borderColor: CHART_COLORS.cyan,
                        backgroundColor: 'transparent',
                        borderWidth: 2,
                        tension: 0.4,
                        pointRadius: 0,
                    },
                    {
                        label: '↓ Received',
                        data: netRecvHistory,
                        borderColor: CHART_COLORS.green,
                        backgroundColor: 'transparent',
                        borderWidth: 2,
                        tension: 0.4,
                        pointRadius: 0,
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { min: 0, ticks: { callback: v => formatBytes(v) + '/s' } },
                    x: { display: false }
                },
                plugins: { legend: { position: 'top' } }
            }
        });
    }

    // Disk Doughnut
    const diskCtx = document.getElementById('diskChart')?.getContext('2d');
    if (diskCtx) {
        diskChart = new Chart(diskCtx, {
            type: 'doughnut',
            data: {
                labels: ['Used', 'Free'],
                datasets: [{
                    data: [0, 100],
                    backgroundColor: [CHART_COLORS.yellow, 'rgba(255, 255, 255, 0.05)'],
                    borderColor: ['rgba(255, 170, 0, 0.3)', 'rgba(255, 255, 255, 0.02)'],
                    borderWidth: 1,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '72%',
                plugins: {
                    legend: { display: true, position: 'bottom' },
                }
            }
        });
    }

    // Bandwidth
    const bwCtx = document.getElementById('bandwidthChart')?.getContext('2d');
    if (bwCtx) {
        bandwidthChart = new Chart(bwCtx, {
            type: 'line',
            data: {
                labels: timeLabels,
                datasets: [
                    {
                        label: '↑ Upload',
                        data: netSentHistory,
                        borderColor: CHART_COLORS.orange,
                        backgroundColor: gradientFill(bwCtx, 'rgba(255, 102, 0, 0.12)', 'rgba(255, 102, 0, 0)'),
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4,
                        pointRadius: 0,
                    },
                    {
                        label: '↓ Download',
                        data: netRecvHistory,
                        borderColor: CHART_COLORS.purple,
                        backgroundColor: gradientFill(bwCtx, 'rgba(168, 85, 247, 0.12)', 'rgba(168, 85, 247, 0)'),
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4,
                        pointRadius: 0,
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { min: 0, ticks: { callback: v => formatBytes(v) + '/s' } },
                    x: { display: false }
                },
                plugins: { legend: { position: 'top' } }
            }
        });
    }

    // Packet Flow
    const pktCtx = document.getElementById('packetChart')?.getContext('2d');
    if (pktCtx) {
        packetChart = new Chart(pktCtx, {
            type: 'bar',
            data: {
                labels: timeLabels,
                datasets: [
                    {
                        label: 'Packets Out',
                        data: packetSentHistory,
                        backgroundColor: CHART_COLORS.cyanDim,
                        borderColor: CHART_COLORS.cyan,
                        borderWidth: 1,
                    },
                    {
                        label: 'Packets In',
                        data: packetRecvHistory,
                        backgroundColor: CHART_COLORS.greenDim,
                        borderColor: CHART_COLORS.green,
                        borderWidth: 1,
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { min: 0 },
                    x: { display: false }
                },
                plugins: { legend: { position: 'top' } }
            }
        });
    }

    // Traffic Distribution
    const tdCtx = document.getElementById('trafficDistChart')?.getContext('2d');
    if (tdCtx) {
        trafficDistChart = new Chart(tdCtx, {
            type: 'doughnut',
            data: {
                labels: ['Sent', 'Received', 'Errors', 'Drops'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: [CHART_COLORS.cyan, CHART_COLORS.green, CHART_COLORS.red, CHART_COLORS.yellow],
                    borderWidth: 0,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '65%',
                plugins: { legend: { position: 'bottom' } }
            }
        });
    }

    // Top CPU Bar
    const tcCtx = document.getElementById('topCpuChart')?.getContext('2d');
    if (tcCtx) {
        topCpuChart = new Chart(tcCtx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'CPU %',
                    data: [],
                    backgroundColor: CHART_COLORS.cyanDim,
                    borderColor: CHART_COLORS.cyan,
                    borderWidth: 1,
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                scales: { x: { min: 0 } },
                plugins: { legend: { display: false } }
            }
        });
    }

    // Top Mem Bar
    const tmCtx = document.getElementById('topMemChart')?.getContext('2d');
    if (tmCtx) {
        topMemChart = new Chart(tmCtx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Memory %',
                    data: [],
                    backgroundColor: CHART_COLORS.greenDim,
                    borderColor: CHART_COLORS.green,
                    borderWidth: 1,
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                scales: { x: { min: 0 } },
                plugins: { legend: { display: false } }
            }
        });
    }

    // CPU Core Chart
    const ccCtx = document.getElementById('cpuCoreChart')?.getContext('2d');
    if (ccCtx) {
        cpuCoreChart = new Chart(ccCtx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Core Usage %',
                    data: [],
                    backgroundColor: [],
                    borderWidth: 0,
                    borderRadius: 4,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { min: 0, max: 100, ticks: { callback: v => v + '%' } }
                },
                plugins: { legend: { display: false } }
            }
        });
    }

    // Memory Breakdown
    const mbCtx = document.getElementById('memBreakdownChart')?.getContext('2d');
    if (mbCtx) {
        memBreakdownChart = new Chart(mbCtx, {
            type: 'doughnut',
            data: {
                labels: ['Used', 'Available'],
                datasets: [{
                    data: [0, 100],
                    backgroundColor: [CHART_COLORS.green, 'rgba(255, 255, 255, 0.05)'],
                    borderWidth: 0,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '70%',
                plugins: { legend: { position: 'bottom' } }
            }
        });
    }

    // Swap
    const swCtx = document.getElementById('swapChart')?.getContext('2d');
    if (swCtx) {
        swapChart = new Chart(swCtx, {
            type: 'doughnut',
            data: {
                labels: ['Used', 'Free'],
                datasets: [{
                    data: [0, 100],
                    backgroundColor: [CHART_COLORS.purple, 'rgba(255, 255, 255, 0.05)'],
                    borderWidth: 0,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '70%',
                plugins: { legend: { position: 'bottom' } }
            }
        });
    }

    // Connection Type
    const ctCtx = document.getElementById('connTypeChart')?.getContext('2d');
    if (ctCtx) {
        connTypeChart = new Chart(ctCtx, {
            type: 'doughnut',
            data: {
                labels: ['TCP', 'UDP'],
                datasets: [{
                    data: [0, 0],
                    backgroundColor: [CHART_COLORS.cyan, CHART_COLORS.orange],
                    borderWidth: 0,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '70%',
                plugins: { legend: { position: 'bottom' } }
            }
        });
    }

    // Connection Status
    const csCtx = document.getElementById('connStatusChart')?.getContext('2d');
    if (csCtx) {
        connStatusChart = new Chart(csCtx, {
            type: 'doughnut',
            data: {
                labels: ['Established', 'Listening', 'Other'],
                datasets: [{
                    data: [0, 0, 0],
                    backgroundColor: [CHART_COLORS.green, CHART_COLORS.yellow, CHART_COLORS.purple],
                    borderWidth: 0,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '70%',
                plugins: { legend: { position: 'bottom' } }
            }
        });
    }
}

// ─── Utility Functions ──────────────────────────────────────────────
function formatBytes(bytes, decimals = 1) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(Math.abs(bytes)) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(decimals)) + ' ' + sizes[i];
}

function formatNumber(num) {
    if (num >= 1e9) return (num / 1e9).toFixed(1) + 'B';
    if (num >= 1e6) return (num / 1e6).toFixed(1) + 'M';
    if (num >= 1e3) return (num / 1e3).toFixed(1) + 'K';
    return num.toString();
}

function getTimeLabel() {
    const now = new Date();
    return now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function getStatusBadge(status) {
    const s = (status || '').toLowerCase();
    if (s === 'running') return '<span class="badge badge-running">running</span>';
    if (s === 'sleeping') return '<span class="badge badge-sleeping">sleeping</span>';
    if (s === 'zombie') return '<span class="badge badge-zombie">zombie</span>';
    if (s === 'established') return '<span class="badge badge-established">established</span>';
    if (s === 'listen') return '<span class="badge badge-listen">listen</span>';
    return `<span class="badge badge-other">${status}</span>`;
}

function getInterfaceBadge(type) {
    const colors = {
        'WiFi': 'badge-running', 'Ethernet': 'badge-established',
        'Bluetooth': 'badge-listen', 'Loopback': 'badge-other',
        'VPN': 'badge-sleeping', 'Docker': 'badge-zombie',
    };
    return `<span class="badge ${colors[type] || 'badge-other'}">${type}</span>`;
}

// ─── Real-time SocketIO Updates ─────────────────────────────────────
socket.on('system_metrics', (data) => {
    const time = getTimeLabel();

    // Push to histories
    cpuHistory.push(data.cpu);
    memHistory.push(data.memory_percent);
    netSentHistory.push(data.net_sent_rate);
    netRecvHistory.push(data.net_recv_rate);
    packetSentHistory.push(data.packets_sent_rate);
    packetRecvHistory.push(data.packets_recv_rate);
    timeLabels.push(time);

    // Trim
    if (cpuHistory.length > MAX_HISTORY) {
        cpuHistory.shift(); memHistory.shift();
        netSentHistory.shift(); netRecvHistory.shift();
        packetSentHistory.shift(); packetRecvHistory.shift();
        timeLabels.shift();
    }

    // Update stat cards
    updateEl('stat-cpu', data.cpu.toFixed(1) + '%');
    updateEl('stat-ram', data.memory_percent.toFixed(1) + '%');
    updateEl('stat-disk', data.disk_percent.toFixed(1) + '%');
    updateEl('stat-net', formatBytes(data.net_recv_rate) + '/s');

    // Stat bars
    setBarWidth('stat-cpu-bar', data.cpu);
    setBarWidth('stat-ram-bar', data.memory_percent);
    setBarWidth('stat-disk-bar', data.disk_percent);

    // Net bar (normalize to a rough max of ~10MB/s)
    const netPercent = Math.min((data.net_recv_rate / (10 * 1024 * 1024)) * 100, 100);
    setBarWidth('stat-net-bar', netPercent);

    // Update charts
    if (cpuChart) cpuChart.update('none');
    if (memChart) memChart.update('none');
    if (netChart) netChart.update('none');
    if (bandwidthChart) bandwidthChart.update('none');
    if (packetChart) packetChart.update('none');

    // Disk chart
    if (diskChart) {
        diskChart.data.datasets[0].data = [data.disk_used, data.disk_total - data.disk_used];
        diskChart.data.labels = [`Used (${formatBytes(data.disk_used)})`, `Free (${formatBytes(data.disk_total - data.disk_used)})`];
        diskChart.update('none');
    }

    // CPU per core
    if (cpuCoreChart && data.cpu_per_core) {
        cpuCoreChart.data.labels = data.cpu_per_core.map((_, i) => `Core ${i}`);
        cpuCoreChart.data.datasets[0].data = data.cpu_per_core;
        cpuCoreChart.data.datasets[0].backgroundColor = data.cpu_per_core.map(v =>
            v > 80 ? CHART_COLORS.red : v > 50 ? CHART_COLORS.yellow : CHART_COLORS.cyan
        );
        cpuCoreChart.update('none');
    }

    // Memory breakdown
    if (memBreakdownChart) {
        const used = data.memory_used;
        const avail = data.memory_total - data.memory_used;
        memBreakdownChart.data.datasets[0].data = [used, avail];
        memBreakdownChart.data.labels = [`Used (${formatBytes(used)})`, `Available (${formatBytes(avail)})`];
        memBreakdownChart.update('none');
    }

    // Battery
    if (data.battery) {
        const bc = document.getElementById('batteryCard');
        if (bc) bc.style.display = 'block';
        updateEl('battery-percent', data.battery.percent + '%');
        const statusIcon = data.battery.plugged
            ? '<i class="fa-solid fa-plug"></i> Plugged In'
            : '<i class="fa-solid fa-battery-half"></i> On Battery';
        const statusEl = document.getElementById('battery-status');
        if (statusEl) statusEl.innerHTML = statusIcon;
        const secs = data.battery.secs_left;
        updateEl('battery-time', secs > 0 ? Math.floor(secs / 3600) + 'h ' + Math.floor((secs % 3600) / 60) + 'm' : '–');
    }

    // Network panel stats
    updateEl('net-total-sent', formatBytes(data.net_sent_total));
    updateEl('net-total-recv', formatBytes(data.net_recv_total));
});

function updateEl(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
}

function setBarWidth(id, pct) {
    const el = document.getElementById(id);
    if (el) el.style.width = Math.min(pct, 100) + '%';
}

// ─── API Data Loaders ──────────────────────────────────────────────

async function loadSystemData() {
    try {
        const res = await fetch('/api/system');
        const data = await res.json();

        updateEl('info-hostname', data.hostname);
        updateEl('info-os', data.os);
        updateEl('info-arch', data.architecture);
        updateEl('info-cores', `${data.cpu.count} Physical / ${data.cpu.count_logical} Logical`);
        updateEl('info-freq', data.cpu.freq_current ? data.cpu.freq_current.toFixed(0) + ' MHz' : 'N/A');
        updateEl('info-uptime', data.uptime);
        updateEl('info-boot', new Date(data.boot_time).toLocaleString());
        updateEl('info-python', data.python);

        // Swap chart
        if (swapChart && data.swap) {
            swapChart.data.datasets[0].data = [data.swap.used, data.swap.free];
            swapChart.data.labels = [`Used (${formatBytes(data.swap.used)})`, `Free (${formatBytes(data.swap.free)})`];
            swapChart.update();
        }

        // Partitions table
        const tbody = document.getElementById('partitionsBody');
        if (tbody && data.disk.partitions) {
            tbody.innerHTML = data.disk.partitions.map(p => `
                <tr>
                    <td>${p.device}</td>
                    <td>${p.mountpoint}</td>
                    <td>${p.fstype}</td>
                    <td>${formatBytes(p.total)}</td>
                    <td>${formatBytes(p.used)}</td>
                    <td>${formatBytes(p.free)}</td>
                    <td>
                        <div style="display:flex;align-items:center;gap:8px">
                            <div class="stat-bar" style="width:80px"><div class="stat-bar-fill" style="width:${p.percent}%;background:${p.percent > 85 ? CHART_COLORS.red : CHART_COLORS.cyan}"></div></div>
                            <span>${p.percent}%</span>
                        </div>
                    </td>
                </tr>
            `).join('');
        }
    } catch (e) {
        console.error('System data error:', e);
    }
}

async function loadNetworkData() {
    try {
        const res = await fetch('/api/network');
        const data = await res.json();

        updateEl('net-total-sent', formatBytes(data.total_io.bytes_sent));
        updateEl('net-total-recv', formatBytes(data.total_io.bytes_recv));
        updateEl('net-packets-sent', formatNumber(data.total_io.packets_sent));
        updateEl('net-packets-recv', formatNumber(data.total_io.packets_recv));

        const tbody = document.getElementById('interfacesBody');
        if (tbody) {
            tbody.innerHTML = data.interfaces.map(iface => {
                const ipv4 = iface.addresses.find(a => a.type === 'IPv4');
                const mac = iface.addresses.find(a => a.type === 'MAC');
                return `
                    <tr>
                        <td><strong>${iface.name}</strong></td>
                        <td>${getInterfaceBadge(iface.type)}</td>
                        <td>${iface.is_up ? '<span class="badge badge-up">UP</span>' : '<span class="badge badge-down">DOWN</span>'}</td>
                        <td>${ipv4 ? ipv4.address : '–'}</td>
                        <td style="font-size:0.68rem;color:var(--text-dim)">${mac ? mac.address : '–'}</td>
                        <td>${iface.speed ? iface.speed + ' Mbps' : '–'}</td>
                        <td>${formatBytes(iface.bytes_sent)}</td>
                        <td>${formatBytes(iface.bytes_recv)}</td>
                    </tr>
                `;
            }).join('');
        }
    } catch (e) {
        console.error('Network data error:', e);
    }
}

async function loadFirewallData() {
    try {
        const res = await fetch('/api/firewall');
        const data = await res.json();

        updateEl('fw-status', data.status);
        updateEl('fw-packets-out', formatNumber(data.packets.sent));
        updateEl('fw-packets-in', formatNumber(data.packets.recv));
        updateEl('fw-errors', formatNumber(data.packets.errors_in + data.packets.errors_out + data.packets.drop_in + data.packets.drop_out));

        // Traffic distribution chart
        if (trafficDistChart) {
            trafficDistChart.data.datasets[0].data = [
                data.bytes.sent, data.bytes.recv,
                data.packets.errors_in + data.packets.errors_out,
                data.packets.drop_in + data.packets.drop_out
            ];
            trafficDistChart.update();
        }

        // Firewall rules table
        const tbody = document.getElementById('firewallBody');
        if (tbody) {
            if (data.rules.length === 0) {
                tbody.innerHTML = '<tr><td colspan="3" style="text-align:center;color:var(--text-dim);padding:30px">No firewall rules found or insufficient privileges</td></tr>';
            } else {
                tbody.innerHTML = data.rules.map((r, i) => `
                    <tr>
                        <td>${i + 1}</td>
                        <td><span class="badge badge-other">${r.type}</span></td>
                        <td style="white-space:normal;word-break:break-all;max-width:none">${r.rule}</td>
                    </tr>
                `).join('');
            }
        }
    } catch (e) {
        console.error('Firewall data error:', e);
    }
}

async function loadServicesData() {
    try {
        const res = await fetch('/api/services');
        const data = await res.json();

        updateEl('srv-total', data.total_count);
        updateEl('srv-running', data.running);
        updateEl('srv-sleeping', data.sleeping);
        updateEl('srv-zombie', data.zombie);

        // Top CPU chart
        if (topCpuChart) {
            const top = data.services.filter(s => s.cpu > 0).slice(0, 8);
            topCpuChart.data.labels = top.map(s => s.name.substring(0, 18));
            topCpuChart.data.datasets[0].data = top.map(s => s.cpu);
            topCpuChart.update();
        }

        // Top Memory chart
        if (topMemChart) {
            const top = [...data.services].sort((a, b) => b.memory - a.memory).slice(0, 8);
            topMemChart.data.labels = top.map(s => s.name.substring(0, 18));
            topMemChart.data.datasets[0].data = top.map(s => s.memory);
            topMemChart.update();
        }

        // Services table
        const tbody = document.getElementById('servicesBody');
        if (tbody) {
            const search = (document.getElementById('serviceSearch')?.value || '').toLowerCase();
            const filtered = search ? data.services.filter(s => s.name.toLowerCase().includes(search) || String(s.pid).includes(search)) : data.services;

            tbody.innerHTML = filtered.slice(0, 100).map(s => `
                <tr>
                    <td>${s.pid}</td>
                    <td><strong>${s.name}</strong></td>
                    <td>${getStatusBadge(s.status)}</td>
                    <td style="color:${s.cpu > 50 ? CHART_COLORS.red : s.cpu > 20 ? CHART_COLORS.yellow : CHART_COLORS.cyan}">${s.cpu}%</td>
                    <td style="color:${s.memory > 10 ? CHART_COLORS.red : s.memory > 5 ? CHART_COLORS.yellow : CHART_COLORS.green}">${s.memory}%</td>
                    <td style="color:var(--text-dim)">${s.user}</td>
                    <td style="color:var(--text-dim)">${s.started}</td>
                </tr>
            `).join('');
        }
    } catch (e) {
        console.error('Services data error:', e);
    }
}

async function loadConnectionsData() {
    try {
        const res = await fetch('/api/connections');
        const data = await res.json();

        updateEl('conn-total', data.total);
        updateEl('conn-established', data.established);
        updateEl('conn-listening', data.listening);
        updateEl('conn-protocol', `${data.tcp} / ${data.udp}`);

        // Connection type chart
        if (connTypeChart) {
            connTypeChart.data.datasets[0].data = [data.tcp, data.udp];
            connTypeChart.update();
        }

        // Connection status chart
        if (connStatusChart) {
            const other = data.total - data.established - data.listening;
            connStatusChart.data.datasets[0].data = [data.established, data.listening, other];
            connStatusChart.update();
        }

        // Connections table
        const tbody = document.getElementById('connectionsBody');
        if (tbody) {
            const search = (document.getElementById('connSearch')?.value || '').toLowerCase();
            const filtered = search ? data.connections.filter(c =>
                c.local_address.includes(search) || c.remote_address.includes(search) ||
                c.process.toLowerCase().includes(search) || c.status.toLowerCase().includes(search)
            ) : data.connections;

            tbody.innerHTML = filtered.slice(0, 100).map(c => `
                <tr>
                    <td><span class="badge ${c.type === 'TCP' ? 'badge-running' : 'badge-listen'}">${c.type}</span></td>
                    <td>${c.local_address}</td>
                    <td>${c.remote_address}</td>
                    <td>${getStatusBadge(c.status)}</td>
                    <td>${c.pid}</td>
                    <td>${c.process}</td>
                </tr>
            `).join('');
        }
    } catch (e) {
        console.error('Connections data error:', e);
    }
}

async function loadLogsData() {
    try {
        const res = await fetch('/api/logs');
        const data = await res.json();

        const container = document.getElementById('logContainer');
        if (!container) return;

        const search = (document.getElementById('logSearch')?.value || '').toLowerCase();
        const filtered = search ? data.logs.filter(l => l.message.toLowerCase().includes(search)) : data.logs;

        container.innerHTML = filtered.map(log => {
            let cls = 'log-info';
            const msg = log.message.toLowerCase();
            if (msg.includes('error') || msg.includes('fail') || msg.includes('critical')) cls = 'log-error';
            else if (msg.includes('warn')) cls = 'log-warning';
            if (log.source === 'netra') cls = 'log-netra';

            return `<div class="log-entry ${cls}">
                <span class="log-source">[${log.source}]</span>
                <span>${escapeHtml(log.message)}</span>
            </div>`;
        }).join('');

        // Auto scroll
        if (document.getElementById('autoScroll')?.checked) {
            container.scrollTop = container.scrollHeight;
        }
    } catch (e) {
        console.error('Logs data error:', e);
    }
}

function escapeHtml(text) {
    const d = document.createElement('div');
    d.textContent = text;
    return d.innerHTML;
}

// ─── Password Change ────────────────────────────────────────────────
async function changePassword() {
    const btn = document.getElementById('btnChangePassword');
    const feedback = document.getElementById('passwordFeedback');
    const currentPassword = document.getElementById('currentPassword')?.value;
    const newPassword = document.getElementById('newPassword')?.value;
    const confirmPassword = document.getElementById('confirmPassword')?.value;

    if (!currentPassword || !newPassword || !confirmPassword) {
        showFeedback(feedback, 'error', 'All fields are required');
        return;
    }

    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> <span>Changing...</span>';

    try {
        const res = await fetch('/api/change-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': CSRF_TOKEN,
            },
            body: JSON.stringify({
                current_password: currentPassword,
                new_password: newPassword,
                confirm_password: confirmPassword,
            })
        });

        const data = await res.json();

        if (data.status === 'success') {
            showFeedback(feedback, 'success', data.message);
            // Clear inputs
            document.getElementById('currentPassword').value = '';
            document.getElementById('newPassword').value = '';
            document.getElementById('confirmPassword').value = '';
        } else {
            showFeedback(feedback, 'error', data.message);
        }
    } catch (e) {
        showFeedback(feedback, 'error', 'Network error: ' + e.message);
    }

    btn.disabled = false;
    btn.innerHTML = '<i class="fa-solid fa-key"></i> <span>Change Password</span>';
}

function showFeedback(el, type, message) {
    if (!el) return;
    el.style.display = 'block';
    el.className = `form-feedback form-feedback-${type}`;
    el.innerHTML = `<i class="fa-solid ${type === 'success' ? 'fa-circle-check' : 'fa-circle-xmark'}"></i> ${message}`;
    // Auto-hide after 8 seconds
    setTimeout(() => { el.style.display = 'none'; }, 8000);
}

function togglePasswordVisibility(inputId, btn) {
    const input = document.getElementById(inputId);
    if (!input) return;
    const icon = btn.querySelector('i');
    if (input.type === 'password') {
        input.type = 'text';
        icon.className = 'fa-solid fa-eye-slash';
    } else {
        input.type = 'password';
        icon.className = 'fa-solid fa-eye';
    }
}

// ─── Update Feature ─────────────────────────────────────────────────
async function triggerUpdate() {
    const btn = document.getElementById('btnUpdate');
    const output = document.getElementById('updateOutput');
    const log = document.getElementById('updateLog');

    btn.disabled = true;
    btn.innerHTML = '<span class="update-icon"><i class="fa-solid fa-spinner fa-spin"></i></span><span>Updating...</span>';
    output.style.display = 'block';
    log.textContent = 'Fetching updates from git repository...\n';

    try {
        const res = await fetch('/api/update', {
            method: 'POST',
            headers: { 'X-CSRF-Token': CSRF_TOKEN }
        });
        const data = await res.json();

        if (data.status === 'success') {
            log.textContent += data.message + '\n';
            if (data.output) log.textContent += data.output;
            log.style.color = '#00ff88';
        } else {
            log.textContent += data.message + '\n';
            if (data.output) log.textContent += data.output;
            log.style.color = '#ff3366';
        }
    } catch (e) {
        log.textContent += 'Error: ' + e.message + '\n';
        log.style.color = '#ff3366';
    }

    btn.disabled = false;
    btn.innerHTML = '<span class="update-icon"><i class="fa-solid fa-rocket"></i></span><span>Check & Update</span>';
}

// ─── Navigation ─────────────────────────────────────────────────────
function initNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    const panels = document.querySelectorAll('.panel');

    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const target = item.dataset.panel;

            navItems.forEach(n => n.classList.remove('active'));
            item.classList.add('active');

            panels.forEach(p => {
                p.classList.remove('active');
                if (p.id === 'panel-' + target) {
                    p.classList.add('active');
                }
            });

            // Load data for the panel
            loadPanelData(target);

            // Close sidebar on mobile
            document.getElementById('sidebar')?.classList.remove('open');
        });
    });

    // Mobile menu toggle
    document.getElementById('menuToggle')?.addEventListener('click', () => {
        document.getElementById('sidebar')?.classList.toggle('open');
    });

    // Search filters
    document.getElementById('serviceSearch')?.addEventListener('input', () => loadServicesData());
    document.getElementById('connSearch')?.addEventListener('input', () => loadConnectionsData());
    document.getElementById('logSearch')?.addEventListener('input', () => loadLogsData());
}

function loadPanelData(panel) {
    switch (panel) {
        case 'overview': loadSystemData(); break;
        case 'network': loadNetworkData(); break;
        case 'firewall': loadFirewallData(); break;
        case 'services': loadServicesData(); break;
        case 'resources': loadSystemData(); break;
        case 'connections': loadConnectionsData(); break;
        case 'logs': loadLogsData(); break;
    }
}

// ─── Clock ──────────────────────────────────────────────────────────
function updateClock() {
    const el = document.getElementById('clock');
    if (el) {
        const now = new Date();
        el.textContent = now.toLocaleTimeString('en-US', { hour12: false });
    }
}

// ─── Init ───────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    initNavigation();
    loadSystemData();
    loadNetworkData();

    updateClock();
    setInterval(updateClock, 1000);

    // Periodic data refresh (15 seconds)
    setInterval(() => {
        const activePanel = document.querySelector('.nav-item.active')?.dataset.panel;
        if (activePanel) loadPanelData(activePanel);
    }, 15000);
});
