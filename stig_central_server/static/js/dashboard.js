async function fetchDashboardData() {
    try {
        const response = await fetch('/api/v1/summary');
        const data = await response.json();
        updateDashboard(data);
    } catch (error) {
        console.error('Error fetching dashboard data:', error);
    }
}

function updateDashboard(data) {
    // Update summary cards
    document.getElementById('total-hosts').textContent = data.total_hosts;
    document.getElementById('compliance-score').textContent = 
        `${data.compliance_score.toFixed(1)}%`;
    document.getElementById('critical-findings').textContent = 
        data.critical_findings;

    // Update recent scans table
    updateRecentScansTable(data.recent_scans);

    // Update compliance trend chart
    updateComplianceChart(data.compliance_trend);
}

function updateRecentScansTable(scans) {
    const tbody = document.querySelector('#recent-scans-table tbody');
    tbody.innerHTML = scans.map(scan => `
        <tr>
            <td class="table-cell">${scan.hostname}</td>
            <td class="table-cell">${formatDate(scan.timestamp)}</td>
            <td class="table-cell">
                <span class="status-badge status-${scan.status.toLowerCase()}">
                    ${scan.status}
                </span>
            </td>
        </tr>
    `).join('');
}

function updateComplianceChart(trend) {
    const ctx = document.getElementById('compliance-chart').getContext('2d');
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: trend.map(t => formatDate(t.date)),
            datasets: [{
                label: 'Compliance Score',
                data: trend.map(t => t.score),
                borderColor: '#3B82F6',
                tension: 0.1
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100
                }
            }
        }
    });
}

function formatDate(dateString) {
    return new Date(dateString).toLocaleDateString();
}

// Initial load
document.addEventListener('DOMContentLoaded', fetchDashboardData);
// Refresh every 5 minutes
setInterval(fetchDashboardData, 300000); 