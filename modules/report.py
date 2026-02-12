import os
import html
from datetime import datetime


def _read_file(filepath):
    """Read a text file and return lines, or empty list if file doesn't exist."""
    if not os.path.exists(filepath):
        return []
    with open(filepath, 'r') as f:
        return [line.rstrip('\n') for line in f.readlines() if line.strip()]


def _read_dcsync_files(output_dir):
    """Read all dcsync-notadmin_*.txt files and combine them."""
    lines = []
    for filename in sorted(os.listdir(output_dir)):
        if filename.startswith("dcsync-notadmin_") and filename.endswith(".txt"):
            filepath = os.path.join(output_dir, filename)
            with open(filepath, 'r') as f:
                for line in f.readlines():
                    if line.strip():
                        lines.append(line.rstrip('\n'))
    return lines


def _make_table(table_id, headers, rows):
    """Build a searchable, sortable data table matching QuickScope style."""
    count = len(rows)
    if count == 0:
        return '<div class="no-data">No data found</div>\n'

    # Table controls (search + row count)
    out = '<div class="table-container">\n'
    out += f'''    <div class="table-controls">
        <input type="text" id="{table_id}-search"
               onkeyup="filterTable('{table_id}-search', '{table_id}')"
               placeholder="Search table...">
        <span class="row-count" id="{table_id}-count">{count} rows</span>
    </div>\n'''

    # Table header
    out += f'<table class="data-table" id="{table_id}">\n<thead><tr>\n'
    for i, h in enumerate(headers):
        out += f'<th onclick="sortTable({i}, \'{table_id}\')">{html.escape(h)} <span class="sort-icon">&#8693;</span></th>\n'
    out += '</tr></thead>\n<tbody>\n'

    # Table rows
    for row in rows:
        out += '<tr>'
        for cell in row:
            out += f'<td>{html.escape(cell)}</td>'
        out += '</tr>\n'

    out += '</tbody>\n</table>\n</div>\n'
    return out


def _parse_lines_to_rows(lines):
    """Parse raw output lines into single-column table rows."""
    return [[line] for line in lines]


def _build_tab(tab_id, title, sections_data, read_fn, output_dir=None):
    """Build a tab content div with multiple sub-sections as tables."""
    content = f'<div id="{tab_id}" class="tab-content" style="display: none;">\n'
    content += '    <div class="section-content">\n'
    content += f'<h1>{html.escape(title)}</h1>\n'

    for label, source in sections_data:
        if callable(source):
            lines = source()
        else:
            lines = source

        table_id = f"{tab_id}-{label.lower().replace(' ', '-').replace('/', '-').replace('(', '').replace(')', '')}"
        rows = _parse_lines_to_rows(lines)
        content += f'<h2 class="sub-section-title">{html.escape(label)}'
        content += f' <span class="entry-count">({len(lines)} entries)</span></h2>\n'
        content += _make_table(table_id, ["Data"], rows)

    content += '    </div>\n</div>\n'
    return content


def generate_report(output_dir, report_data):
    """Generate a self-contained HTML report from output files and summary data."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def read(filename):
        return _read_file(os.path.join(output_dir, filename))

    # Extract summary stats
    domains = report_data.get('domains', [])
    dcs = report_data.get('dcs', [])
    computers = report_data.get('computers', 0)
    users = report_data.get('users', 0)
    enabled_users = report_data.get('enabled_users', 0)
    sessions = report_data.get('sessions', 0)
    owned_users = report_data.get('owned_users', 0)

    # Count findings for dashboard
    kerberoastable = read("kerberoastable.txt")
    asreproastable = read("asprep_roast.txt")
    da_sessions = read("da_sessions.txt")
    local_admins = read("users_localadmins.txt")
    vuln_certs = read("vuln_certs.txt")
    unconstrained = read("unconstrained_delegation.txt")

    # --- Build tabs ---

    # Tab: Dashboard
    dashboard = '<div id="dashboard" class="tab-content" style="display: block;">\n'
    dashboard += '    <div class="section-content">\n'
    dashboard += '<h1>AD-Recon Dashboard</h1>\n'

    # Environment overview table
    dashboard += '<h2 class="sub-section-title">Environment Overview</h2>\n'
    overview_rows = []
    for d in domains:
        overview_rows.append(["Domain", d])
    for dc in dcs:
        overview_rows.append(["Domain Controller", dc])
    overview_rows.append(["Total Computers", str(computers)])
    overview_rows.append(["Total Users", str(users)])
    overview_rows.append(["Enabled Users", str(enabled_users)])
    overview_rows.append(["Owned Users", str(owned_users)])
    overview_rows.append(["Sessions", str(sessions)])
    dashboard += _make_table("dashboard-overview", ["Property", "Value"], overview_rows)

    # Findings summary table with clickable rows
    dashboard += '<h2 class="sub-section-title">Findings Summary</h2>\n'
    findings = [
        ("Kerberoastable Users", str(len(kerberoastable)), "quick-wins"),
        ("ASREPRoastable Users", str(len(asreproastable)), "quick-wins"),
        ("Unconstrained Delegation", str(len(unconstrained)), "quick-wins"),
        ("Domain Admin Sessions", str(len(da_sessions)), "priv-esc"),
        ("Local Admin Rights", str(len(local_admins)), "priv-esc"),
        ("Vulnerable Cert Templates", str(len(vuln_certs)), "certs"),
    ]
    dashboard += '<div class="table-container">\n'
    dashboard += '<table class="data-table" id="dashboard-findings">\n'
    dashboard += '<thead><tr>'
    dashboard += '<th>Finding</th>'
    dashboard += '<th>Count</th>'
    dashboard += '<th>Details</th>'
    dashboard += '</tr></thead>\n<tbody>\n'
    for finding_label, count, target in findings:
        dashboard += f'<tr class="finding-row" onclick="jumpToTab(\'{target}\')">'
        dashboard += f'<td>{html.escape(finding_label)}</td>'
        dashboard += f'<td>{count}</td>'
        dashboard += f'<td class="jump-link">View &rarr;</td>'
        dashboard += '</tr>\n'
    dashboard += '</tbody>\n</table>\n</div>\n'

    dashboard += '    </div>\n</div>\n'

    # Tab: Quick Wins
    quick_wins = _build_tab("quick-wins", "Quick Wins", [
        ("Kerberoastable Users", kerberoastable),
        ("ASREPRoastable Users", asreproastable),
        ("Unconstrained Delegation", unconstrained),
        ("Password Not Required", read("users-enabled-PassNotReqd.txt")),
        ("Password Never Expires", read("user_enabled_passNeverExpires.txt")),
        ("Password Last Set > 1 Year", read("enabled_users_passwordlastset_1yr.txt")),
        ("Enabled Accounts Never Logged On", read("enabledacct_never_loggedon.txt")),
    ], read)

    # Tab: Privilege Escalation
    priv_esc = _build_tab("priv-esc", "Privilege Escalation", [
        ("Domain Admin Sessions", da_sessions),
        ("Users with Local Admin Rights", local_admins),
        ("DCSync / AllExtendedRights / GenericAll (Non-Admin)", lambda: _read_dcsync_files(output_dir)),
        ("Users with Path to DA", read("users_with_path_to_DA.txt")),
        ("Computers with Path to DA", read("computers_with_path_to_DA.txt")),
        ("Groups with Path to DA", read("groups_with_path_to_DA.txt")),
    ], read)

    # Tab: Certificates
    certs = _build_tab("certs", "Certificate Issues", [
        ("Vulnerable Certificate Templates", vuln_certs),
        ("Certificate Enroll Permissions", read("cert_enroll_permissions.txt")),
    ], read)

    # Tab: Access Rights
    access = _build_tab("access", "Access Rights", [
        ("Users First Degree Outbound Rights", read("users_outbound_1st_rights.txt")),
        ("Users Transitive Outbound Rights", read("users_outbound_trans_rights.txt")),
        ("Users Transitive Inbound Rights", read("users_inbound_trans_rights.txt")),
        ("Computer Transitive Outbound Rights", read("comp_outbound_trans_rights.txt")),
        ("Disabled Users Outbound Rights", read("disabled_users_outbound_firstRights.txt")),
        ("AllowedToAct", read("AllowedToAct.txt")),
        ("WriteAccountRestrictions", read("WriteAccountRestrictions.txt")),
        ("Common Groups Outbound Rights", read("common_groups_outboundrights.txt")),
        ("Computer Owners", read("comp_owners.txt")),
    ], read)

    # Tab: HVT
    hvt = _build_tab("hvt", "High Value Targets", [
        ("HVT Inbound Rights", read("hvt_inbound_rights.txt")),
        ("HVT AdminCount False Paths", read("hvt_AdminFalse.txt")),
    ], read)

    # Tab: Inventory
    inventory = _build_tab("inventory", "Inventory", [
        ("User Descriptions", read("user_descriptions.txt")),
        ("Computer Descriptions", read("computer_descriptions.txt")),
        ("Group Descriptions", read("group_descriptions.txt")),
        ("Admin Users (admincount: true)", read("admin_users.txt")),
        ("Admin Groups (admincount: true)", read("admin_groups.txt")),
        ("Computer SPNs", read("computer_spns.txt")),
        ("Top 100 Oldest Computers", read("top100_oldest_computers.txt")),
        ("LAPS Disabled Computers", read("computers_laps_disabled.txt")),
        ("All Sessions", read("sessions_all.txt")),
        ("Server RDP Rights", read("server_RDP.txt")),
        ("Server Admin by Group", read("server_admin_bygroup.txt")),
        ("First Degree User DCOM Rights", read("firstdegree_user_dcom_rights.txt")),
        ("Group Delegated User DCOM Rights", read("groupdel_user_dcom_rights.txt")),
        ("First Degree Group DCOM Rights", read("firstdegree_group_dcom_rights.txt")),
        ("GPO Inbound Rights", read("gpo_inbound_rights.txt")),
    ], read)

    # Tab: Owned
    owned = _build_tab("owned", "Owned Users", [
        ("Owned Users Outbound First Degree Rights", read("owned_users_outbound_1st_rights.txt")),
        ("AdminCount False Transitive Outbound Rights", read("admincount_false_outbound_trans_rights.txt")),
    ], read)

    report_html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';">
    <title>AD-Recon Report</title>
    <style>
* {{
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}}

body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Helvetica Neue', sans-serif;
    background: #f5f7fa;
    color: #2c3e50;
    line-height: 1.6;
}}

.header {{
    background: linear-gradient(135deg, #1A4677 0%, #22ACE8 100%);
    color: white;
    padding: 2rem;
    text-align: center;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}}

.header h1 {{
    font-size: 2.5rem;
    margin-bottom: 0.5rem;
}}

.header .subtitle {{
    font-size: 1.1rem;
    opacity: 0.9;
}}

/* Tab Navigation */
.tab-nav {{
    position: sticky;
    top: 0;
    background: #1A4677;
    padding: 0;
    box-shadow: 0 2px 8px rgba(0,0,0,0.15);
    z-index: 1000;
    display: flex;
    flex-wrap: wrap;
    justify-content: center;
}}

.tab-button {{
    background: transparent;
    color: #ecf0f1;
    border: none;
    padding: 1rem 2rem;
    cursor: pointer;
    transition: all 0.3s ease;
    font-size: 1rem;
    font-weight: 500;
    border-bottom: 3px solid transparent;
}}

.tab-button:hover {{
    background: #22ACE8;
    border-bottom-color: #DE560A;
}}

.tab-button.active {{
    background: #DE560A;
    border-bottom-color: #DE560A;
    color: white;
}}

/* Content Sections */
.tab-content {{
    display: none;
    padding: 2rem;
    animation: fadeIn 0.3s ease;
}}

@keyframes fadeIn {{
    from {{ opacity: 0; transform: translateY(10px); }}
    to {{ opacity: 1; transform: translateY(0); }}
}}

.section-content {{
    max-width: 1400px;
    margin: 0 auto;
}}

.section-content h1 {{
    color: #2c3e50;
    margin-bottom: 1.5rem;
    font-size: 2rem;
    border-bottom: 3px solid #22ACE8;
    padding-bottom: 0.5rem;
}}

/* Findings table clickable rows */
.finding-row {{
    cursor: pointer;
    transition: background 0.2s ease;
}}

.finding-row:hover {{
    background: #e8f4fd !important;
}}

.jump-link {{
    color: #22ACE8;
    font-weight: 600;
}}

/* Sub-section titles */
.sub-section-title {{
    color: #2c3e50;
    margin: 2rem 0 1rem 0;
    font-size: 1.4rem;
    font-weight: 600;
    padding-bottom: 0.5rem;
    border-bottom: 2px solid #ecf0f1;
}}

.entry-count {{
    color: #7f8c8d;
    font-weight: 400;
    font-size: 1rem;
}}

/* Tables */
.table-container {{
    background: white;
    border-radius: 12px;
    box-shadow: 0 4px 15px rgba(0,0,0,0.08);
    overflow: hidden;
    margin-bottom: 1.5rem;
}}

.table-controls {{
    padding: 1.5rem;
    background: #f8f9fa;
    border-bottom: 1px solid #e9ecef;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 1rem;
}}

.table-controls input[type="text"] {{
    padding: 0.75rem 1rem;
    border: 2px solid #e9ecef;
    border-radius: 8px;
    font-size: 1rem;
    width: 300px;
    transition: border-color 0.3s ease;
}}

.table-controls input[type="text"]:focus {{
    outline: none;
    border-color: #DE560A;
}}

.row-count {{
    color: #7f8c8d;
    font-weight: 500;
}}

.data-table {{
    width: 100%;
    border-collapse: collapse;
}}

.data-table th {{
    background: #22ACE8;
    color: white;
    padding: 1rem;
    text-align: left;
    cursor: pointer;
    user-select: none;
    font-weight: 600;
    text-transform: uppercase;
    font-size: 0.9rem;
    letter-spacing: 0.5px;
    position: relative;
}}

.data-table th:hover {{
    background: #1A4677;
}}

.column-resizer {{
    position: absolute;
    top: 0;
    right: 0;
    width: 5px;
    height: 100%;
    cursor: col-resize;
    user-select: none;
    background: transparent;
    z-index: 1;
}}

.column-resizer:hover {{
    background: rgba(255, 255, 255, 0.3);
}}

.sort-icon {{
    float: right;
    opacity: 0.6;
}}

.data-table td {{
    padding: 0.75rem 1rem;
    border-bottom: 1px solid #e9ecef;
    color: #2c3e50;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 0.9rem;
    word-break: break-all;
}}

.data-table tr:hover {{
    background: #f8f9fa;
}}

.data-table tr:last-child td {{
    border-bottom: none;
}}

/* No Data Message */
.no-data {{
    text-align: center;
    padding: 3rem;
    color: #7f8c8d;
    font-size: 1.2rem;
    background: white;
    border-radius: 12px;
    box-shadow: 0 4px 15px rgba(0,0,0,0.08);
    margin-bottom: 1.5rem;
}}

/* Footer */
.footer {{
    text-align: center;
    padding: 2rem;
    color: #7f8c8d;
    font-size: 0.9rem;
}}

/* Responsive Design */
@media (max-width: 768px) {{
    .tab-button {{
        padding: 0.75rem 1rem;
        font-size: 0.9rem;
    }}

    .header h1 {{
        font-size: 1.8rem;
    }}

    .table-controls {{
        flex-direction: column;
        align-items: stretch;
    }}

    .table-controls input[type="text"] {{
        width: 100%;
    }}

    .data-table {{
        font-size: 0.9rem;
    }}

    .data-table th,
    .data-table td {{
        padding: 0.75rem 0.5rem;
    }}
}}
    </style>
</head>
<body>
    <div class="header">
        <h1>AD-Recon Report</h1>
        <div class="subtitle">Active Directory Reconnaissance Report</div>
        <div class="subtitle">Generated: {timestamp}</div>
    </div>

    <div class="tab-nav">
        <button class="tab-button active" data-tab="dashboard" onclick="showTab('dashboard')">Dashboard</button>
        <button class="tab-button" data-tab="quick-wins" onclick="showTab('quick-wins')">Quick Wins</button>
        <button class="tab-button" data-tab="priv-esc" onclick="showTab('priv-esc')">Privilege Escalation</button>
        <button class="tab-button" data-tab="certs" onclick="showTab('certs')">Certificates</button>
        <button class="tab-button" data-tab="access" onclick="showTab('access')">Access Rights</button>
        <button class="tab-button" data-tab="hvt" onclick="showTab('hvt')">HVT</button>
        <button class="tab-button" data-tab="inventory" onclick="showTab('inventory')">Inventory</button>
        <button class="tab-button" data-tab="owned" onclick="showTab('owned')">Owned Users</button>
    </div>

{dashboard}
{quick_wins}
{priv_esc}
{certs}
{access}
{hvt}
{inventory}
{owned}

    <div class="footer">
        Generated by AD-Recon | {timestamp}
    </div>

    <script>
function showTab(tabName) {{
    var tabContents = document.getElementsByClassName('tab-content');
    for (var i = 0; i < tabContents.length; i++) {{
        tabContents[i].style.display = 'none';
    }}
    var tabButtons = document.getElementsByClassName('tab-button');
    for (var i = 0; i < tabButtons.length; i++) {{
        tabButtons[i].className = tabButtons[i].className.replace(' active', '');
    }}
    document.getElementById(tabName).style.display = 'block';
    event.currentTarget.className += ' active';
}}

function jumpToTab(tabName) {{
    var tabContents = document.getElementsByClassName('tab-content');
    for (var i = 0; i < tabContents.length; i++) {{
        tabContents[i].style.display = 'none';
    }}
    var tabButtons = document.getElementsByClassName('tab-button');
    for (var i = 0; i < tabButtons.length; i++) {{
        tabButtons[i].className = tabButtons[i].className.replace(' active', '');
        if (tabButtons[i].getAttribute('data-tab') === tabName) {{
            tabButtons[i].className += ' active';
        }}
    }}
    document.getElementById(tabName).style.display = 'block';
    window.scrollTo(0, 0);
}}

function sortTable(columnIndex, tableId) {{
    var table = document.getElementById(tableId);
    var tbody = table.getElementsByTagName('tbody')[0];
    var rows = Array.from(tbody.getElementsByTagName('tr'));
    var currentSort = table.getAttribute('data-sort-col');
    var currentDir = table.getAttribute('data-sort-dir');
    var ascending = true;
    if (currentSort == columnIndex && currentDir === 'asc') {{
        ascending = false;
    }}
    rows.sort(function(a, b) {{
        var aValue = a.getElementsByTagName('td')[columnIndex].textContent.trim();
        var bValue = b.getElementsByTagName('td')[columnIndex].textContent.trim();
        var aNum = parseFloat(aValue);
        var bNum = parseFloat(bValue);
        if (!isNaN(aNum) && !isNaN(bNum)) {{
            return ascending ? aNum - bNum : bNum - aNum;
        }}
        return ascending ? aValue.localeCompare(bValue) : bValue.localeCompare(aValue);
    }});
    rows.forEach(function(row) {{ tbody.appendChild(row); }});
    table.setAttribute('data-sort-col', columnIndex);
    table.setAttribute('data-sort-dir', ascending ? 'asc' : 'desc');
}}

function filterTable(inputId, tableId) {{
    var input = document.getElementById(inputId);
    var filter = input.value.toLowerCase();
    var table = document.getElementById(tableId);
    var tbody = table.getElementsByTagName('tbody')[0];
    var rows = tbody.getElementsByTagName('tr');
    var visibleCount = 0;
    for (var i = 0; i < rows.length; i++) {{
        var row = rows[i];
        var cells = row.getElementsByTagName('td');
        var found = false;
        for (var j = 0; j < cells.length; j++) {{
            var cellText = cells[j].textContent || cells[j].innerText;
            if (cellText.toLowerCase().indexOf(filter) > -1) {{
                found = true;
                break;
            }}
        }}
        if (found) {{
            row.style.display = '';
            visibleCount++;
        }} else {{
            row.style.display = 'none';
        }}
    }}
    var countElement = document.getElementById(tableId + '-count');
    if (countElement) {{
        countElement.textContent = visibleCount + ' rows';
    }}
}}

function makeColumnsResizable() {{
    var tables = document.querySelectorAll('table.data-table');
    tables.forEach(function(table) {{
        var headers = table.querySelectorAll('th');
        headers.forEach(function(header) {{
            var resizer = document.createElement('div');
            resizer.className = 'column-resizer';
            header.appendChild(resizer);
            var startX, startWidth;
            resizer.addEventListener('mousedown', function(e) {{
                e.preventDefault();
                startX = e.pageX;
                startWidth = header.offsetWidth;
                document.addEventListener('mousemove', resize);
                document.addEventListener('mouseup', stopResize);
            }});
            function resize(e) {{
                var width = startWidth + (e.pageX - startX);
                if (width > 50) {{
                    header.style.width = width + 'px';
                    header.style.minWidth = width + 'px';
                    header.style.maxWidth = width + 'px';
                }}
            }}
            function stopResize() {{
                document.removeEventListener('mousemove', resize);
                document.removeEventListener('mouseup', stopResize);
            }}
        }});
    }});
}}

document.addEventListener('DOMContentLoaded', function() {{
    var firstTab = document.getElementsByClassName('tab-content')[0];
    if (firstTab) {{
        firstTab.style.display = 'block';
    }}
    makeColumnsResizable();
}});
    </script>
</body>
</html>'''

    report_path = os.path.join(output_dir, "ad_recon_report.html")
    with open(report_path, 'w') as f:
        f.write(report_html)

    print(f"\n[+] HTML Report generated: {report_path}")
