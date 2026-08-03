//go:build ignore

package main

import "fmt"

// The five storylines.
//
// They deliberately overlap. j.rivera's compromised workstation talks to the
// same file server a.novak is staging data on; the scanner that produces the
// false positives touches every host in the estate. A pivot on a host or an
// address therefore crosses stories, which is what makes pivoting worth having
// — a demo where every indicator belongs to exactly one incident teaches the
// wrong lesson.

const (
	c2IP      = "198.51.100.73"
	c2Domain  = "cdn-metrics.example"
	poolIP    = "45.147.230.11"
	poolDom   = "pool.minexmr.example"
	stagedZip = "C:\\Users\\a.novak\\AppData\\Local\\Temp\\q4-export.zip"
	maldocSHA = "9f2a1c33be05c8b0a2b3a1f77c9e0e6a2f4d5b8c1e0a7d9f3b2c4e6a8d0f1b3c"
	minerSHA  = "3c1b5e7a9d2f4068ac13be57d9f0248613579bdf02468ace13579bdf02468ace"
)

func buildStory() {
	storyPhishing()
	storyAccountCompromise()
	storyCryptominer()
	storyScannerFalsePositives()
	storyDataStaging()
}

// ---------------------------------------------------------------------------
// 1. Phishing → execution → credential access → C2 → lateral movement
//
// The centrepiece. Day 3, one host, one user, a chain an analyst can follow
// from the email to the outbound session.
// ---------------------------------------------------------------------------

func storyPhishing() {
	ws := workstations[0] // workstation-14
	const user = "j.rivera"

	add(3, 8, 5, event(4009, 4, 1, 3, "Inbound email with archive attachment", map[string]any{
		"device": hostByName("mx-01").device(),
		"email": map[string]any{
			"from":    "billing@nordwind-invoices.example",
			"to":      []string{"j.rivera@northwind.example"},
			"subject": "Outstanding invoice 88213 — action required",
		},
		"metadata": meta("evt-mail-0001", "Mail Gateway", "Acme"),
		"observables": []map[string]any{
			obs("email.from", 5, "billing@nordwind-invoices.example"),
			obs("user.name", 4, user),
		},
	}))

	add(3, 8, 14, event(1001, 1, 1, 2, "Attachment extracted to user temp directory", map[string]any{
		"device": ws.device(),
		"user":   map[string]any{"name": user, "domain": "CORP"},
		"file": map[string]any{
			"name": "invoice-88213.docm",
			"path": "C:\\Users\\j.rivera\\AppData\\Local\\Temp\\invoice-88213.docm",
			"hashes": []map[string]any{
				{"algorithm": "SHA-256", "algorithm_id": 3, "value": maldocSHA},
			},
		},
		"metadata": meta("evt-file-0002", "EDR", "Acme"),
		"observables": []map[string]any{
			obs("file.name", 7, "invoice-88213.docm"),
			obs("file.hash", 8, maldocSHA),
			obs("device.hostname", 1, ws.Name),
		},
	}))

	add(3, 8, 14, event(1007, 1, 1, 4, "Office application spawned a scripting host", map[string]any{
		"device": ws.device(),
		"user":   map[string]any{"name": user, "domain": "CORP"},
		"process": map[string]any{
			"name": "powershell.exe", "pid": 6612,
			"cmd_line": "powershell.exe -nop -w hidden -enc SQBFAFgAIABbAFMAeQBzAHQAZQBtAC4A",
			"user":     map[string]any{"name": user, "domain": "CORP"},
		},
		"parent":   map[string]any{"name": "WINWORD.EXE", "pid": 4180},
		"metadata": meta("evt-proc-0003", "EDR", "Acme"),
		"observables": []map[string]any{
			obs("process.name", 9, "powershell.exe"),
			obs("device.hostname", 1, ws.Name),
			obs("user.name", 4, user),
		},
	}))

	add(3, 8, 15, event(4003, 4, 2, 3, "DNS query for newly registered domain", map[string]any{
		"device":   ws.device(),
		"query":    map[string]any{"hostname": c2Domain, "type": "A"},
		"metadata": meta("evt-dns-0004", "DNS", "Acme"),
		"observables": []map[string]any{
			obs("dns.hostname", 1, c2Domain),
			obs("device.hostname", 1, ws.Name),
		},
	}))

	// The beacon. Regular, quiet, and repeated — the shape that makes a pattern
	// visible in the timeline rather than a single suspicious moment.
	for i, min := range []int{16, 31, 46, 61, 76, 91, 106, 121} {
		add(3, 8+min/60, min%60, event(4001, 4, 1, 3, "Outbound HTTPS session established", map[string]any{
			"device":       ws.device(),
			"src_endpoint": map[string]any{"ip": ws.IP, "port": 51000 + i},
			"dst_endpoint": map[string]any{"ip": c2IP, "port": 443, "hostname": c2Domain},
			"traffic":      map[string]any{"bytes_out": 1120 + i*23, "bytes_in": 480 + i*11},
			"metadata":     meta(fmt.Sprintf("evt-net-%04d", 10+i), "Firewall", "Acme"),
			"observables": []map[string]any{
				obs("dst_endpoint.ip", 2, c2IP),
				obs("dns.hostname", 1, c2Domain),
				obs("device.hostname", 1, ws.Name),
			},
		}))
	}

	add(3, 9, 52, event(1007, 1, 1, 5, "Process opened a handle to LSASS", map[string]any{
		"device": ws.device(),
		"user":   map[string]any{"name": user, "domain": "CORP"},
		"process": map[string]any{
			"name": "svc_update.exe", "pid": 7104,
			"cmd_line": "svc_update.exe -dump 668",
		},
		"parent":   map[string]any{"name": "powershell.exe", "pid": 6612},
		"metadata": meta("evt-proc-0020", "EDR", "Acme"),
		"observables": []map[string]any{
			obs("process.name", 9, "svc_update.exe"),
			obs("device.hostname", 1, ws.Name),
		},
	}))

	add(3, 10, 22, event(3002, 3, 1, 4, "Interactive logon to domain controller", map[string]any{
		"device":   hostByName("dc-01").device(),
		"user":     map[string]any{"name": user, "domain": "CORP"},
		"auth":     map[string]any{"protocol": "Kerberos", "logon_type": "Network"},
		"metadata": meta("evt-auth-0021", "Windows", "Microsoft"),
		"observables": []map[string]any{
			obs("user.name", 4, user),
			obs("device.hostname", 1, "dc-01"),
			obs("src_endpoint.ip", 2, ws.IP),
		},
	}))

	add(3, 10, 41, event(4001, 4, 6, 4, "Firewall blocked outbound connection to known C2 infrastructure",
		map[string]any{
			"device":       hostByName("fw-edge-01").device(),
			"src_endpoint": map[string]any{"ip": ws.IP, "port": 51122},
			"dst_endpoint": map[string]any{"ip": c2IP, "port": 443},
			"disposition":  "Blocked", "disposition_id": 2,
			"metadata": meta("evt-net-0022", "Firewall", "Acme"),
			"observables": []map[string]any{
				obs("dst_endpoint.ip", 2, c2IP),
				obs("device.hostname", 1, ws.Name),
			},
		}))

	// The findings, in the order an analyst would meet them.
	finding(3, 8, 6, findingSpec{
		UID: "fnd-phish-0001", Title: "Malicious attachment delivered to j.rivera",
		Desc:     "A macro-enabled document arrived from a lookalike sender domain and was not quarantined. The attachment hash is unknown to the gateway.",
		Severity: 4, Risk: 71, Status: "In Progress", StatusID: 2,
		Confidence: "High", ConfID: 3,
		Analytic: "Lookalike Sender With Macro Attachment", RuleUID: "rule-mail-lookalike",
		Tactic:    [2]string{"Initial Access", "TA0001"},
		Technique: [2]string{"Phishing", "T1566"},
		Related:   []string{"evt-mail-0001", "evt-file-0002"},
		Device:    hostByName("mx-01"), User: user,
		Observable: []map[string]any{
			obs("email.from", 5, "billing@nordwind-invoices.example"),
			obs("file.hash", 8, maldocSHA),
			obs("user.name", 4, user),
		},
	})

	finding(3, 8, 15, findingSpec{
		UID: "fnd-exec-0002", Title: "Encoded PowerShell spawned by Office on workstation-14",
		Desc:     "WINWORD.EXE spawned powershell.exe with a hidden window and a base64-encoded command, the execution stage of a maldoc chain.",
		Severity: 5, Risk: 88, Status: "In Progress", StatusID: 2,
		Confidence: "High", ConfID: 3,
		Analytic: "Office Spawns Encoded Shell", RuleUID: "rule-office-encoded-shell",
		Tactic:    [2]string{"Execution", "TA0002"},
		Technique: [2]string{"Command and Scripting Interpreter", "T1059"},
		Related:   []string{"evt-proc-0003"},
		Device:    ws, User: user,
		Observable: []map[string]any{
			obs("process.name", 9, "powershell.exe"),
			obs("device.hostname", 1, ws.Name),
		},
	})

	finding(3, 9, 5, findingSpec{
		UID: "fnd-c2-0003", Title: "Confirmed C2 beaconing from workstation-14",
		Desc:     "Eight outbound sessions to the same host at a fifteen-minute interval, with request and response sizes that barely vary. The destination resolved from a domain registered four days ago.",
		Severity: 5, Risk: 91, Status: "In Progress", StatusID: 2,
		Confidence: "High", ConfID: 3,
		Analytic: "Periodic Beacon To Young Domain", RuleUID: "rule-beacon-interval",
		Tactic:    [2]string{"Command and Control", "TA0011"},
		Technique: [2]string{"Application Layer Protocol", "T1071"},
		Related:   []string{"evt-net-0010", "evt-net-0011", "evt-dns-0004"},
		Device:    ws, User: user,
		Observable: []map[string]any{
			obs("dst_endpoint.ip", 2, c2IP),
			obs("dns.hostname", 1, c2Domain),
			obs("device.hostname", 1, ws.Name),
		},
	})

	finding(3, 9, 53, findingSpec{
		UID: "fnd-cred-0004", Title: "LSASS memory access from unsigned binary on workstation-14",
		Desc:     "An unsigned executable in a user-writable directory opened a handle to LSASS with dump rights. Credential material for anyone logged on to this host should be treated as exposed.",
		Severity: 5, Risk: 94, Status: "New", StatusID: 1,
		Confidence: "High", ConfID: 3,
		Analytic: "LSASS Handle Access", RuleUID: "rule-lsass-handle",
		Tactic:    [2]string{"Credential Access", "TA0006"},
		Technique: [2]string{"OS Credential Dumping", "T1003"},
		Related:   []string{"evt-proc-0020"},
		Device:    ws, User: user,
		Observable: []map[string]any{
			obs("process.name", 9, "svc_update.exe"),
			obs("device.hostname", 1, ws.Name),
		},
	})

	finding(3, 10, 25, findingSpec{
		UID: "fnd-lat-0005", Title: "Domain controller logon from a host under investigation",
		Desc:     "j.rivera authenticated to dc-01 from workstation-14 thirty minutes after credential access was detected on that host. Consistent with reuse of dumped credentials rather than the user's own activity.",
		Severity: 4, Risk: 83, Status: "New", StatusID: 1,
		Confidence: "Medium", ConfID: 2,
		Analytic: "Logon From Host With Recent Credential Access", RuleUID: "rule-lateral-after-cred",
		Tactic:    [2]string{"Lateral Movement", "TA0008"},
		Technique: [2]string{"Remote Services", "T1021"},
		Related:   []string{"evt-auth-0021"},
		Device:    hostByName("dc-01"), User: user,
		Observable: []map[string]any{
			obs("user.name", 4, user),
			obs("device.hostname", 1, "dc-01"),
		},
	})
}

// ---------------------------------------------------------------------------
// 2. Account compromise — the case nobody has picked up
//
// Deliberately left unowned and unnoted, so the case header's next-action
// prompt has something true to say.
// ---------------------------------------------------------------------------

func storyAccountCompromise() {
	const user = "m.chen"

	add(4, 2, 12, event(3002, 3, 1, 3, "VPN authentication succeeded", map[string]any{
		"device":       hostByName("vpn-gw-01").device(),
		"user":         map[string]any{"name": user, "domain": "CORP"},
		"src_endpoint": map[string]any{"ip": "203.0.113.45"},
		"auth":         map[string]any{"protocol": "SAML", "logon_type": "Remote"},
		"metadata":     meta("evt-auth-0100", "VPN", "Acme"),
		"observables": []map[string]any{
			obs("user.name", 4, user),
			obs("src_endpoint.ip", 2, "203.0.113.45"),
		},
	}))

	add(4, 2, 41, event(3002, 3, 2, 3, "Multi-factor prompt denied by user", map[string]any{
		"device":       hostByName("vpn-gw-01").device(),
		"user":         map[string]any{"name": user, "domain": "CORP"},
		"src_endpoint": map[string]any{"ip": "203.0.113.45"},
		"metadata":     meta("evt-auth-0101", "VPN", "Acme"),
		"observables": []map[string]any{
			obs("user.name", 4, user),
			obs("src_endpoint.ip", 2, "203.0.113.45"),
		},
	}))

	for i := 0; i < 6; i++ {
		add(4, 2, 42+i*2, event(3002, 3, 2, 3, "Multi-factor prompt denied by user", map[string]any{
			"device":       hostByName("vpn-gw-01").device(),
			"user":         map[string]any{"name": user, "domain": "CORP"},
			"src_endpoint": map[string]any{"ip": "203.0.113.45"},
			"metadata":     meta(fmt.Sprintf("evt-auth-%04d", 110+i), "VPN", "Acme"),
			"observables": []map[string]any{
				obs("user.name", 4, user),
				obs("src_endpoint.ip", 2, "203.0.113.45"),
			},
		}))
	}

	finding(4, 2, 55, findingSpec{
		UID: "fnd-ident-0010", Title: "Impossible travel sign-in for m.chen",
		Desc:     "A successful VPN sign-in from an address geolocating 4,100 km from the previous session ninety minutes earlier. No corresponding travel request.",
		Severity: 3, Risk: 55, Status: "New", StatusID: 1,
		Confidence: "Medium", ConfID: 2,
		Analytic: "Impossible Travel", RuleUID: "rule-impossible-travel",
		Tactic:    [2]string{"Initial Access", "TA0001"},
		Technique: [2]string{"Valid Accounts", "T1078"},
		Related:   []string{"evt-auth-0100"},
		User:      user,
		Observable: []map[string]any{
			obs("user.name", 4, user),
			obs("src_endpoint.ip", 2, "203.0.113.45"),
		},
	})

	finding(4, 3, 2, findingSpec{
		UID: "fnd-ident-0011", Title: "Repeated MFA prompts denied for m.chen",
		Desc:     "Seven push notifications in fourteen minutes, all denied. Consistent with an attacker holding valid credentials and attempting to fatigue the second factor.",
		Severity: 4, Risk: 68, Status: "New", StatusID: 1,
		Confidence: "High", ConfID: 3,
		Analytic: "MFA Fatigue", RuleUID: "rule-mfa-fatigue",
		Tactic:    [2]string{"Credential Access", "TA0006"},
		Technique: [2]string{"Multi-Factor Authentication Request Generation", "T1621"},
		Related:   []string{"evt-auth-0101"},
		User:      user,
		Observable: []map[string]any{
			obs("user.name", 4, user),
			obs("src_endpoint.ip", 2, "203.0.113.45"),
		},
	})
}

// ---------------------------------------------------------------------------
// 3. Cryptominer on a build agent — the case that was closed
// ---------------------------------------------------------------------------

func storyCryptominer() {
	agent := hostByName("build-agent-03")

	add(1, 23, 14, event(1001, 1, 1, 3, "Executable written to a build workspace", map[string]any{
		"device": agent.device(),
		"file": map[string]any{
			"name": "kworker", "path": "/var/lib/build/tmp/kworker",
			"hashes": []map[string]any{
				{"algorithm": "SHA-256", "algorithm_id": 3, "value": minerSHA},
			},
		},
		"metadata": meta("evt-file-0200", "EDR", "Acme"),
		"observables": []map[string]any{
			obs("file.hash", 8, minerSHA),
			obs("device.hostname", 1, agent.Name),
		},
	}))

	add(1, 23, 16, event(1007, 1, 1, 4, "Process started with a mining pool argument", map[string]any{
		"device": agent.device(),
		"process": map[string]any{
			"name": "kworker", "pid": 20114,
			"cmd_line": "/var/lib/build/tmp/kworker --pool " + poolDom + ":3333 --cpu 90",
		},
		"metadata": meta("evt-proc-0201", "EDR", "Acme"),
		"observables": []map[string]any{
			obs("process.name", 9, "kworker"),
			obs("dns.hostname", 1, poolDom),
			obs("device.hostname", 1, agent.Name),
		},
	}))

	for i := 0; i < 5; i++ {
		add(2, i, 5, event(4001, 4, 1, 3, "Sustained outbound connection to mining pool", map[string]any{
			"device":       agent.device(),
			"src_endpoint": map[string]any{"ip": agent.IP},
			"dst_endpoint": map[string]any{"ip": poolIP, "port": 3333, "hostname": poolDom},
			"traffic":      map[string]any{"bytes_out": 90000 + i*4000, "bytes_in": 12000},
			"metadata":     meta(fmt.Sprintf("evt-net-%04d", 210+i), "Firewall", "Acme"),
			"observables": []map[string]any{
				obs("dst_endpoint.ip", 2, poolIP),
				obs("dns.hostname", 1, poolDom),
				obs("device.hostname", 1, agent.Name),
			},
		}))
	}

	finding(1, 23, 20, findingSpec{
		UID: "fnd-miner-0020", Title: "Cryptocurrency miner running on build-agent-03",
		Desc:     "A binary masquerading as a kernel worker was written into a build workspace and started with a mining pool argument, pinned at 90% CPU. Reached the host through an unpinned CI dependency.",
		Severity: 4, Risk: 74, Status: "Resolved", StatusID: 4,
		Confidence: "High", ConfID: 3,
		Verdict: "True Positive", VerdictID: 1,
		Analytic: "Mining Pool Connection", RuleUID: "rule-miner-pool",
		Tactic:    [2]string{"Impact", "TA0040"},
		Technique: [2]string{"Resource Hijacking", "T1496"},
		Related:   []string{"evt-proc-0201", "evt-file-0200"},
		Device:    agent,
		Observable: []map[string]any{
			obs("file.hash", 8, minerSHA),
			obs("dst_endpoint.ip", 2, poolIP),
			obs("device.hostname", 1, agent.Name),
		},
	})

	finding(2, 4, 30, findingSpec{
		UID: "fnd-miner-0021", Title: "Build agent CPU saturated for five hours",
		Desc:     "Sustained 90% CPU on build-agent-03 with no queued jobs. Raised independently of the miner detection and resolved by the same containment.",
		Severity: 2, Risk: 31, Status: "Resolved", StatusID: 4,
		Confidence: "Medium", ConfID: 2,
		Verdict: "True Positive", VerdictID: 1,
		Analytic: "Anomalous Sustained CPU", RuleUID: "rule-cpu-anomaly",
		Device:     agent,
		Observable: []map[string]any{obs("device.hostname", 1, agent.Name)},
	})
}

// ---------------------------------------------------------------------------
// 4. The scanner — findings that are real detections and benign in context
//
// Every queue has these, and an analyst's job is as much dismissing them well
// as chasing the rest. They carry a False Positive verdict so the queue shows
// what a closed-out alert looks like.
// ---------------------------------------------------------------------------

func storyScannerFalsePositives() {
	const scanner = "10.20.9.40"

	for i, h := range []host{workstations[1], workstations[2], hostByName("srv-sql-02"), hostByName("srv-file-01")} {
		add(2, 19, 5+i*3, event(4001, 4, 1, 2, "Legacy TLS 1.0 handshake offered", map[string]any{
			"device":       h.device(),
			"src_endpoint": map[string]any{"ip": scanner},
			"dst_endpoint": map[string]any{"ip": h.IP, "port": 443},
			"tls":          map[string]any{"version": "TLSv1.0"},
			"metadata":     meta(fmt.Sprintf("evt-net-%04d", 300+i), "Firewall", "Acme"),
			"observables": []map[string]any{
				obs("src_endpoint.ip", 2, scanner),
				obs("device.hostname", 1, h.Name),
			},
		}))
	}

	finding(2, 19, 30, findingSpec{
		UID: "fnd-scan-0030", Title: "Legacy TLS handshakes from an internal host",
		Desc:     "TLS 1.0 offered to four hosts in twelve minutes from 10.20.9.40, which is the authenticated vulnerability scanner. Behaviour is by design; the finding is kept for the record rather than deleted.",
		Severity: 2, Risk: 18, Status: "Resolved", StatusID: 4,
		Confidence: "High", ConfID: 3,
		Verdict: "False Positive", VerdictID: 2,
		Analytic: "Deprecated TLS Version", RuleUID: "rule-tls-legacy",
		Observable: []map[string]any{obs("src_endpoint.ip", 2, scanner)},
	})

	finding(2, 20, 2, findingSpec{
		UID: "fnd-scan-0031", Title: "Port sweep across the server subnet",
		Desc:     "1,024 ports touched across 10.20.1.0/24 within four minutes, from the scheduled scanner window. Matches the change record for the Tuesday scan.",
		Severity: 3, Risk: 22, Status: "Resolved", StatusID: 4,
		Confidence: "High", ConfID: 3,
		Verdict: "False Positive", VerdictID: 2,
		Analytic: "Horizontal Port Sweep", RuleUID: "rule-port-sweep",
		Observable: []map[string]any{obs("src_endpoint.ip", 2, scanner)},
	})

	finding(0, 11, 15, findingSpec{
		UID: "fnd-scan-0032", Title: "EICAR test file detected on ws-eng-31",
		Desc:     "The EICAR string appeared in a security-awareness training folder. Benign by definition; retained so the detection path is demonstrably working.",
		Severity: 1, Risk: 5, Status: "Resolved", StatusID: 4,
		Confidence: "High", ConfID: 3,
		Verdict: "False Positive", VerdictID: 2,
		Analytic: "EICAR Test String", RuleUID: "rule-eicar",
		Device:     workstations[3],
		Observable: []map[string]any{obs("device.hostname", 1, workstations[3].Name)},
	})
}

// ---------------------------------------------------------------------------
// 5. Data staging — open in the queue, not yet a case
//
// So the triage queue holds something an analyst would escalate themselves,
// rather than every finding already belonging somewhere.
// ---------------------------------------------------------------------------

func storyDataStaging() {
	fileSrv := hostByName("srv-file-01")
	const user = "a.novak"

	add(4, 18, 40, event(1001, 1, 1, 2, "Large archive created in a user temp directory", map[string]any{
		"device": workstations[2].device(),
		"user":   map[string]any{"name": user, "domain": "CORP"},
		"file": map[string]any{
			"name": "q4-export.zip", "path": stagedZip, "size": 2_411_663_872,
		},
		"metadata": meta("evt-file-0400", "EDR", "Acme"),
		"observables": []map[string]any{
			obs("file.name", 7, "q4-export.zip"),
			obs("user.name", 4, user),
		},
	}))

	for i := 0; i < 4; i++ {
		add(4, 18, 42+i*3, event(1001, 1, 2, 2, "Bulk read from finance share", map[string]any{
			"device":   fileSrv.device(),
			"user":     map[string]any{"name": user, "domain": "CORP"},
			"file":     map[string]any{"name": fmt.Sprintf("FY26-Q%d.xlsx", i+1), "path": "\\\\srv-file-01\\finance\\"},
			"metadata": meta(fmt.Sprintf("evt-file-%04d", 410+i), "EDR", "Acme"),
			"observables": []map[string]any{
				obs("user.name", 4, user),
				obs("device.hostname", 1, fileSrv.Name),
			},
		}))
	}

	finding(4, 19, 10, findingSpec{
		UID: "fnd-exfil-0040", Title: "Bulk finance share access followed by local archiving",
		Desc:     "a.novak read 812 files from the finance share out of hours and created a 2.2 GB archive locally. No upload has been observed. Could be a quarter-end export or the staging half of an exfiltration.",
		Severity: 4, Risk: 66, Status: "New", StatusID: 1,
		Confidence: "Low", ConfID: 1,
		Analytic: "Bulk Read Then Archive", RuleUID: "rule-stage-archive",
		Tactic:    [2]string{"Collection", "TA0009"},
		Technique: [2]string{"Archive Collected Data", "T1560"},
		Related:   []string{"evt-file-0400"},
		Device:    fileSrv, User: user,
		Observable: []map[string]any{
			obs("user.name", 4, user),
			obs("file.name", 7, "q4-export.zip"),
			obs("device.hostname", 1, fileSrv.Name),
		},
	})

	finding(0, 9, 20, findingSpec{
		UID: "fnd-misc-0050", Title: "Service account authenticated from a workstation",
		Desc:     "svc_backup signed in from ws-fin-07, which is not a management host. Low confidence: the account is also used for scheduled restores from that subnet.",
		Severity: 3, Risk: 44, Status: "New", StatusID: 1,
		Confidence: "Low", ConfID: 1,
		Analytic: "Service Account On Workstation", RuleUID: "rule-svc-on-ws",
		Tactic:    [2]string{"Defense Evasion", "TA0005"},
		Technique: [2]string{"Valid Accounts", "T1078"},
		Device:    workstations[2], User: "svc_backup",
		Observable: []map[string]any{obs("user.name", 4, "svc_backup")},
	})

	finding(1, 14, 45, findingSpec{
		UID: "fnd-misc-0051", Title: "Scheduled task created on srv-sql-02",
		Desc:     "A task was registered outside the change window by admin.jkim. Matches an approved patching ticket but the ticket reference was not recorded on the task.",
		Severity: 2, Risk: 27, Status: "In Progress", StatusID: 2,
		Confidence: "Medium", ConfID: 2,
		Analytic: "Task Created Outside Change Window", RuleUID: "rule-task-window",
		Tactic:    [2]string{"Persistence", "TA0003"},
		Technique: [2]string{"Scheduled Task/Job", "T1053"},
		Device:    hostByName("srv-sql-02"), User: "admin.jkim",
		Observable: []map[string]any{obs("user.name", 4, "admin.jkim")},
	})
}

func hostByName(name string) host {
	for _, h := range append(append([]host{}, workstations...), servers...) {
		if h.Name == name {
			return h
		}
	}
	panic("unknown host " + name)
}

func meta(uid, product, vendor string) map[string]any {
	return map[string]any{
		"uid": uid, "version": "1.8.0",
		"product": map[string]any{"name": product, "vendor_name": vendor},
	}
}
