//go:build ignore

package main

import (
	"fmt"
	"math/rand"
)

// The ordinary traffic the stories sit inside.
//
// Without it the demo is a list of alerts, and every screen that exists to find
// signal in volume — clustering on the events screen, the timeline's grouping,
// the ranked queue — has nothing to do. These records are deliberately dull:
// logons that succeed, DNS that resolves, files that open.
//
// Generated from a fixed seed, so regenerating the dataset produces byte-identical
// output and a diff shows only what actually changed.

const backgroundSeed = 20260803

func buildBackground() {
	r := rand.New(rand.NewSource(backgroundSeed))

	dailyLogons(r)
	dnsAndWeb(r)
	fileActivity(r)
	adminActivity(r)
	noisyDenials(r)
}

// dailyLogons: people arriving, unlocking, and occasionally mistyping.
func dailyLogons(r *rand.Rand) {
	n := 0
	for day := 0; day <= spanDays; day++ {
		for _, u := range people {
			ws := workstations[r.Intn(len(workstations))]
			hour := 7 + r.Intn(3)
			min := r.Intn(60)

			add(day, hour, min, event(3002, 3, 1, 1, "Successful interactive logon", map[string]any{
				"device":   ws.device(),
				"user":     map[string]any{"name": u, "domain": "CORP"},
				"auth":     map[string]any{"protocol": "Kerberos", "logon_type": "Interactive"},
				"metadata": meta(fmt.Sprintf("bg-auth-%05d", n), "Windows", "Microsoft"),
				"observables": []map[string]any{
					obs("user.name", 4, u),
					obs("device.hostname", 1, ws.Name),
				},
			}))
			n++

			// A mistyped password now and then, which is what makes a real
			// failure count unremarkable.
			if r.Intn(4) == 0 {
				add(day, hour, min-1, event(3002, 3, 2, 2, "Logon failed: bad password", map[string]any{
					"device":   ws.device(),
					"user":     map[string]any{"name": u, "domain": "CORP"},
					"metadata": meta(fmt.Sprintf("bg-auth-%05d", n), "Windows", "Microsoft"),
					"observables": []map[string]any{
						obs("user.name", 4, u),
						obs("device.hostname", 1, ws.Name),
					},
				}))
				n++
			}

			// Screen unlocks through the day.
			for i := 0; i < 2+r.Intn(3); i++ {
				add(day, 9+r.Intn(8), r.Intn(60), event(3002, 3, 1, 1, "Workstation unlocked", map[string]any{
					"device":      ws.device(),
					"user":        map[string]any{"name": u, "domain": "CORP"},
					"auth":        map[string]any{"logon_type": "Unlock"},
					"metadata":    meta(fmt.Sprintf("bg-auth-%05d", n), "Windows", "Microsoft"),
					"observables": []map[string]any{obs("user.name", 4, u)},
				}))
				n++
			}
		}
	}
}

// dnsAndWeb: the domains an office resolves all day.
func dnsAndWeb(r *rand.Rand) {
	domains := []string{
		"updates.microsoft.example", "cdn.jsdelivr.example", "portal.northwind.example",
		"mail.northwind.example", "docs.northwind.example", "api.payroll-saas.example",
		"telemetry.vendor.example", "packages.npmjs.example", "registry.docker.example",
	}
	n := 0
	for day := 0; day <= spanDays; day++ {
		for i := 0; i < 26; i++ {
			ws := workstations[r.Intn(len(workstations))]
			d := domains[r.Intn(len(domains))]
			hour := 8 + r.Intn(9)
			min := r.Intn(60)

			add(day, hour, min, event(4003, 4, 2, 1, "DNS query resolved", map[string]any{
				"device":      ws.device(),
				"query":       map[string]any{"hostname": d, "type": "A"},
				"metadata":    meta(fmt.Sprintf("bg-dns-%05d", n), "DNS", "Acme"),
				"observables": []map[string]any{obs("dns.hostname", 1, d)},
			}))
			n++

			if r.Intn(3) == 0 {
				add(day, hour, min, event(4002, 4, 1, 1, "HTTP request completed", map[string]any{
					"device":       ws.device(),
					"src_endpoint": map[string]any{"ip": ws.IP},
					"dst_endpoint": map[string]any{"hostname": d, "port": 443},
					"http_request": map[string]any{"method": "GET", "url": map[string]any{"hostname": d, "path": "/"}},
					"http_status":  200,
					"metadata":     meta(fmt.Sprintf("bg-http-%05d", n), "Proxy", "Acme"),
					"observables":  []map[string]any{obs("dns.hostname", 1, d)},
				}))
				n++
			}
		}
	}
}

// fileActivity: documents being opened and saved on the shares.
func fileActivity(r *rand.Rand) {
	files := []string{
		"FY26-forecast.xlsx", "board-pack.pptx", "supplier-terms.docx",
		"headcount.xlsx", "incident-runbook.md", "release-notes.md",
	}
	shares := []host{hostByName("srv-file-01"), hostByName("srv-sql-02")}
	n := 0
	for day := 0; day <= spanDays; day++ {
		for i := 0; i < 18; i++ {
			h := shares[r.Intn(len(shares))]
			u := people[r.Intn(len(people))]
			f := files[r.Intn(len(files))]
			activity := 1 + r.Intn(2) // create or read

			add(day, 8+r.Intn(9), r.Intn(60), event(1001, 1, activity, 1, "File accessed on share", map[string]any{
				"device":   h.device(),
				"user":     map[string]any{"name": u, "domain": "CORP"},
				"file":     map[string]any{"name": f, "path": "\\\\" + h.Name + "\\shared\\"},
				"metadata": meta(fmt.Sprintf("bg-file-%05d", n), "EDR", "Acme"),
				"observables": []map[string]any{
					obs("user.name", 4, u),
					obs("file.name", 7, f),
					obs("device.hostname", 1, h.Name),
				},
			}))
			n++
		}
	}
}

// adminActivity: the processes a managed estate starts on its own.
func adminActivity(r *rand.Rand) {
	procs := []struct{ name, cmd string }{
		{"MsMpEng.exe", "MsMpEng.exe"},
		{"gpupdate.exe", "gpupdate.exe /force"},
		{"backup-agent", "/usr/sbin/backup-agent --nightly"},
		{"dockerd", "/usr/bin/dockerd"},
		{"sshd", "/usr/sbin/sshd -D"},
	}
	all := append(append([]host{}, workstations...), servers...)
	n := 0
	for day := 0; day <= spanDays; day++ {
		for i := 0; i < 14; i++ {
			h := all[r.Intn(len(all))]
			p := procs[r.Intn(len(procs))]

			add(day, r.Intn(24), r.Intn(60), event(1007, 1, 1, 1, "Process started", map[string]any{
				"device":      h.device(),
				"process":     map[string]any{"name": p.name, "pid": 1000 + r.Intn(60000), "cmd_line": p.cmd},
				"metadata":    meta(fmt.Sprintf("bg-proc-%05d", n), "EDR", "Acme"),
				"observables": []map[string]any{obs("process.name", 9, p.name), obs("device.hostname", 1, h.Name)},
			}))
			n++
		}
	}
}

// noisyDenials: perimeter drops, which every firewall produces constantly and
// which must not look like an incident.
func noisyDenials(r *rand.Rand) {
	fw := hostByName("fw-edge-01")
	n := 0
	for day := 0; day <= spanDays; day++ {
		for i := 0; i < 20; i++ {
			src := fmt.Sprintf("%d.%d.%d.%d", 91+r.Intn(60), r.Intn(256), r.Intn(256), 1+r.Intn(254))
			port := []int{22, 23, 445, 3389, 5900}[r.Intn(5)]

			add(day, r.Intn(24), r.Intn(60), event(4001, 4, 6, 1, "Inbound connection denied at the perimeter",
				map[string]any{
					"device":         fw.device(),
					"src_endpoint":   map[string]any{"ip": src},
					"dst_endpoint":   map[string]any{"ip": "203.0.113.10", "port": port},
					"disposition":    "Blocked",
					"disposition_id": 2,
					"metadata":       meta(fmt.Sprintf("bg-net-%05d", n), "Firewall", "Acme"),
					"observables":    []map[string]any{obs("src_endpoint.ip", 2, src)},
				}))
			n++
		}
	}
}
