/* Chapters 13–18 platform pages: course tour, cases, ask, moderation and operations.
   Loaded before the main script; it uses that script's helpers (h, api, $, pageHeader, panel, badge,
   gridTable, copyButton, markdown, fmtDate) only when a page is rendered. */
"use strict";
window.Platform = (() => {
  const S = {user: null, users: [], timer: null};
  const css = `
.sb-nav-2{padding-top:.6rem}
.sb-nav a[hidden]{display:none!important}
.identity{border:1px solid var(--line);border-radius:6px;padding:.55rem .6rem;margin-bottom:.4rem;font-size:.8rem;display:flex;flex-direction:column;gap:.4rem}
.identity .who{font-weight:600;color:var(--text)}
.identity .row{gap:.35rem;flex-wrap:nowrap}.identity select{min-height:30px;font-size:.8rem;padding:.2rem .4rem;flex:1;min-width:0}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.75rem;margin-bottom:1.25rem}
.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:1rem}
.chart{width:100%;height:auto;display:block}
.chart text{font:10px var(--sans);fill:var(--muted)}
.chart .grid{stroke:var(--line);stroke-width:1}
.chart .thr{stroke:var(--bad);stroke-dasharray:4 3;stroke-width:1.2}
.chart .mark{stroke:var(--accent);stroke-width:1.5}
.legend{display:flex;flex-wrap:wrap;gap:.3rem .9rem;font-size:.75rem;color:var(--muted);margin-top:.35rem}
.legend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:.3rem;vertical-align:-1px}
.c0{--c:#2f5bea}.c1{--c:#17803d}.c2{--c:#b25e09}.c3{--c:#9333ea}.c4{--c:#c4302b}
.st-PRIMARY{color:var(--ok)}.st-SECONDARY{color:var(--accent)}.st-down,.st-UNKNOWN,.st-RECOVERING{color:var(--bad)}
.notice.warn{border-left:3px solid var(--warn)}
.verdicts{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:.75rem;margin:.75rem 0}
.formgrid{display:grid;grid-template-columns:minmax(0,2fr) 140px minmax(0,1fr) auto;gap:.5rem}.formgrid .full{grid-column:1/-1}
@media (max-width:700px){.formgrid{grid-template-columns:1fr}}
.inline-select{min-height:28px;padding:.1rem .3rem;font-size:.8rem}
.cite{font-size:.75em;vertical-align:super;font-weight:600}
`;
  document.addEventListener("DOMContentLoaded", () => document.head.append(Object.assign(document.createElement("style"), {textContent: css})));

  // ------------------------------------------------------------------ identity
  const setToken = t => { try { t ? localStorage.setItem("cti_session", t) : localStorage.removeItem("cti_session"); } catch (e) {} };
  async function loadMe(){
    try { S.user = (await api("/api/auth/me")).user; } catch (e) { S.user = null; }
    if (!S.users.length) { try { S.users = await api("/api/auth/users"); } catch (e) {} }
    renderIdentity(); applyNav();
  }
  function renderIdentity(){
    const box = $("identity"); if (!box) return;
    if (S.user){
      box.replaceChildren(h("span", {class: "muted"}, "Signed in as"), h("span", {class: "who"}, S.user._id),
        h("span", {class: "muted"}, S.user.role + (S.user.org ? ` · ${S.user.org} (${S.user.org_role})` : "")),
        h("button", {class: "btn small", type: "button", onclick: signOut}, "Sign out"));
    } else {
      const sel = h("select", {class: "field", "aria-label": "Demo identity"}, S.users.map(u => h("option", {value: u._id}, `${u._id} — ${u.role}`)));
      box.replaceChildren(h("span", {class: "muted"}, "Demo sign-in (no passwords)"),
        h("div", {class: "row"}, sel, h("button", {class: "btn small primary", type: "button", onclick: () => signIn(sel.value)}, "Sign in")));
    }
  }
  async function signIn(username){
    const r = await api("/api/auth/signin", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({username})});
    setToken(r.token); await loadMe(); route();
  }
  function signOut(){ setToken(null); S.user = null; renderIdentity(); applyNav(); route(); }
  function allowed(needs){
    if (!needs) return true;
    if (!S.user) return false;
    if (needs === "user") return true;
    if (needs === "org") return !!S.user.org;
    return needs.split(",").includes(S.user.role);
  }
  function applyNav(){ for (const a of document.querySelectorAll(".sb-nav a[data-needs]")) a.hidden = !allowed(a.dataset.needs); }

  // ------------------------------------------------------------------ helpers
  // Each render draws into its own container; only the newest one is shown, so a slow page can never
  // overwrite a page the user navigated to afterwards.
  S.seq = 0;
  S.target = null;
  const view = () => S.target || $("view-platform");
  const fmtTime = s => s ? new Date(s).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit", second: "2-digit"}) : "—";
  const fmtBytes = n => n == null ? "—" : n > 1e6 ? (n / 1e6).toFixed(1) + " MB" : (n / 1e3).toFixed(1) + " kB";
  const pct = v => v == null ? "—" : (v * 100).toFixed(1) + " %";
  const num = v => v == null ? "—" : String(Math.round(v * 100) / 100);
  const post = (path, body) => api(path, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body || {})});
  function tabs(base, items, current){
    return h("div", {class: "subtabs", role: "tablist"}, items.map(([id, label]) =>
      h("button", {role: "tab", "aria-selected": String(id === current), onclick: () => { location.hash = `#${base}/${id}`; }}, label)));
  }
  function errorBox(err){
    const info = err.info || {};
    if (err.status === 401) return h("div", {class: "panel"}, h("h2", {}, "Sign in to continue"), h("p", {class: "muted"}, "Choose a demo identity at the bottom of the sidebar and press Sign in."));
    if (info.start_command) return h("div", {class: "notice warn"}, h("strong", {}, info.message || "This lab is not running."),
      h("div", {class: "small muted", style: "margin:.35rem 0"}, "Start it from the project folder in Ubuntu:"), h("div", {class: "cmd"}, h("code", {}, info.start_command), copyButton(info.start_command)));
    if (err.status === 429) return h("div", {class: "notice warn"}, err.message + (err.retryAfter ? ` (retry in ${err.retryAfter} s)` : ""));
    return h("div", {class: "notice warn"}, h("span", {class: "error"}, err.message));
  }
  function gate(needs, what){
    if (allowed(needs)) return null;
    if (!S.user) return errorBox({status: 401});
    const msg = needs === "org" ? "Your account does not belong to an organisation. Ask an administrator to add you (Operations → Users)."
      : `${what} needs the ${needs.replace(",", " or ")} role. You are signed in as ${S.user.role}.`;
    return h("div", {class: "notice warn"}, msg);
  }
  const tile = (k, v, s) => h("div", {class: "kpi"}, h("div", {class: "k"}, k), h("div", {class: "v"}, v), s ? h("div", {class: "s"}, s) : null);
  function startCard(state){
    if (!state || state.running) return null;
    return h("div", {class: "notice warn", style: "margin-bottom:1rem"}, h("strong", {}, `${state.label || "This lab"} is stopped`),
      " — charts show the last recorded data.", h("div", {class: "cmd", style: "margin-top:.5rem"}, h("code", {}, state.start_command), copyButton(state.start_command)));
  }
  function stopTimer(){ if (S.timer) { clearInterval(S.timer); S.timer = null; } }

  // ------------------------------------------------------------------ charts (inline SVG)
  function timeChart({title, series, from, to, yMax, thresholds = [], markers = [], format = num, height = 170}){
    const W = 600, H = height, L = 44, R = 8, T = 10, B = 22;
    const pts = series.flatMap(s => s.points.filter(p => p[1] != null));
    const max = Math.max(yMax || 0, ...thresholds.map(t => t.y * 1.15), ...pts.map(p => p[1]), 0.0001) * (yMax ? 1 : 1.12);
    const t0 = from.getTime(), t1 = to.getTime();
    const x = t => L + (W - L - R) * Math.min(1, Math.max(0, (t - t0) / (t1 - t0)));
    const y = v => T + (H - T - B) * (1 - v / max);
    const ns = "http://www.w3.org/2000/svg";
    const el = (tag, attrs, text) => { const n = document.createElementNS(ns, tag); for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v); if (text != null) n.textContent = text; return n; };
    const svg = el("svg", {viewBox: `0 0 ${W} ${H}`, class: "chart", role: "img", "aria-label": title});
    for (let i = 0; i <= 3; i++){ const v = max * i / 3; svg.append(el("line", {x1: L, x2: W - R, y1: y(v), y2: y(v), class: "grid"}), el("text", {x: L - 6, y: y(v) + 3, "text-anchor": "end"}, format(v))); }
    for (let i = 0; i <= 4; i++){ const t = t0 + (t1 - t0) * i / 4; svg.append(el("text", {x: x(t), y: H - 6, "text-anchor": i === 0 ? "start" : i === 4 ? "end" : "middle"}, new Date(t).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"}))); }
    for (const th of thresholds) svg.append(el("line", {x1: L, x2: W - R, y1: y(th.y), y2: y(th.y), class: "thr"}), el("text", {x: W - R, y: y(th.y) - 4, "text-anchor": "end", fill: "var(--bad)"}, th.label));
    let lastMark = -1e9;
    for (const m of markers){
      const mx = x(m.t);
      svg.append(el("line", {x1: mx, x2: mx, y1: T, y2: H - B, class: "mark"}));
      if (mx - lastMark > 110){ svg.append(el("text", {x: Math.min(mx + 3, W - 110), y: T + 9, fill: "var(--accent)"}, m.label)); lastMark = mx; }
    }
    series.forEach((s, i) => {
      const d = s.points.filter(p => p[1] != null).map((p, j) => `${j ? "L" : "M"}${x(p[0]).toFixed(1)},${y(p[1]).toFixed(1)}`).join("");
      const colour = ["#2f5bea", "#17803d", "#b25e09", "#9333ea", "#c4302b"][i % 5];
      if (d) svg.append(el("path", {d, fill: "none", stroke: colour, "stroke-width": 1.6}));
      const real = s.points.filter(p => p[1] != null);
      if (real.length <= 30) for (const p of real) svg.append(el("circle", {cx: x(p[0]), cy: y(p[1]), r: 3, fill: colour}));
    });
    return h("section", {class: "panel"}, h("h2", {style: "font-size:.88rem"}, title), pts.length ? svg : h("p", {class: "muted small"}, "No samples in this window yet."),
      h("div", {class: "legend"}, series.map((s, i) => h("span", {class: "c" + (i % 5)}, h("i", {style: "background:var(--c)"}), s.name))));
  }
  function stateChart({members, from, to, markers}){
    const W = 600, L = 120, R = 8, rowH = 22, T = 6;
    const names = Object.keys(members);
    const H = T + names.length * rowH + 22;
    const t0 = from.getTime(), t1 = to.getTime();
    const x = t => L + (W - L - R) * Math.min(1, Math.max(0, (t - t0) / (t1 - t0)));
    const ns = "http://www.w3.org/2000/svg";
    const el = (tag, attrs, text) => { const n = document.createElementNS(ns, tag); for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v); if (text != null) n.textContent = text; return n; };
    const colour = s => s === "PRIMARY" ? "#17803d" : s === "SECONDARY" ? "#7b9bff" : "#c4302b";
    const svg = el("svg", {viewBox: `0 0 ${W} ${H}`, class: "chart", role: "img", "aria-label": "Member state over time"});
    names.forEach((name, i) => {
      const yy = T + i * rowH;
      svg.append(el("text", {x: 4, y: yy + 14}, name));
      const pts = members[name];
      pts.forEach((p, j) => {
        const start = Date.parse(p.ts), end = j + 1 < pts.length ? Date.parse(pts[j + 1].ts) : Math.min(t1, start + 15000);
        if (end - start > 60000) return; // gap: the lab was stopped
        svg.append(el("rect", {x: x(start), y: yy + 3, width: Math.max(1, x(end) - x(start)), height: rowH - 8, fill: colour(p.state)}));
      });
    });
    let lastLabel = -1e9;
    for (const m of markers){
      const mx = x(m.t);
      const line = el("line", {x1: mx, x2: mx, y1: 0, y2: H - 16, class: "mark"});
      line.append(el("title", {}, `${m.label} at ${new Date(m.t).toLocaleTimeString()}`));
      svg.append(line);
      if (mx - lastLabel > 110){ svg.append(el("text", {x: Math.min(mx + 3, W - 110), y: H - 4, fill: "var(--accent)"}, m.label)); lastLabel = mx; }
    }
    return h("section", {class: "panel"}, h("h2", {style: "font-size:.88rem"}, "Member state over time"),
      names.length ? svg : h("p", {class: "muted small"}, "No samples yet — start the lab and wait 10 s."),
      h("div", {class: "legend"}, [["PRIMARY", "#17803d"], ["SECONDARY", "#7b9bff"], ["other / down", "#c4302b"], ["election", "var(--accent)"]].map(([n, c]) =>
        h("span", {}, h("i", {style: `background:${c}`}), n))));
  }
  function memberSeries(series, field){
    return Object.entries(series).map(([name, rows]) => ({name, points: rows.map(r => [Date.parse(r.ts), r[field]])}));
  }

  // ------------------------------------------------------------------ Course tour
  async function tour(){
    const V = view(); // this render's own container, captured before any await
    const data = await api("/api/tour");
    const statusTag = s => h("span", {class: "badge " + ({app: "s-passed", running: "s-passed", stopped: "s-none"}[s] || "")}, s);
    V.replaceChildren(
      pageHeader({crumbs: [{label: "Course"}], title: "Course tour", desc: "Every chapter from 7 to 18: what it does in this app, whether its lab is running, its Docker images and where it lives."
        + (data.public ? " Lab features are disabled on this public deployment." : "")}),
      panel("Chapters", h("span", {class: "muted small"}, "app = built into the dashboard · running/stopped = its lab topology"),
        gridTable([
          {label: "#", cls: "num", render: r => r.chapter.slice(2)},
          {label: "What it does here", render: r => h("div", {}, h("div", {class: "title"}, r.what), h("div", {class: "small muted"}, r.image))},
          {label: "Status", cls: "nowrap", render: r => statusTag(r.status)},
          {label: "Links", cls: "nowrap", render: r => h("div", {class: "row"}, h("a", {class: "btn small primary", href: r.link}, "Open"), h("a", {class: "btn small", href: r.lab_page}, "Lab"),
            r.status === "stopped" ? copyButton(r.start_command, "Copy start") : null)}], data.chapters)));
  }

  // ------------------------------------------------------------------ Chapter 15: cases
  async function cases(params){
    const V = view(); // this render's own container, captured before any await
    const blocked = gate("org", "Cases"); if (blocked) return V.replaceChildren(pageHeader({title: "Cases"}), blocked);
    const [me, rows] = await Promise.all([api("/api/cases/me"), api("/api/cases")]);
    const isAdmin = me.org_role === "admin";
    const members = isAdmin ? await api("/api/cases/org/members") : [];
    const title = h("input", {class: "field", required: true, minlength: 3, maxlength: 200, placeholder: "What needs investigating?", value: params.get("title") || ""});
    const priority = h("select", {class: "field"}, ["low", "medium", "high", "critical"].map(p => h("option", {value: p, selected: p === (params.get("ref") ? "high" : "medium")}, p)));
    const ref = h("input", {class: "field", maxlength: 500, placeholder: "Threat reference (optional)", value: params.get("ref") || ""});
    const msg = h("p", {class: "small muted", style: "margin:.5rem 0 0"});
    const form = h("form", {class: "formgrid"}, title, priority, ref, h("button", {class: "btn primary"}, "Open case"));
    form.onsubmit = async e => {
      e.preventDefault();
      try { await post("/api/cases", {title: title.value, priority: priority.value, threat_ref: ref.value || null}); location.hash = "#cases"; route(); }
      catch (err){ msg.replaceChildren(errorBox(err)); }
    };
    const editStatus = c => {
      const s = h("select", {class: "field inline-select"}, ["open", "investigating", "closed"].map(v => h("option", {value: v, selected: v === c.status}, v)));
      s.onchange = async () => { try { await api("/api/cases/" + c._id, {method: "PATCH", headers: {"Content-Type": "application/json"}, body: JSON.stringify({status: s.value})}); } catch (err){ alert(err.message); } };
      return s;
    };
    const editAssignee = c => {
      if (!isAdmin) return c.assignee;
      const s = h("select", {class: "field inline-select"}, members.map(m => h("option", {value: m._id, selected: m._id === c.assignee}, m._id)));
      s.onchange = async () => { try { await api("/api/cases/" + c._id, {method: "PATCH", headers: {"Content-Type": "application/json"}, body: JSON.stringify({assignee: s.value})}); } catch (err){ alert(err.message); } };
      return s;
    };
    V.replaceChildren(
      pageHeader({crumbs: [{label: "Chapter 15"}], title: "Cases", desc: `Organisation ${me.org_name} · you are ${me.org_role === "admin" ? "an organisation admin" : "a member"}. Cases are isolated per organisation; another organisation cannot see them at all.`,
        meta: [`${me.mine} of your cases`, isAdmin ? `${me.org_total} in the organisation` : null, `${me.open} open`, `limit ${me.rate_limit_per_minute} requests/min`]}),
      h("div", {class: "stack"},
          h("section", {class: "panel"}, h("h2", {}, "Open a case"), form, msg),
          panel(isAdmin ? "All cases of the organisation" : "Your cases", h("span", {class: "muted small"}, rows.length + " shown"),
            gridTable([
              {label: "Case", cls: "nowrap", render: c => h("code", {}, c._id)},
              {label: "Title", cls: "title", render: c => h("div", {style: "min-width:220px"}, c.title, c.threat_ref ? h("div", {class: "small muted"}, c.threat_ref) : null)},
              {label: "Priority", render: c => badge({critical: "failed", high: "partial", medium: "none", low: "none"}[c.priority], c.priority)},
              {label: "Status", render: editStatus},
              {label: "Owner", cls: "hide-sm nowrap", render: c => c.owner},
              {label: "Assignee", cls: "hide-sm", render: editAssignee},
              {label: "", cls: "right", render: c => isAdmin ? h("button", {class: "btn small", onclick: async () => {
                if (!confirm(`Delete ${c._id}?`)) return;
                try { await api("/api/cases/" + c._id, {method: "DELETE"}); route(); } catch (err){ alert(err.message); } }}, "Delete") : null}], rows)),
          isAdmin ? panel("Members", null, gridTable([{label: "User", render: m => m._id}, {label: "Org role", render: m => m.org_role}, {label: "Cases", cls: "right", render: m => String(m.cases)}], members)) : null));
  }

  // ------------------------------------------------------------------ Chapter 17: ask
  async function askPage(){
    const V = view(); // this render's own container, captured before any await
    const blocked = gate("user", "Ask"); if (blocked) return V.replaceChildren(pageHeader({title: "Ask the reports"}), blocked);
    const log = h("div", {class: "chat-log", style: "max-height:none"});
    const input = h("input", {class: "field grow", required: true, minlength: 3, maxlength: 500, placeholder: "Which reports mention Cobalt Strike?"});
    const send = h("button", {class: "btn primary"}, "Ask");
    const form = h("form", {class: "chat-form", style: "padding:0;border:0"}, input, send);
    const renderAnswer = (r) => {
      const md = markdown(r.answer.replace(/\[(\d+)\]/g, "⟦$1⟧"));
      md.innerHTML = md.innerHTML.replace(/⟦(\d+)⟧/g, (_, n) => `<a class="cite" href="#cite-${n}" title="Source ${n}">[${n}]</a>`);
      const cites = h("ol", {class: "small", style: "margin:.5rem 0 0;padding-left:1.2rem"}, (r.citations || []).map(c =>
        h("li", {}, h("a", {href: c.url || "#", target: "_blank", rel: "noopener"}, c.report), ` — page ${c.page}`, c.date ? ` · ${c.date}` : "", h("span", {class: "muted"}, ` · ${c.source}`))));
      return h("div", {class: "msg a"}, md, r.mode === "extractive" ? h("p", {class: "small", style: "color:var(--warn)"}, "Extractive answer: the language model was unavailable, so these are the closest matching reports.") : null,
        cites, h("div", {class: "meta"}, h("span", {}, r.mode === "llm" ? `Generated by ${r.model}` : "Extractive"), h("span", {}, r.retrieval || ""),
          r.memory_used ? h("span", {}, `used ${r.memory_used} earlier exchange(s)`) : null, r.budget_left != null ? h("span", {}, `${r.budget_left} questions left today`) : null));
    };
    try {
      for (const x of await api("/api/ask/history")) log.append(h("div", {class: "msg q"}, x.question), h("div", {class: "msg a"}, markdown(x.answer), h("div", {class: "meta"}, x.mode)));
    } catch (e) {}
    if (!log.children.length) log.append(h("p", {class: "muted small chat-empty"}, "Ask about the 435 Botvrij.eu OSINT reports and the classroom advisories. Follow-ups like “and in 2023?” use your last 5 exchanges."));
    form.onsubmit = async e => {
      e.preventDefault();
      const q = input.value.trim(); if (!q) return;
      log.querySelector(".chat-empty")?.remove();
      log.append(h("div", {class: "msg q"}, q));
      const box = h("div", {class: "msg a"}, h("span", {class: "muted"}, "Searching the reports and writing an answer…"));
      log.append(box); send.disabled = true;
      try { box.replaceWith(renderAnswer(await post("/api/ask", {question: q}))); input.value = ""; }
      catch (err){ box.replaceChildren(errorBox(err)); }
      finally { send.disabled = false; }
    };
    V.replaceChildren(
      pageHeader({crumbs: [{label: "Chapter 17"}], title: "Ask the reports", desc: "Retrieval-augmented answers over threat reports stored in MongoDB: 384-d all-MiniLM embeddings, cosine search plus keywords, and a local LLM that must cite its sources.",
        actions: [h("button", {class: "btn", onclick: async () => { await api("/api/ask/history", {method: "DELETE"}); route(); }}, "Forget history")]}),
      h("section", {class: "panel"}, log, h("div", {style: "margin-top:1rem"}, form)));
  }

  // ------------------------------------------------------------------ moderation
  async function moderation(tab){
    const V = view(); // this render's own container, captured before any await
    const blocked = gate("moderator,admin", "Moderation"); if (blocked) return V.replaceChildren(pageHeader({title: "Moderation"}), blocked);
    tab = tab || "alerts";
    const body = h("div", {});
    V.replaceChildren(pageHeader({crumbs: [{label: "Moderation"}], title: "Moderation", desc: "Alerts from monitoring, fraud review across three databases, false-positive review and organisations."}),
      tabs("moderation", [["alerts", "Alerts"], ["fraud", "Fraud review"], ["fp", "False positives"], ["organisations", "Organisations"]], tab), body);
    try { await ({alerts: modAlerts, fraud: modFraud, fp: modFp, organisations: modOrgs}[tab] || modAlerts)(body); }
    catch (err){ body.replaceChildren(errorBox(err)); }
  }
  async function modAlerts(body){
    const rows = await api("/api/moderation/alerts");
    body.append(panel("Warnings", h("span", {class: "muted small"}, "Open, or resolved in the last 24 h and not yet acknowledged · cache hit ratio < 80 % · replication lag > 10 s"),
      gridTable([
        {label: "Level", render: a => a.status === "resolved" ? badge("none", "resolved") : badge("partial", a.level || "WARNING")},
        {label: "Alert", cls: "title", render: a => h("div", {}, a.message, h("div", {class: "small muted"}, `${a.topology} · ${a.member} · value ${a.kind === "cache" ? pct(a.value) : num(a.value) + " s"}`))},
        {label: "Since", cls: "nowrap hide-sm", render: a => fmtDate(a.first_seen)},
        {label: "", cls: "right", render: a => a.acknowledged_by ? h("span", {class: "small muted"}, "Acknowledged by " + a.acknowledged_by)
          : h("button", {class: "btn small", onclick: async () => { await post("/api/moderation/alerts/ack", {key: a._id}); route(); }}, "Acknowledge")}], rows)));
  }
  async function modFraud(body){
    const data = await api("/api/moderation/fraud");
    const detail = h("div", {});
    const hops = h("select", {class: "field inline-select"}, [2, 3, 4].map(n => h("option", {value: n, selected: n === 3}, `${n} hops`)));
    async function analyse(acc){
      detail.replaceChildren(h("p", {class: "muted"}, "Querying MongoDB, Cassandra and Neo4j…"));
      try {
        const r = await api(`/api/moderation/fraud/${encodeURIComponent(acc.account)}?max_hops=${hops.value}` + (acc.transactions?.[0] ? "&txn_id=" + encodeURIComponent(acc.transactions[0].id) : ""));
        const card = (dbName, key, content) => h("section", {class: "panel"}, h("div", {class: "row", style: "justify-content:space-between"}, h("h2", {style: "margin:0"}, dbName),
          badge(r.breakers[key].state === "closed" ? "passed" : "failed", "breaker " + r.breakers[key].state)), r.errors[key] ? h("p", {class: "error small"}, r.errors[key]) : content);
        detail.replaceChildren(h("div", {class: "verdicts"},
          card("MongoDB · transaction", "mongo", h("pre", {class: "log", style: "max-height:220px"}, JSON.stringify(r.transaction, null, 2))),
          card("Cassandra · profile", "cassandra", h("pre", {class: "log", style: "max-height:220px"}, JSON.stringify(r.profile, null, 2))),
          card("Neo4j · ring members", "neo4j", r.rings?.length ? h("ul", {}, r.rings.map(x => h("li", {}, x.id))) : h("p", {class: "muted small"}, "No ring within this many hops."))),
          h("p", {class: "small muted"}, r.classification));
      } catch (err){ detail.replaceChildren(errorBox(err)); }
    }
    body.append(h("div", {class: "grid-main"},
      h("div", {class: "stack"}, detail.childNodes.length ? detail : (detail.append(h("p", {class: "muted"}, "Pick an account to analyse it across the three databases.")), detail)),
      h("div", {class: "stack sticky-side"}, panel("Accounts in device-sharing rings", hops,
        gridTable([{label: "Account", cls: "title", render: a => a.account}, {label: "Ring paths", cls: "right", render: a => String(a.ring_paths)},
          {label: "Transactions", cls: "right", render: a => String(a.transactions.length)}], data.accounts, analyse),
        h("p", {class: "small muted", style: "margin:0;padding:.7rem 1.1rem;border-top:1px solid var(--line)"}, data.note)))));
  }
  async function modFp(body){
    const reason = h("select", {class: "field"}, [["", "All reasons"], ["shared_infrastructure", "Shared / benign infrastructure"], ["single_unrated_source", "One unrated source"], ["many_families", "Blamed on 4+ families"]].map(([v, l]) => h("option", {value: v}, l)));
    const kind = h("select", {class: "field"}, [["", "All kinds"], ["url", "URLs"], ["domain", "Domains"], ["ip", "IPs"]].map(([v, l]) => h("option", {value: v}, l)));
    const q = h("input", {class: "field grow", placeholder: "Filter by value or family"});
    const openOnly = h("input", {type: "checkbox", checked: true});
    const list = h("div", {}), detail = h("div", {});
    const syncBtn = h("button", {class: "btn small", type: "button"}, "Sync to Cassandra & Neo4j");
    syncBtn.onclick = async () => { syncBtn.disabled = true; try { const s = await post("/api/moderation/fp/sync"); syncBtn.textContent = `Synced ${s.candidates} candidates`; } catch (err){ detail.replaceChildren(errorBox(err)); } finally { syncBtn.disabled = false; } };
    async function load(){
      list.replaceChildren(h("div", {class: "empty-row"}, "Loading…"));
      const p = new URLSearchParams({limit: 50, open_only: openOnly.checked});
      if (reason.value) p.set("reason", reason.value); if (kind.value) p.set("kind", kind.value); if (q.value) p.set("q", q.value);
      const d = await api("/api/moderation/fp?" + p);
      list.replaceChildren(h("div", {class: "panel-body small muted", style: "padding-bottom:0"}, `${d.total.toLocaleString()} candidates · ${d.decided} decided · by reason: ` +
        Object.entries(d.reason_counts).map(([k, v]) => `${d.reasons[k]} ${v.toLocaleString()}`).join(" · ")),
        gridTable([{label: "Value", cls: "title", render: i => h("code", {}, i.value)}, {label: "Kind", render: i => i.kind},
          {label: "Reasons", render: i => h("div", {class: "summary-chips"}, i.reasons.map(r => h("span", {class: "chip"}, r)))},
          {label: "Feeds", cls: "hide-sm", render: i => i.feeds.join(", ")}, {label: "Families", cls: "right hide-sm", render: i => String(i.family_count)}], d.items, show),
        !d.items.length && q.value.trim() ? h("div", {class: "panel-body"}, h("button", {class: "btn", type: "button", onclick: () => show({value: q.value.trim()})},
          `Look up “${q.value.trim()}” in all three databases`), h("span", {class: "small muted", style: "margin-left:.6rem"}, "It is not a candidate, but any imported indicator can be reviewed.")) : null);
    }
    async function show(item){
      detail.replaceChildren(h("p", {class: "muted"}, "Asking each database…"));
      detail.scrollIntoView({behavior: "smooth", block: "nearest"});
      try {
        const r = await api("/api/moderation/fp/value?value=" + encodeURIComponent(item.value));
        const decide = async d => { await post("/api/moderation/fp/decision", {value: r.value, kind: r.kind, decision: d}); show(item); load(); };
        detail.replaceChildren(h("section", {class: "panel"},
          h("div", {class: "row", style: "justify-content:space-between"}, h("h2", {style: "margin:0"}, h("code", {}, r.value)),
            h("div", {class: "row"}, h("span", {class: "small muted"}, "Vote:"), badge(r.vote.result === "false_positive" ? "failed" : r.vote.result === "keep" ? "passed" : "none", r.vote.result.replace("_", " ")))),
          h("p", {class: "small muted"}, `${r.vote.false_positive_votes} say false positive, ${r.vote.keep_votes} say keep · ${r.vote.rule}` + (r.decision ? ` · decided: ${r.decision} by ${r.decided_by}` : "")),
          h("div", {class: "verdicts"}, r.verdicts.map(v => h("div", {class: "kpi"}, h("div", {class: "row", style: "justify-content:space-between"}, h("strong", {}, v.database),
            badge(v.verdict === "false_positive" ? "failed" : v.verdict === "keep" ? "passed" : "none", v.verdict.replace("_", " "))),
            h("p", {class: "small", style: "margin:.4rem 0"}, v.rule),
            h("details", {class: "small"}, h("summary", {}, "Raw data"), h("pre", {class: "log", style: "max-height:200px"}, JSON.stringify(v.raw, null, 2)))))),
          h("div", {class: "row"}, h("button", {class: "btn primary", onclick: () => decide("false_positive")}, "Confirm false positive"),
            h("button", {class: "btn", onclick: () => decide("true_positive")}, "Keep (true positive)"),
            r.decision ? h("button", {class: "btn", onclick: () => decide("clear")}, "Clear decision") : null)));
      } catch (err){ detail.replaceChildren(errorBox(err)); }
    }
    const form = h("form", {class: "toolbar"}, q, reason, kind, h("label", {class: "small row", style: "gap:.3rem"}, openOnly, "open only"), h("button", {class: "btn primary"}, "Filter"));
    form.onsubmit = e => { e.preventDefault(); load(); };
    body.append(detail, h("section", {class: "panel flush", style: "margin-top:1rem"},
      h("div", {class: "panel-head"}, h("h2", {}, "False-positive candidates"), h("div", {class: "row"}, syncBtn, h("a", {class: "btn small", href: "/api/cti/export.csv"}, "Export CSV"))), form, list));
    await load();
  }
  async function modOrgs(body){
    const rows = await api("/api/moderation/organisations");
    const max = Math.max(1, ...rows.map(r => r.cases));
    body.append(panel("Organisations", null, gridTable([
      {label: "Organisation", cls: "title", render: r => r.name},
      {label: "Members", cls: "right", render: r => String(r.members)},
      {label: "Cases", render: r => h("div", {class: "row", style: "flex-wrap:nowrap"}, h("div", {style: `height:8px;border-radius:4px;background:var(--accent);width:${Math.max(4, 160 * r.cases / max)}px`}), String(r.cases))},
      {label: "By status", cls: "hide-sm", render: r => Object.entries(r.by_status).map(([k, v]) => `${k} ${v}`).join(" · ") || "—"},
      {label: "Rate-limit refusals", cls: "right", render: r => String(r.rate_limit_refusals)}], rows)));
  }

  // ------------------------------------------------------------------ operations (admin)
  async function ops(tab, params){
    const V = view(); // this render's own container, captured before any await
    const blocked = gate("admin", "Operations"); if (blocked) return V.replaceChildren(pageHeader({title: "Operations"}), blocked);
    tab = tab || "deployment";
    const body = h("div", {});
    V.replaceChildren(pageHeader({crumbs: [{label: "Admin"}], title: "Operations", desc: "Deployment and monitoring of the replica sets, backups, the Cassandra audit log, the Ask index, feed quality and users."}),
      tabs("ops", [["deployment", "Deployment"], ["monitoring", "Monitoring & backups"], ["audit", "Audit log"], ["ask-index", "Ask index"], ["sources", "Sources"], ["lab18", "Lab 18"], ["users", "Users"]], tab), body);
    const fn = {deployment: opsDeployment, monitoring: opsMonitoring, audit: opsAudit, "ask-index": opsAskIndex, sources: opsSources, lab18: opsLab18, users: opsUsers}[tab] || opsDeployment;
    try { await fn(body, params); } catch (err){ body.replaceChildren(errorBox(err)); }
  }
  function rangeSelect(current, onchange, options = [[30, "30 min"], [120, "2 h"], [720, "12 h"]]){
    const s = h("select", {class: "field inline-select"}, options.map(([v, l]) => h("option", {value: v, selected: v === current}, l)));
    s.onchange = () => onchange(Number(s.value));
    return s;
  }
  async function opsDeployment(body){
    let minutes = 30, topology = "secure";
    const out = h("div", {});
    const topo = h("select", {class: "field inline-select"}, [["secure", "Secure set (Ch 13)"], ["replica", "Replica set rs0 (Ch 8–10, 14)"]].map(([v, l]) => h("option", {value: v}, l)));
    const result = h("div", {});
    async function draw(){
      const d = await api(`/api/ops/metrics/deployment?minutes=${minutes}&topology=${topology}`);
      const to = new Date(), from = new Date(to - minutes * 60000);
      const markers = d.elections.map(e => ({t: Date.parse(e.ts), label: "elected " + (e.new_primary || "?").split(":")[0]}));
      const failBtn = h("button", {class: "btn primary", disabled: !d.running}, "Test failover");
      failBtn.onclick = async () => {
        failBtn.disabled = true; result.replaceChildren(h("p", {class: "muted"}, "Stepping down the primary and waiting for an election…"));
        try { const r = await post("/api/ops/lab13/failover?topology=" + topology); result.replaceChildren(h("div", {class: "notice"}, `${r.message}: ${r.old_primary} → ${r.new_primary || "none yet"} in ${r.seconds} s. The chart shows the marker within ~10 s.`)); }
        catch (err){ result.replaceChildren(errorBox(err)); }
        finally { failBtn.disabled = false; draw(); }
      };
      out.replaceChildren(startCard(d) || "",
        h("div", {class: "grid-main"},
          h("div", {class: "stack"},
            panel("Members", h("div", {class: "row"}, failBtn), gridTable([
              {label: "Member", cls: "title", render: m => m.name}, {label: "State", render: m => h("span", {class: "badge st-" + (m.state || "down")}, m.state || "down")},
              {label: "Ping", cls: "right", render: m => m.ping_ms == null ? "—" : m.ping_ms + " ms"}, {label: "Lag", cls: "right", render: m => m.lag_s == null ? "—" : num(m.lag_s) + " s"},
              {label: "Ops/s", cls: "right hide-sm", render: m => num(m.ops_per_s)}, {label: "Connections", cls: "right hide-sm", render: m => m.connections ?? "—"}], d.members)),
            result,
            stateChart({members: Object.fromEntries(Object.entries(d.series).map(([n, rows]) => [n, rows])), from, to, markers}),
            h("div", {class: "charts"},
              timeChart({title: "Operations per second", series: memberSeries(d.series, "ops_per_s"), from, to, markers}),
              timeChart({title: "Replication lag (s)", series: memberSeries(d.series, "lag_s"), from, to, markers}),
              timeChart({title: "Heartbeat ping (ms)", series: memberSeries(d.series, "ping_ms"), from, to}),
              timeChart({title: "Connections", series: memberSeries(d.series, "connections"), from, to}),
              timeChart({title: "Cache hit ratio", series: memberSeries(d.series, "hit_ratio"), from, to, yMax: 1, format: pct}))),
          h("div", {class: "stack sticky-side"},
            panel("Kubernetes", badge("none", "not configured"), h("div", {class: "panel-body small"}, d.kubernetes.note, h("div", {class: "cmd", style: "margin-top:.5rem"}, h("code", {}, d.kubernetes.command), copyButton(d.kubernetes.command)))),
            panel("MongoDB Atlas", badge("none", "needs key"), h("div", {class: "panel-body small"}, d.atlas.note)),
            panel("Monitoring stack", null, h("div", {class: "panel-body small muted"}, "Prometheus and Grafana are replaced by the dashboard's own sampler (every 10 s, MongoDB time-series collection cti_platform.metrics). The Percona exporter for Prometheus runs with ./scripts/exporter.sh on port 9216.")),
            d.compass ? panel("Compass", null, h("div", {class: "panel-body"}, h("div", {class: "cmd"}, h("code", {}, d.compass), copyButton(d.compass)))) : null)));
    }
    topo.onchange = () => { topology = topo.value; draw(); };
    body.append(h("div", {class: "toolbar", style: "padding:0 0 1rem;border:0"}, topo, rangeSelect(minutes, m => { minutes = m; draw(); })), out);
    await draw();
    stopTimer(); S.timer = setInterval(() => { if (location.hash.startsWith("#ops/deployment") || location.hash === "#ops") draw().catch(() => {}); else stopTimer(); }, 10000);
  }
  async function opsMonitoring(body){
    let minutes = 60;
    const out = h("div", {}), result = h("div", {});
    async function draw(){
      const d = await api(`/api/ops/metrics/monitoring?minutes=${minutes}`);
      const to = new Date(), from = new Date(to - minutes * 60000);
      const latest = d.members;
      const minHit = latest.map(m => m.hit_ratio).filter(v => v != null);
      const maxLag = latest.map(m => m.lag_s).filter(v => v != null);
      const backup = h("button", {class: "btn primary", disabled: !d.running}, "Back up now");
      const verify = h("button", {class: "btn", disabled: !d.running || !d.newest_backup}, "Verify restore");
      backup.onclick = async () => { backup.disabled = true; result.replaceChildren(h("p", {class: "muted"}, "Running mongodump --oplog…"));
        try { const r = await post("/api/ops/lab14/backup"); result.replaceChildren(h("div", {class: "notice"}, `Backup ${r.file} written: ${fmtBytes(r.bytes)} in ${r.seconds} s.`)); } catch (err){ result.replaceChildren(errorBox(err)); } draw(); };
      verify.onclick = async () => { verify.disabled = true; result.replaceChildren(h("p", {class: "muted"}, "Restoring the newest backup into a scratch database and comparing every document…"));
        try {
          const r = await post("/api/ops/lab14/verify");
          result.replaceChildren(h("section", {class: "panel"}, h("div", {class: "row", style: "justify-content:space-between"}, h("h2", {style: "margin:0"}, "Restore check"), badge(r.passed ? "passed" : "partial", r.passed ? "passed" : "differences")),
            h("p", {class: "small"}, `RTO ${r.rto_s} s (restore time) · RPO ${r.rpo_s} s (age of the backup) · ${r.backup}`),
            gridTable([{label: "Collection", render: c => c.collection}, {label: "Source", cls: "right", render: c => String(c.source_count)}, {label: "Restored", cls: "right", render: c => String(c.restored_count)},
              {label: "Missing", cls: "right", render: c => String(c.missing)}, {label: "Extra", cls: "right", render: c => String(c.extra)}, {label: "Differing", cls: "right", render: c => String(c.differing)}], r.collections),
            h("p", {class: "small muted"}, r.note)));
        } catch (err){ result.replaceChildren(errorBox(err)); } draw(); };
      const bk = d.backups.slice().reverse();
      out.replaceChildren(startCard(d) || "",
        h("div", {class: "tiles"},
          tile("Cache hit ratio", minHit.length ? pct(Math.min(...minHit)) : "—", "lowest member · alert below 80 %"),
          tile("Replication lag", maxLag.length ? num(Math.max(...maxLag)) + " s" : "—", "highest secondary · alert above 10 s"),
          tile("Open alerts", String(d.open_alerts.length), d.open_alerts.filter(a => !a.acknowledged_by).length + " unacknowledged"),
          tile("Newest backup", d.newest_backup ? fmtTime(d.newest_backup.ts) : "none", d.newest_backup ? fmtBytes(d.newest_backup.bytes) : "press Back up now"),
          tile("Last RTO", d.last_rto_s != null ? d.last_rto_s + " s" : "—", "from Verify restore")),
        h("div", {class: "row", style: "margin-bottom:1rem"}, backup, verify, rangeSelect(minutes, m => { minutes = m; draw(); }, [[30, "30 min"], [120, "2 h"], [720, "12 h"]])),
        result,
        h("div", {class: "charts", style: "margin-top:1rem"},
          timeChart({title: "Cache hit ratio", series: memberSeries(d.series, "hit_ratio"), from, to, yMax: 1, format: pct, thresholds: [{y: d.thresholds.hit_ratio, label: "80 %"}]}),
          timeChart({title: "Replication lag (s)", series: memberSeries(d.series, "lag_s"), from, to, thresholds: [{y: d.thresholds.lag_s, label: "10 s"}]}),
          timeChart({title: "Operations per second", series: memberSeries(d.series, "ops_per_s"), from, to}),
          timeChart({title: "Connections", series: memberSeries(d.series, "connections"), from, to}),
          bk.length ? timeChart({title: "Backup size", series: [{name: "archive size (MB)", points: bk.map(b => [Date.parse(b.ts), b.bytes / 1e6])}],
            from: new Date(Math.min(from, Date.parse(bk[0].ts) - 60000)), to, format: v => v.toFixed(1)}) : panel("Backup size", null, h("p", {class: "panel-body muted small"}, "No backups yet."))));
    }
    body.append(out);
    await draw();
    stopTimer(); S.timer = setInterval(() => { if (location.hash.startsWith("#ops/monitoring")) draw().catch(() => {}); else stopTimer(); }, 10000);
  }
  async function opsAudit(body){
    const day = h("input", {class: "field", type: "date", value: new Date().toISOString().slice(0, 10)});
    const actor = h("select", {class: "field"}, h("option", {value: ""}, "Everyone"), S.users.map(u => h("option", {value: u._id}, u._id)));
    const out = h("div", {});
    async function draw(){
      const p = new URLSearchParams({limit: 200}); if (day.value) p.set("day", day.value); if (actor.value) p.set("actor", actor.value);
      const [log, sum] = await Promise.all([api("/api/ops/audit?" + p), api("/api/ops/audit/summary?days=7")]);
      if (!log.available){
        out.replaceChildren(h("div", {class: "notice warn"}, h("strong", {}, `${log.waiting} event(s) waiting`), " in the MongoDB outbox: the audit log lives in Cassandra (lab 16), which is stopped. They will be delivered exactly once when it starts.",
          h("div", {class: "cmd", style: "margin-top:.5rem"}, h("code", {}, log.start_command), copyButton(log.start_command))));
        return;
      }
      const kinds = Object.keys(sum.by_kind);
      const max = Math.max(1, ...sum.days.map(d => d.total));
      out.replaceChildren(
        h("div", {class: "tiles"}, tile("Events, 7 days", String(sum.events_7d)), tile("Waiting in outbox", String(log.waiting), "delivered exactly once"),
          ...Object.entries(sum.by_kind).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([k, v]) => tile(k, String(v), "events in 7 days"))),
        panel("Last 7 days by kind", null, h("div", {class: "panel-body"}, h("div", {style: "display:grid;grid-template-columns:repeat(7,1fr);gap:.5rem;align-items:end;height:140px"},
          sum.days.map(d => h("div", {title: JSON.stringify(d.counts), style: "display:flex;flex-direction:column;justify-content:flex-end;height:100%;gap:1px"},
            kinds.map((k, i) => { const v = Object.entries(d.counts).filter(([a]) => a.startsWith(k + ".")).reduce((s, [, n]) => s + n, 0);
              return v ? h("div", {style: `height:${Math.max(2, 120 * v / max)}px;background:${["#2f5bea", "#17803d", "#b25e09", "#9333ea", "#c4302b", "#0891b2", "#64748b"][i % 7]};border-radius:2px`}) : null; }),
            h("div", {class: "small muted", style: "text-align:center;margin-top:.3rem"}, d.day.slice(5))))),
          h("div", {class: "legend"}, kinds.map((k, i) => h("span", {}, h("i", {style: `background:${["#2f5bea", "#17803d", "#b25e09", "#9333ea", "#c4302b", "#0891b2", "#64748b"][i % 7]}`}), k))))),
        h("div", {style: "height:1rem"}),
        panel("Events", h("span", {class: "muted small"}, log.events.length + " shown · from Cassandra cti_audit"), gridTable([
          {label: "Time", cls: "nowrap", render: e => fmtDate(e.ts)}, {label: "Who", render: e => e.actor}, {label: "Action", render: e => h("code", {}, e.action)},
          {label: "Outcome", render: e => badge(e.outcome === "ok" ? "passed" : "partial", e.outcome)},
          {label: "Details", cls: "hide-sm small muted", render: e => Object.entries(e.details).map(([k, v]) => `${k}=${v}`).join(" · ").slice(0, 160)}], log.events)));
    }
    const form = h("form", {class: "toolbar", style: "padding:0 0 1rem;border:0"}, day, actor, h("button", {class: "btn primary"}, "Show"));
    form.onsubmit = e => { e.preventDefault(); draw().catch(err => out.replaceChildren(errorBox(err))); };
    body.append(form, out);
    await draw();
  }
  async function opsAskIndex(body){
    const out = h("div", {});
    async function draw(){
      const s = await api("/api/ops/ask-index");
      const btn = h("button", {class: "btn primary", disabled: s.state === "indexing"}, s.state === "indexing" ? "Indexing…" : "Index the reports");
      btn.onclick = async () => { try { await post("/api/ops/ask-index"); draw(); } catch (err){ out.append(errorBox(err)); } };
      out.replaceChildren(h("div", {class: "tiles"}, tile("Pages indexed", String(s.chunks_indexed)), tile("State", s.state, s.state === "indexing" ? `${s.done || 0} / ${s.total || "?"}` : s.error || ""),
        tile("Embedding model", s.embedding_model, s.dims ? s.dims + " dimensions" : "384 dimensions"), tile("Questions asked", String(s.questions_asked)), tile("Answer model", s.chat_model)),
        h("div", {class: "row"}, btn), h("p", {class: "small muted"}, s.vector_search + " Report text stays in this platform's MongoDB; it is never put into a public image."));
      if (s.state === "indexing") setTimeout(() => { if (location.hash.startsWith("#ops/ask-index")) draw(); }, 3000);
    }
    body.append(out); await draw();
  }
  async function opsSources(body){
    const s = await api("/api/ops/sources");
    const openReport = async () => {
      let session = null; try { session = localStorage.getItem("cti_session"); } catch (e) {}
      const r = await fetch("/api/ops/report", {headers: session ? {"X-Session": session} : {}});
      const url = URL.createObjectURL(new Blob([await r.text()], {type: "text/html"}));
      window.open(url, "_blank", "noopener");
    };
    body.append(
      h("div", {class: "row", style: "margin-bottom:1rem"}, h("button", {class: "btn primary", onclick: openReport}, "Open comparative report (print to PDF)"), h("a", {class: "btn", href: "/api/cti/export.csv"}, "Export CSV")),
      panel("False-positive rate per feed", null, gridTable([
        {label: "Feed", cls: "title", render: f => f.feed}, {label: "Indicators", cls: "right", render: f => f.indicators.toLocaleString()},
        {label: "Candidates", cls: "right", render: f => f.candidates.toLocaleString()}, {label: "Candidate rate", cls: "right", render: f => pct(f.candidate_rate)},
        {label: "Confirmed FP", cls: "right", render: f => String(f.confirmed_fp)}, {label: "FP rate", cls: "right", render: f => (f.fp_rate * 100).toFixed(3) + " %"}], s.feeds)),
      h("div", {style: "height:1rem"}),
      h("div", {class: "grid-main"},
        panel("Family pairs sharing indicators", h("span", {class: "muted small"}, "1 shared indicator = SUSPICIOUS (weak tie) · 2+ = LINKED"), gridTable([
          {label: "", render: p => badge(p.label === "SUSPICIOUS" ? "partial" : "passed", p.label)},
          {label: "Family A", render: p => p.a}, {label: "Family B", render: p => p.b}, {label: "Shared", cls: "right", render: p => String(p.shared_candidates)},
          {label: "Example", cls: "hide-sm small", render: p => h("code", {}, p.example)}], s.suspicious_pairs)),
        panel("FP test: precision and recall per database", h("span", {class: "muted small"}, s.scoring.labelled + " labelled"), gridTable([
          {label: "Database", render: r => r.database}, {label: "Scored", cls: "right", render: r => String(r.scored)}, {label: "Precision", cls: "right", render: r => r.precision ?? "—"},
          {label: "Recall", cls: "right", render: r => r.recall ?? "—"}, {label: "Threats wrongly dropped", cls: "right", render: r => String(r.real_threats_wrongly_dropped)}], s.scoring.table),
          h("p", {class: "small muted", style: "margin:0;padding:.7rem 1.1rem;border-top:1px solid var(--line)"}, s.scoring.note))));
  }
  async function opsLab18(body){
    const d = await api("/api/labs/lab18");
    body.append(startCard({running: d.running, label: "Lab 18 (MongoDB + Cassandra + Neo4j)", start_command: d.start_command}) || "",
      h("div", {class: "tiles"}, tile("MongoDB", (d.mongodb.botvrij_indicators + d.mongodb.threatfox_indicators).toLocaleString(), "indicator documents"),
        tile("Cassandra", d.cassandra_rows != null ? d.cassandra_rows.toLocaleString() : "—", "rows in cti_fp.indicator_feeds"),
        tile("Neo4j", d.neo4j ? d.neo4j.reduce((s, r) => s + r.n, 0).toLocaleString() : "—", d.neo4j_links ? d.neo4j_links.reduce((s, r) => s + r.n, 0).toLocaleString() + " links" : "nodes"),
        tile("Decisions", String(d.mongodb.fp_decisions), "moderator labels")),
      h("div", {class: "grid-main"},
        panel("Communities (label propagation over families)", h("a", {class: "btn small", href: d.neo4j_browser, target: "_blank", rel: "noopener"}, "Open in Neo4j Browser"),
          d.communities ? gridTable([{label: "Community", render: c => String(c.community)}, {label: "Families", cls: "right", render: c => String(c.families)}, {label: "Sample", cls: "small muted", render: c => c.sample.join(", ")}], d.communities)
            : h("p", {class: "panel-body muted small"}, d.error || "Sync the candidates (Moderation → False positives) to build the graph.")),
        panel("FP test", null, gridTable([{label: "Database", render: r => r.database}, {label: "Precision", cls: "right", render: r => r.precision ?? "—"}, {label: "Recall", cls: "right", render: r => r.recall ?? "—"},
          {label: "Wrongly dropped", cls: "right", render: r => String(r.real_threats_wrongly_dropped)}], d.scoring.table))),
      h("p", {class: "small muted"}, "Benchmarks for the three databases are in Experiments → Chapter 18 → Results."));
  }
  async function opsUsers(body){
    const d = await api("/api/admin/users");
    const orgs = [["", "— none —"], ...d.organisations.map(o => [o._id, o.name])];
    const save = async (u, patch) => { try { await api("/api/admin/users/" + u._id, {method: "PATCH", headers: {"Content-Type": "application/json"}, body: JSON.stringify(patch)}); await loadMe(); route(); } catch (err){ alert(err.message); } };
    body.append(panel("Accounts", h("span", {class: "muted small"}, "Changes are audited as user.update"), gridTable([
      {label: "User", cls: "title", render: u => u._id},
      {label: "Role", render: u => { const s = h("select", {class: "field inline-select"}, ["analyst", "moderator", "admin"].map(r => h("option", {value: r, selected: r === u.role}, r))); s.onchange = () => save(u, {role: s.value}); return s; }},
      {label: "Organisation", render: u => { const s = h("select", {class: "field inline-select"}, orgs.map(([v, l]) => h("option", {value: v, selected: v === (u.org || "")}, l))); s.onchange = () => save(u, {org: s.value || null, org_role: s.value ? (u.org_role || "member") : null}); return s; }},
      {label: "Org role", render: u => { if (!u.org) return "—"; const s = h("select", {class: "field inline-select"}, ["member", "admin"].map(r => h("option", {value: r, selected: r === u.org_role}, r))); s.onchange = () => save(u, {org_role: s.value}); return s; }}], d.users)));
  }

  // ------------------------------------------------------------------ router entry
  async function render(name, rest, params){
    stopTimer();
    const seq = ++S.seq;
    const target = h("div", {});
    $("view-platform").replaceChildren(h("div", {class: "empty"}, "Loading…"));
    if (!S.users.length || S.user === null) await loadMe();
    if (seq !== S.seq) return;
    S.target = target;
    try {
      if (name === "tour") await tour();
      else if (name === "cases") await cases(params);
      else if (name === "ask") await askPage();
      else if (name === "moderation") await moderation(rest[0]);
      else if (name === "ops") await ops(rest[0], params);
    } catch (err){ target.replaceChildren(pageHeader({title: name[0].toUpperCase() + name.slice(1)}), errorBox(err)); }
    if (seq === S.seq) $("view-platform").replaceChildren(target);
  }
  document.addEventListener("DOMContentLoaded", () => { loadMe(); });
  return {render, loadMe, signIn, get user(){ return S.user; }};
})();
