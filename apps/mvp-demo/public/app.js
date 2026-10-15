const ui = {
  state: { mode: "synthetic-presentation", activeCase: null },
  view: "submit",
};

const byId = (id) => document.getElementById(id);
const caseState = () => ui.state.activeCase;

async function request(path, options = {}) {
  const response = await fetch(path, options);
  const body = await response.json();
  if (!response.ok) throw new Error(body.message || body.error || `Request failed (${response.status})`);
  return body;
}

async function command(path, body) {
  const options = { method: "POST", headers: {} };
  if (body !== undefined) {
    options.headers["content-type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  ui.state = await request(path, options);
  render();
}

function showToast(message, error = false) {
  const toast = byId("toast");
  toast.textContent = message;
  toast.className = `toast show${error ? " error" : ""}`;
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => { toast.className = "toast"; }, 3200);
}

function switchView(view, updateHistory = true) {
  ui.view = view;
  document.querySelectorAll(".view").forEach((node) => node.classList.toggle("active", node.id === `view-${view}`));
  document.querySelectorAll(".step").forEach((node) => node.classList.toggle("active", node.dataset.view === view));
  if (updateHistory) window.history.replaceState(null, "", `#${view}`);
}

function communityResult(active) {
  const total = active.votes.support + active.votes.oppose;
  if (total < 3) return "QUORUM PENDING";
  if (active.votes.support / total >= 0.6) return "SUPPORT";
  if (active.votes.oppose / total >= 0.6) return "OPPOSE";
  return "INCONCLUSIVE";
}

function render() {
  const active = caseState();

  byId("receipt-id").textContent = active?.receiptId || "Submit a complaint first";
  byId("receipt-complaint").textContent = active?.complaintId || "—";
  byId("receipt-log").textContent = active ? `${active.logStatus} · ${active.witnesses} witnesses` : "—";
  byId("receipt-ciphertext").textContent = active?.encryptedSummary || "—";
  byId("receipt-time").textContent = active ? new Date(active.submittedAt).toLocaleString() : "—";
  byId("verify-receipt").disabled = !active;

  byId("handler-empty").hidden = Boolean(active);
  byId("handler-case").hidden = !active;
  if (active) {
    byId("handler-case-id").textContent = active.complaintId;
    const decided = active.handlerOutcome !== "PENDING";
    document.querySelectorAll("[data-decision]").forEach((button) => { button.disabled = decided; });
    byId("redaction-preview").textContent = active.redactedStatement || "A redacted derivative appears after the handler decision.";
    byId("approve-publication").disabled = active.publicationStatus !== "PENDING_REVIEW";
    byId("reject-publication").disabled = active.publicationStatus !== "PENDING_REVIEW";
    byId("handler-status").textContent = decided
      ? `Finding: ${active.handlerOutcome} · Publication: ${active.publicationStatus}`
      : "Case opened. Access event recorded.";
  }

  const isPublic = active?.publicationStatus === "APPROVED";
  byId("community-empty").hidden = Boolean(isPublic);
  byId("community-case").hidden = !isPublic;
  if (active && isPublic) {
    byId("community-case-id").textContent = active.complaintId;
    byId("public-statement").textContent = active.redactedStatement;
    byId("support-count").textContent = String(active.votes.support);
    byId("oppose-count").textContent = String(active.votes.oppose);
    const total = active.votes.support + active.votes.oppose;
    byId("quorum-label").textContent = total < 3 ? `${3 - total} more vote${3 - total === 1 ? "" : "s"} required` : `Quorum met · ${communityResult(active)}`;
  }

  const auditReady = Boolean(active && isPublic && active.handlerOutcome !== "PENDING");
  byId("audit-empty").hidden = auditReady;
  byId("audit-case").hidden = !auditReady;
  if (active && auditReady) {
    const result = communityResult(active);
    const total = active.votes.support + active.votes.oppose;
    byId("audit-handler").textContent = active.handlerOutcome;
    byId("audit-community").textContent = result;
    byId("record-audit").disabled = total < 3;
    byId("audit-outcome").textContent = active.auditOutcome === "PENDING" ? "Pending comparison" : active.auditOutcome;
    byId("audit-explanation").textContent = active.auditOutcome === "ALIGNED"
      ? "The independent community outcome agrees with the assigned handler."
      : active.auditOutcome === "CONFLICTING"
        ? "The outcomes conflict. The public listing can be frozen and escalated without changing the private case."
        : active.auditOutcome === "COMMUNITY_INCONCLUSIVE"
          ? "Community quorum was reached without the 60 percent decision threshold."
          : "The auditor independently compares the handler outcome with the public vote.";
    const resultBox = byId("audit-result");
    resultBox.className = `audit-result ${active.auditOutcome === "ALIGNED" ? "aligned" : active.auditOutcome === "CONFLICTING" ? "conflicting" : "pending"}`;
    byId("audit-event").textContent = active.auditEventId ? `Signed demo event: ${active.auditEventId}` : total < 3 ? "Community quorum has not been met." : "Ready for an append-only auditor action.";
  }

  document.querySelectorAll(".step").forEach((button) => {
    const view = button.dataset.view;
    if (view === "receipt" || view === "handler") button.disabled = !active;
    else if (view === "community") button.disabled = !isPublic;
    else if (view === "audit") button.disabled = !auditReady;
    else button.disabled = false;
  });
}

async function initialize() {
  document.querySelectorAll(".step").forEach((button) => button.addEventListener("click", () => switchView(button.dataset.view)));
  document.querySelectorAll("[data-decision]").forEach((button) => button.addEventListener("click", async () => {
    try {
      await command("/demo/v1/handler-decision", { outcome: button.dataset.decision });
      showToast("Append-only handler finding recorded.");
    } catch (error) { showToast(error.message, true); }
  }));
  document.querySelectorAll("[data-vote]").forEach((button) => button.addEventListener("click", async () => {
    try {
      await command("/demo/v1/votes", { choice: button.dataset.vote });
      showToast("Synthetic nullifier accepted; vote recorded once.");
    } catch (error) { showToast(error.message, true); }
  }));

  byId("complaint-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    byId("submit-status").textContent = "Encrypting locally and proving membership…";
    try {
      await command("/demo/v1/complaints", {
        matter: byId("matter").value,
        summary: byId("summary").value,
        evidenceCount: Number(byId("evidence").value),
      });
      byId("submit-status").textContent = "Atomic acceptance completed.";
      switchView("receipt");
      showToast("Encrypted complaint accepted and receipt issued.");
    } catch (error) {
      byId("submit-status").textContent = "";
      showToast(error.message, true);
    }
  });

  byId("verify-receipt").addEventListener("click", async () => {
    try {
      ui.state = await request("/demo/v1/state");
      render();
      byId("receipt-status").textContent = "Receipt, inclusion and witness quorum verified.";
    } catch (error) { showToast(error.message, true); }
  });
  byId("approve-publication").addEventListener("click", async () => {
    try { await command("/demo/v1/publication-review", { approve: true }); switchView("community"); showToast("Independent reviewer approved the derivative."); }
    catch (error) { showToast(error.message, true); }
  });
  byId("reject-publication").addEventListener("click", async () => {
    try { await command("/demo/v1/publication-review", { approve: false }); showToast("Derivative kept private."); }
    catch (error) { showToast(error.message, true); }
  });
  byId("record-audit").addEventListener("click", async () => {
    try { await command("/demo/v1/audit"); showToast("Signed auditor comparison recorded."); }
    catch (error) { showToast(error.message, true); }
  });
  byId("reset-demo").addEventListener("click", async () => {
    try { await command("/demo/v1/reset"); switchView("submit"); showToast("Presentation state reset."); }
    catch (error) { showToast(error.message, true); }
  });

  try {
    const [state, readiness, config] = await Promise.all([
      request("/demo/v1/state"),
      request("/health/ready"),
      request("/public/v1/config"),
    ]);
    ui.state = state;
    byId("tenant-label").textContent = config.tenantSlug;
    byId("system-readiness").textContent = readiness.ready ? "All systems ready" : "Dependency unavailable";
    byId("zone-readiness").textContent = Object.entries(readiness.zones).map(([name, value]) => `${name}: ${value}`).join(" · ");
  } catch (error) {
    byId("system-readiness").textContent = "Runtime unavailable";
    showToast(error.message, true);
  }
  render();
  const initial = new URLSearchParams(window.location.search).get("view") || window.location.hash.slice(1);
  if (["submit", "receipt", "handler", "community", "audit"].includes(initial)) {
    switchView(initial, false);
    window.requestAnimationFrame(() => window.scrollTo(0, 0));
  }
}

void initialize();
