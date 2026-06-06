const state = {
  index: null,
  currentRun: null,
  currentScenarioId: null,
  currentArtifactId: null,
};

const elements = {
  artifactRoots: document.querySelector("#artifact-roots"),
  runList: document.querySelector("#run-list"),
  scenarioList: document.querySelector("#scenario-list"),
  emptyState: document.querySelector("#empty-state"),
  runOverview: document.querySelector("#run-overview"),
  runTitle: document.querySelector("#run-title"),
  runRoot: document.querySelector("#run-root"),
  runSummary: document.querySelector("#run-summary"),
  runStats: document.querySelector("#run-stats"),
  scenarioOverview: document.querySelector("#scenario-overview"),
  scenarioTitle: document.querySelector("#scenario-title"),
  scenarioDescription: document.querySelector("#scenario-description"),
  scenarioBadges: document.querySelector("#scenario-badges"),
  whatHappened: document.querySelector("#what-happened"),
  whyResult: document.querySelector("#why-result"),
  verificationSection: document.querySelector("#verification-section"),
  verificationChecks: document.querySelector("#verification-checks"),
  flowSection: document.querySelector("#flow-section"),
  flowList: document.querySelector("#flow-list"),
  artifactSection: document.querySelector("#artifact-section"),
  artifactTabs: document.querySelector("#artifact-tabs"),
  artifactMeta: document.querySelector("#artifact-meta"),
  artifactJson: document.querySelector("#artifact-json"),
  refreshButton: document.querySelector("#refresh-button"),
};

elements.refreshButton.addEventListener("click", async () => {
  await loadIndex();
});

async function loadIndex() {
  const response = await fetch("/api/runs");
  const payload = await response.json();
  state.index = payload;

  renderArtifactRoots();
  renderRunList();

  if (!payload.runs.length) {
    showEmptyState(true);
    return;
  }

  showEmptyState(false);
  const firstRun = payload.runs[0];
  await selectRun(firstRun.id);
}

async function selectRun(runId) {
  const response = await fetch(`/api/runs/${encodeURIComponent(runId)}`);
  const run = await response.json();
  state.currentRun = run;
  const firstScenario = run.scenarios[0];
  state.currentScenarioId = firstScenario ? firstScenario.id : null;
  state.currentArtifactId = firstScenario?.artifacts?.[0]?.id ?? null;
  renderRunList();
  renderRunOverview();
  renderScenarioList();
  renderScenario();
}

function showEmptyState(isEmpty) {
  elements.emptyState.classList.toggle("hidden", !isEmpty);
  elements.runOverview.classList.toggle("hidden", isEmpty);
  elements.scenarioOverview.classList.toggle("hidden", isEmpty);
  elements.verificationSection.classList.toggle("hidden", isEmpty);
  elements.flowSection.classList.toggle("hidden", isEmpty);
  elements.artifactSection.classList.toggle("hidden", isEmpty);
}

function renderArtifactRoots() {
  elements.artifactRoots.replaceChildren();
  for (const root of state.index.artifact_roots) {
    const li = document.createElement("li");
    li.textContent = root;
    elements.artifactRoots.append(li);
  }
}

function renderRunList() {
  elements.runList.replaceChildren();
  for (const run of state.index.runs) {
    const button = document.createElement("button");
    button.type = "button";
    button.classList.toggle("active", state.currentRun?.id === run.id);
    button.innerHTML = `
      <div class="run-item-title">${escapeHtml(run.title)}</div>
      <p class="run-item-meta">${escapeHtml(run.artifact_root)}</p>
    `;
    button.addEventListener("click", async () => {
      await selectRun(run.id);
    });

    const li = document.createElement("li");
    li.append(button);
    elements.runList.append(li);
  }
}

function renderRunOverview() {
  const run = state.currentRun;
  elements.runTitle.textContent = run.title;
  elements.runRoot.textContent = run.artifact_root;
  elements.runSummary.replaceChildren();
  for (const line of run.summary_lines) {
    const li = document.createElement("li");
    li.textContent = line;
    elements.runSummary.append(li);
  }

  elements.runStats.replaceChildren();
  for (const [outcome, count] of Object.entries(run.stats)) {
    const badge = buildBadge(`${outcome}: ${count}`, badgeClassForOutcome(outcome));
    elements.runStats.append(badge);
  }
}

function renderScenarioList() {
  elements.scenarioList.replaceChildren();
  for (const scenario of state.currentRun.scenarios) {
    const button = document.createElement("button");
    button.type = "button";
    button.classList.toggle("active", state.currentScenarioId === scenario.id);
    button.innerHTML = `
      <div class="scenario-item-title">${escapeHtml(scenario.label)}</div>
      <p class="scenario-item-meta">${escapeHtml(scenario.final_outcome)}${scenario.reason_code ? ` · ${escapeHtml(scenario.reason_code)}` : ""}</p>
    `;
    button.addEventListener("click", () => {
      state.currentScenarioId = scenario.id;
      state.currentArtifactId = scenario.artifacts[0]?.id ?? null;
      renderScenarioList();
      renderScenario();
    });

    const li = document.createElement("li");
    li.append(button);
    elements.scenarioList.append(li);
  }
}

function renderScenario() {
  const scenario = currentScenario();
  if (!scenario) {
    return;
  }

  elements.scenarioTitle.textContent = scenario.label;
  elements.scenarioDescription.textContent = scenario.description;
  elements.whatHappened.textContent = scenario.what_happened;
  elements.whyResult.textContent = scenario.why_result;

  elements.scenarioBadges.replaceChildren();
  elements.scenarioBadges.append(buildBadge(`final: ${scenario.final_outcome}`, badgeClassForOutcome(scenario.final_outcome)));
  if (scenario.decision_outcome) {
    elements.scenarioBadges.append(buildBadge(`decision: ${scenario.decision_outcome}`, badgeClassForOutcome(scenario.decision_outcome)));
  }
  if (scenario.reason_code) {
    elements.scenarioBadges.append(buildBadge(`reason: ${scenario.reason_code}`, "badge-danger"));
  }

  elements.verificationChecks.replaceChildren();
  for (const check of scenario.verification_checks) {
    const card = document.createElement("dl");
    card.className = "check-card";
    card.innerHTML = `<dt>${escapeHtml(check.label)}</dt><dd>${escapeHtml(check.value)}</dd>`;
    elements.verificationChecks.append(card);
  }

  elements.flowList.replaceChildren();
  for (const step of scenario.flow) {
    const li = document.createElement("li");
    li.innerHTML = `
      <div class="timeline-title">${escapeHtml(step.title)} <span class="badge ${badgeClassForOutcome(step.status)}">${escapeHtml(step.status)}</span></div>
      <div class="timeline-detail">${escapeHtml(step.detail)}</div>
    `;
    elements.flowList.append(li);
  }

  renderArtifacts(scenario);
}

function renderArtifacts(scenario) {
  elements.artifactTabs.replaceChildren();
  for (const artifact of scenario.artifacts) {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = artifact.label;
    button.classList.toggle("active", artifact.id === state.currentArtifactId);
    button.addEventListener("click", () => {
      state.currentArtifactId = artifact.id;
      renderArtifacts(scenario);
    });
    elements.artifactTabs.append(button);
  }

  const selectedArtifact = scenario.artifacts.find((artifact) => artifact.id === state.currentArtifactId) ?? scenario.artifacts[0];
  if (!selectedArtifact) {
    elements.artifactMeta.textContent = "No artifacts found for this scenario.";
    elements.artifactJson.textContent = "";
    return;
  }

  state.currentArtifactId = selectedArtifact.id;
  elements.artifactMeta.textContent = `${selectedArtifact.label} · ${selectedArtifact.path}`;
  elements.artifactJson.textContent = JSON.stringify(selectedArtifact.payload, null, 2);
}

function currentScenario() {
  return state.currentRun?.scenarios.find((scenario) => scenario.id === state.currentScenarioId) ?? null;
}

function buildBadge(text, className) {
  const span = document.createElement("span");
  span.className = `badge ${className}`;
  span.textContent = text;
  return span;
}

function badgeClassForOutcome(outcome) {
  const normalized = (outcome || "").toLowerCase();
  if (["executed", "verified", "completed", "consumed", "allow"].includes(normalized)) {
    return "badge-success";
  }
  if (["approval-required", "approval_required", "needs-evidence", "needs_evidence", "proof_minted", "received", "verified", "state_updated"].includes(normalized)) {
    return "badge-warning";
  }
  if (["deny", "refused", "workflow_deny", "replay_refused"].includes(normalized) || normalized.includes("mismatch") || normalized.includes("deny") || normalized.includes("refus")) {
    return "badge-danger";
  }
  return "badge-neutral";
}

function escapeHtml(text) {
  return String(text ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

loadIndex().catch((error) => {
  console.error(error);
  showEmptyState(true);
});
