import express from "express";
import cors from "cors";
import fs from "fs";
import path from "path";

const app = express();

app.use(cors());
app.use(express.json());

const PORT = 5050;

const dbPath = path.join(process.cwd(), "data", "db.json");

function readDB(): any {
  return JSON.parse(fs.readFileSync(dbPath, "utf-8"));
}

function writeDB(data: any): void {
  fs.writeFileSync(
    dbPath,
    JSON.stringify(data, null, 2)
  );
}

function nextId(prefix: string, items: any[]): string {
  return `${prefix}-${String(items.length + 1).padStart(3, "0")}`;
}


// ==================================================
// HEALTH
// ==================================================

app.get("/api/health", (_req, res) => {
  res.json({
    success: true,
    message: "SentinelX backend is running"
  });
});


// ==================================================
// DASHBOARD
// ==================================================

app.get("/api/dashboard/summary", (_req, res) => {

  const db = readDB();

  const passed = db.tests.filter(
    (t: any) => t.status === "PASSED"
  ).length;

  const failed = db.tests.filter(
    (t: any) => t.status === "FAILED"
  ).length;

  const high = db.vulnerabilities.filter(
    (v: any) => v.severity === "HIGH"
  ).length;

  const medium = db.vulnerabilities.filter(
    (v: any) => v.severity === "MEDIUM"
  ).length;

  const low = db.vulnerabilities.filter(
    (v: any) => v.severity === "LOW"
  ).length;

  const open = db.vulnerabilities.filter(
    (v: any) => v.status === "OPEN"
  ).length;

  const resolved = db.vulnerabilities.filter(
    (v: any) => v.status === "RESOLVED"
  ).length;

  res.json({
    success: true,
    data: {
      totalAssessments: db.assessments.length,
      totalTests: db.tests.length,
      testsPassed: passed,
      testsFailed: failed,
      highVulnerabilities: high,
      mediumVulnerabilities: medium,
      lowVulnerabilities: low,
      openVulnerabilities: open,
      resolvedVulnerabilities: resolved,
      securityScore: 78
    }
  });
});


// ==================================================
// ASSESSMENTS
// ==================================================

app.get("/api/assessments", (_req, res) => {

  const db = readDB();

  res.json({
    success: true,
    data: db.assessments
  });
});


app.post("/api/assessments", (req, res) => {

  const db = readDB();

  const assessment = {
    id: nextId("ASM", db.assessments),
    name: req.body.name || "New Security Assessment",
    target: req.body.target || "Authorized Test Target",
    environment: req.body.environment || "Staging",
    status: "NOT STARTED",
    progress: 0,
    leadAnalyst: req.body.leadAnalyst || "Security Analyst",
    createdAt: new Date().toISOString()
  };

  db.assessments.push(assessment);

  writeDB(db);

  res.status(201).json({
    success: true,
    data: assessment
  });
});


// ==================================================
// SECURITY TESTS
// ==================================================

app.get("/api/tests", (_req, res) => {

  const db = readDB();

  res.json({
    success: true,
    data: db.tests
  });
});


app.post("/api/tests/:id/run", (req, res) => {

  const db = readDB();

  const test = db.tests.find(
    (t: any) => t.id === req.params.id
  );

  if (!test) {
    return res.status(404).json({
      success: false,
      error: "Security test not found"
    });
  }

  test.status = "RUNNING";

  writeDB(db);

  // Safe simulated test engine.
  // No real exploitation is performed.

  setTimeout(() => {

    const updatedDB = readDB();

    const currentTest = updatedDB.tests.find(
      (t: any) => t.id === req.params.id
    );

    if (!currentTest) return;

    if (
      currentTest.category === "Authorization"
    ) {
      currentTest.status = "FAILED";
    } else if (
      currentTest.category === "Security Headers"
    ) {
      currentTest.status = "FAILED";
    } else {
      currentTest.status = "PASSED";
    }

    writeDB(updatedDB);

  }, 1500);

  res.json({
    success: true,
    message: "Security test started",
    testId: test.id,
    simulated: true
  });
});


// ==================================================
// VULNERABILITIES
// ==================================================

app.get("/api/vulnerabilities", (_req, res) => {

  const db = readDB();

  res.json({
    success: true,
    data: db.vulnerabilities
  });
});


app.post("/api/vulnerabilities", (req, res) => {

  const db = readDB();

  const vulnerability = {
    id: nextId("VULN", db.vulnerabilities),
    assessmentId: req.body.assessmentId || "ASM-001",
    title: req.body.title || "New Security Finding",
    severity: req.body.severity || "MEDIUM",
    cvss: req.body.cvss || 5.0,
    component: req.body.component || "Unknown Component",
    status: "OPEN",
    description: req.body.description || "",
    remediation: req.body.remediation || ""
  };

  db.vulnerabilities.push(vulnerability);

  writeDB(db);

  res.status(201).json({
    success: true,
    data: vulnerability
  });
});


// ==================================================
// REMEDIATION
// ==================================================

app.get("/api/remediations", (_req, res) => {

  const db = readDB();

  res.json({
    success: true,
    data: db.remediations
  });
});


app.post("/api/remediations", (req, res) => {

  const db = readDB();

  const remediation = {
    id: nextId("REM", db.remediations),
    vulnerabilityId: req.body.vulnerabilityId,
    status: req.body.status || "OPEN",
    assignedTo: req.body.assignedTo || "Security Developer",
    recommendation: req.body.recommendation || ""
  };

  db.remediations.push(remediation);

  writeDB(db);

  res.status(201).json({
    success: true,
    data: remediation
  });
});


// ==================================================
// RETESTING
// ==================================================

app.get("/api/retests", (_req, res) => {

  const db = readDB();

  res.json({
    success: true,
    data: db.retests
  });
});


app.post("/api/retests", (req, res) => {

  const db = readDB();

  const retest = {
    id: nextId("RETEST", db.retests),
    vulnerabilityId: req.body.vulnerabilityId,
    result: req.body.result || "PASS",
    notes: req.body.notes || "",
    date: new Date().toISOString()
  };

  db.retests.push(retest);

  const vulnerability = db.vulnerabilities.find(
    (v: any) => v.id === retest.vulnerabilityId
  );

  if (vulnerability) {

    vulnerability.status =
      retest.result === "PASS"
        ? "RESOLVED"
        : "REOPENED";
  }

  writeDB(db);

  res.status(201).json({
    success: true,
    data: retest
  });
});


// ==================================================
// EVIDENCE
// ==================================================

app.get("/api/evidence", (_req, res) => {

  const db = readDB();

  res.json({
    success: true,
    data: db.evidence
  });
});


app.post("/api/evidence", (req, res) => {

  const db = readDB();

  const evidence = {
    id: nextId("EVD", db.evidence),
    vulnerabilityId: req.body.vulnerabilityId,
    type: req.body.type || "Test Evidence",
    description: req.body.description || "",
    fileName: req.body.fileName || ""
  };

  db.evidence.push(evidence);

  writeDB(db);

  res.status(201).json({
    success: true,
    data: evidence
  });
});


// ==================================================
// AUDIT LOGS
// ==================================================

app.get("/api/audit-logs", (_req, res) => {

  const db = readDB();

  res.json({
    success: true,
    data: db.auditLogs
  });
});


// ==================================================
// START SERVER
// ==================================================

app.listen(PORT, () => {

  console.log(
    `SentinelX backend running on http://localhost:${PORT}`
  );

});