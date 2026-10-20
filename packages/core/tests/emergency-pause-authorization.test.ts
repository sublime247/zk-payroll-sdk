import {
  authorizeEmergencyPayrollPause,
  assertEmergencyPayrollPauseAuthorized,
  EmergencyPauseAuthorizationError,
  type EmergencyPauseRequest,
} from "../src/pause/emergencyPauseAuthorization";

describe("Emergency Payroll Pause Authorization (#692)", () => {
  const requester = "GSECURITYADMIN111111111111111111111111111111111111111H";
  const coSigner = "GCOMPLIANCEOFFICER22222222222222222222222222222222222H";
  const now = 1715000000000;

  const validRequest: EmergencyPauseRequest = {
    requester,
    requesterRole: "SECURITY_ADMIN",
    scope: "PAYROLL_ONLY",
    severity: "HIGH",
    incidentTicket: "INC-2026-789",
    reason: "Suspicious contract anomaly detected in batch execution telemetry.",
    requestedAtMs: now,
  };

  it("authorizes targeted emergency pause by security admin (success path)", () => {
    const decision = authorizeEmergencyPayrollPause(validRequest, {}, now);
    expect(decision.authorized).toBe(true);
    expect(decision.scope).toBe("PAYROLL_ONLY");
    expect(decision.auditPayload).toBeDefined();
    expect(decision.auditPayload?.incidentTicket).toBe("INC-2026-789");
  });

  it("authorizes critical global pause when valid co-signer is provided (success path with dual-signing)", () => {
    const globalRequest: EmergencyPauseRequest = {
      ...validRequest,
      scope: "ALL",
      severity: "CRITICAL",
      coSigners: [coSigner],
      coSignerRoles: ["COMPLIANCE_OFFICER"],
    };

    const decision = authorizeEmergencyPayrollPause(globalRequest, {}, now);
    expect(decision.authorized).toBe(true);
    expect(decision.warnings).toContain(
      "CRITICAL severity emergency pause will immediately halt contract operations upon submission."
    );
  });

  it("rejects critical/global pause when mandatory co-signer is missing (failure path)", () => {
    const soloGlobalRequest: EmergencyPauseRequest = {
      ...validRequest,
      scope: "ALL",
      severity: "CRITICAL",
      coSigners: [], // Missing required co-signer
    };

    const decision = authorizeEmergencyPayrollPause(soloGlobalRequest, {}, now);
    expect(decision.authorized).toBe(false);
    expect(decision.denialCode).toBe("INSUFFICIENT_CO_SIGNERS");
    expect(decision.reason).toContain("requires at least 1 authorized co-signer");
  });

  it("rejects self-cosigning on emergency pause (edge case)", () => {
    const selfCoSignRequest: EmergencyPauseRequest = {
      ...validRequest,
      scope: "ALL",
      severity: "CRITICAL",
      coSigners: [requester], // Requester trying to co-sign themselves!
    };

    const decision = authorizeEmergencyPayrollPause(selfCoSignRequest, {}, now);
    expect(decision.authorized).toBe(false);
    expect(decision.denialCode).toBe("SELF_CO_SIGN_PROHIBITED");
  });

  it("rejects duplicate co-signers (edge case)", () => {
    const dupCoSignRequest: EmergencyPauseRequest = {
      ...validRequest,
      scope: "ALL",
      severity: "CRITICAL",
      coSigners: [coSigner, coSigner], // Duplicate
    };

    const decision = authorizeEmergencyPayrollPause(dupCoSignRequest, {}, now);
    expect(decision.authorized).toBe(false);
    expect(decision.denialCode).toBe("DUPLICATE_CO_SIGNERS");
  });

  it("rejects unauthorized initiator role (failure path)", () => {
    const unauthorizedReq: EmergencyPauseRequest = {
      ...validRequest,
      requesterRole: "JUNIOR_DEVELOPER",
    };

    const decision = authorizeEmergencyPayrollPause(unauthorizedReq, {}, now);
    expect(decision.authorized).toBe(false);
    expect(decision.denialCode).toBe("UNAUTHORIZED_INITIATOR");
  });

  it("rejects missing or too short incident ticket", () => {
    const invalidTicketReq: EmergencyPauseRequest = {
      ...validRequest,
      incidentTicket: "T1", // Too short
    };

    const decision = authorizeEmergencyPayrollPause(invalidTicketReq, {}, now);
    expect(decision.authorized).toBe(false);
    expect(decision.denialCode).toBe("INVALID_INCIDENT_TICKET");
  });

  it("assertEmergencyPayrollPauseAuthorized throws typed error on rejection", () => {
    const badReq: EmergencyPauseRequest = {
      ...validRequest,
      requesterRole: "INTERN",
    };

    expect(authorizeEmergencyPayrollPause(badReq, {}, now).authorized).toBe(false);
    expect(() => assertEmergencyPayrollPauseAuthorized(badReq, {}, now)).toThrow(
      EmergencyPauseAuthorizationError
    );
  });
});
