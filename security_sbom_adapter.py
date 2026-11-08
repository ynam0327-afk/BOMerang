
"""Adapt BOMerang security results for CycloneDX conversion."""


def to_cyclonedx_risk(priority):
    packages = []

    for result in priority.get("results", []):
        package = result.get("package") or {}
        purl = package.get("purl")

        if not purl:
            continue

        findings = []

        for vuln in result.get("vulnerabilities") or []:
            validation = vuln.get("local_version_validation") or {}
            match_status = validation.get("status", "unknown")

            # Only publish locally verified affected matches.
            if match_status != "affected":
                continue

            vuln_id = vuln.get("canonical_id")
            if not vuln_id:
                continue

            risk = vuln.get("project_priority") or {}
            cvss = risk.get("selected_cvss") or {}

            
            provisional = (
                result.get("version_status") != "confirmed"
                or risk.get("provisional", False)
            )

            priority_pending = risk.get("status") == "pending"
            pending_reason = risk.get("reason")

            review_reasons = []

            if provisional:
                review_reasons.append("provisional_version")

            if priority_pending:
                review_reasons.append(pending_reason or "priority_assessment_pending")

            application_status = (vuln.get("application_review") or {}).get("status", "unreviewed")
            if application_status == "unreviewed":
                review_reasons.append("exploit_conditions_not_verified")

            findings.append({
                "vulnerability_id": vuln_id,
                "aliases": vuln.get("all_ids") or [],
                "cvss_score": cvss.get("score"),
                "cvss_version": cvss.get("version"),
                "cvss_vector": cvss.get("vector"),
                "priority_score": risk.get("priority_score"),
                "priority_status": risk.get("status"),
                "version_status": result.get("version_status", package.get("version_status")),
                "provisional": provisional,
                "priority_reason": pending_reason,
                "application_status": application_status,
                "runtime_applicability": risk.get("runtime_applicability", "not_evaluated"),
                "weights": risk.get("weights"),
                "score_breakdown": risk.get("contributions"),
                "cvss_source": cvss.get("source"),
                "match_status": match_status,
                "status": risk.get("status"),
                "review_required": bool(review_reasons),
                "review_reasons": review_reasons,
            })

        packages.append({
            "purl": purl,
            "findings": findings,
        })

    return {
        "model_version": (
            priority.get("priority_model") or {}
        ).get("model_id", "unknown"),
        "generated_at": priority.get("source_generated_at"),
        "priority_model": priority.get("priority_model"),
        "coverage_note": (
            "Includes locally validated affected findings only. "
            "Unknown and unaffected findings remain in the"
            "original security analysis output."
        ),
        "packages": packages,
    }
