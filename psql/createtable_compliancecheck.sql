CREATE TABLE compliance_checks (
    id SERIAL PRIMARY KEY,
    vulnerability_id INT REFERENCES vulnerabilities(id),
    requirement_id INT REFERENCES compliance_requirements(id),
    compliant BOOLEAN,
    date_checked DATE
);
