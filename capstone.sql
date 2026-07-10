DROP DATABASE IF EXISTS cloud_security_posture_db;
CREATE DATABASE cloud_security_posture_db
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_0900_ai_ci;

USE cloud_security_posture_db;

SET FOREIGN_KEY_CHECKS = 0;

DROP TABLE IF EXISTS finding_cis_mappings;
DROP TABLE IF EXISTS cis_controls;
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS resources;
DROP TABLE IF EXISTS scans;

SET FOREIGN_KEY_CHECKS = 1;

CREATE TABLE scans (
    scan_id INT NOT NULL AUTO_INCREMENT,
    aws_profile VARCHAR(100),
    aws_account_id VARCHAR(32),
    region VARCHAR(50),
    service VARCHAR(100),
    scan_type VARCHAR(100),
    started_at DATETIME,
    completed_at DATETIME,
    status VARCHAR(50),
    business_profile VARCHAR(100),
    PRIMARY KEY (scan_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE resources (
    resource_id INT NOT NULL AUTO_INCREMENT,
    scan_id INT NOT NULL,
    aws_resource_id VARCHAR(255),
    resource_name VARCHAR(255),
    resource_type VARCHAR(100),
    service VARCHAR(50),
    region VARCHAR(50),
    arn TEXT,
    PRIMARY KEY (resource_id),
    KEY idx_resources_scan_id (scan_id),
    CONSTRAINT fk_resources_scans
        FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE findings (
    finding_id INT NOT NULL AUTO_INCREMENT,
    scan_id INT NOT NULL,
    resource_id INT,
    finding_code VARCHAR(50),
    title VARCHAR(255),
    description TEXT,
    severity VARCHAR(20),
    compliance_status VARCHAR(50),
    remediation TEXT,
    evidence TEXT,
    detected_at DATETIME,
    business_framework VARCHAR(100),
    business_mapping VARCHAR(255),
    db_engine VARCHAR(100),
    db_environment VARCHAR(100),
    db_engine_note TEXT,
    PRIMARY KEY (finding_id),
    KEY idx_findings_scan_id (scan_id),
    KEY idx_findings_resource_id (resource_id),
    CONSTRAINT fk_findings_scans
        FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
        ON DELETE CASCADE,
    CONSTRAINT fk_findings_resources
        FOREIGN KEY (resource_id) REFERENCES resources(resource_id)
        ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE cis_controls (
    cis_id INT NOT NULL AUTO_INCREMENT,
    cis_version VARCHAR(50),
    control_code VARCHAR(50),
    control_title VARCHAR(255),
    PRIMARY KEY (cis_id),
    UNIQUE KEY uq_cis_control_code (control_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE finding_cis_mappings (
    mapping_id INT NOT NULL AUTO_INCREMENT,
    finding_id INT NOT NULL,
    cis_id INT NOT NULL,
    PRIMARY KEY (mapping_id),
    UNIQUE KEY uq_finding_cis (finding_id, cis_id),
    KEY idx_mapping_finding_id (finding_id),
    KEY idx_mapping_cis_id (cis_id),
    CONSTRAINT fk_mapping_findings
        FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
        ON DELETE CASCADE,
    CONSTRAINT fk_mapping_cis_controls
        FOREIGN KEY (cis_id) REFERENCES cis_controls(cis_id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;