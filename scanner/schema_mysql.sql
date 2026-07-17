-- AWS Security Posture Assessment Tool - MySQL schema
-- Extended to match the columns the scanner and dashboard actually use,
-- including the business-profile and DB-profiling fields.
--


CREATE DATABASE IF NOT EXISTS `cloud_security_posture_db`
  DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE `cloud_security_posture_db`;

SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS `finding_cis_mappings`;
DROP TABLE IF EXISTS `findings`;
DROP TABLE IF EXISTS `resources`;
DROP TABLE IF EXISTS `cis_controls`;
DROP TABLE IF EXISTS `scans`;
SET FOREIGN_KEY_CHECKS = 1;

CREATE TABLE `scans` (
  `scan_id`          INT AUTO_INCREMENT PRIMARY KEY,
  `aws_profile`      VARCHAR(50)  NOT NULL,
  `aws_account_id`   VARCHAR(20),
  `region`           VARCHAR(30)  NOT NULL,
  `service`          VARCHAR(50)  NOT NULL,
  `scan_type`        VARCHAR(50)  NOT NULL,          -- basic, full, compliance, PoC Manual Scan
  `started_at`       VARCHAR(40),
  `completed_at`     VARCHAR(40),
  `status`           VARCHAR(20)  NOT NULL,          -- running, completed, failed
  `business_profile` VARCHAR(30)  DEFAULT 'general'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `resources` (
  `resource_id`     INT AUTO_INCREMENT PRIMARY KEY,
  `scan_id`         INT          NOT NULL,
  `aws_resource_id` VARCHAR(255) NOT NULL,           -- bucket name, instance id, key id, etc.
  `resource_name`   VARCHAR(255),
  `resource_type`   VARCHAR(50)  NOT NULL,           -- S3 Bucket, EC2 Instance, IAM User, etc.
  `service`         VARCHAR(50)  NOT NULL,
  `region`          VARCHAR(30),
  `arn`             VARCHAR(512),
  KEY `idx_resources_scan` (`scan_id`),
  CONSTRAINT `fk_resources_scan` FOREIGN KEY (`scan_id`)
    REFERENCES `scans` (`scan_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `cis_controls` (
  `cis_id`        INT AUTO_INCREMENT PRIMARY KEY,
  `cis_version`   VARCHAR(100) NOT NULL,             -- e.g. CIS AWS Foundations Benchmark v1.5.0
  `control_code`  VARCHAR(50)  NOT NULL,             -- e.g. 2.1.1
  `control_title` VARCHAR(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `findings` (
  `finding_id`         INT AUTO_INCREMENT PRIMARY KEY,
  `scan_id`            INT          NOT NULL,
  `resource_id`        INT          NOT NULL,
  `finding_code`       VARCHAR(50)  NOT NULL,        -- e.g. S3-001
  `title`              VARCHAR(255) NOT NULL,
  `description`        TEXT,
  `severity`           VARCHAR(20)  NOT NULL,        -- Low, Medium, High, Critical
  `compliance_status`  VARCHAR(20),                  -- PASS, FAIL, REMEDIATED
  `remediation`        TEXT,
  `detected_at`        VARCHAR(40),
  `evidence`           TEXT,
  `business_framework` VARCHAR(255),
  `business_mapping`   VARCHAR(255),
  `db_engine`          VARCHAR(50),
  `db_environment`     VARCHAR(30),
  `db_engine_note`     TEXT,
  KEY `idx_findings_scan` (`scan_id`),
  KEY `idx_findings_resource` (`resource_id`),
  CONSTRAINT `fk_findings_scan` FOREIGN KEY (`scan_id`)
    REFERENCES `scans` (`scan_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_findings_resource` FOREIGN KEY (`resource_id`)
    REFERENCES `resources` (`resource_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `finding_cis_mappings` (
  `mapping_id` INT AUTO_INCREMENT PRIMARY KEY,
  `finding_id` INT NOT NULL,
  `cis_id`     INT NOT NULL,
  KEY `idx_map_finding` (`finding_id`),
  KEY `idx_map_cis` (`cis_id`),
  CONSTRAINT `fk_map_finding` FOREIGN KEY (`finding_id`)
    REFERENCES `findings` (`finding_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_map_cis` FOREIGN KEY (`cis_id`)
    REFERENCES `cis_controls` (`cis_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
