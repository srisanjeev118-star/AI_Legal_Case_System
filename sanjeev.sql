CREATE DATABASE IF NOT EXISTS legal_case_system;
USE legal_case_system;

SET FOREIGN_KEY_CHECKS = 0;

DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS case_notes;
DROP TABLE IF EXISTS documents;
DROP TABLE IF EXISTS hearings;
DROP TABLE IF EXISTS cases;
DROP TABLE IF EXISTS lawyers;
DROP TABLE IF EXISTS clients;
DROP TABLE IF EXISTS users;

SET FOREIGN_KEY_CHECKS = 1;


-- USERS
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role ENUM('Admin','Lawyer','User') DEFAULT 'User',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


-- CLIENTS
CREATE TABLE clients (
    client_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    email VARCHAR(150),
    phone VARCHAR(20),
    address VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


-- LAWYERS
CREATE TABLE lawyers (
    lawyer_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    email VARCHAR(150),
    phone VARCHAR(20),
    specialization VARCHAR(150),
    experience INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


-- CASES
CREATE TABLE cases (
    case_id INT AUTO_INCREMENT PRIMARY KEY,
    case_number VARCHAR(100) NOT NULL UNIQUE,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    case_type VARCHAR(100),
    status ENUM(
        'Pending',
        'Under Investigation',
        'Active',
        'Closed'
    ) DEFAULT 'Pending',
    client_id INT,
    lawyer_id INT,
    filing_date DATE,

    FOREIGN KEY (client_id)
        REFERENCES clients(client_id)
        ON DELETE SET NULL,

    FOREIGN KEY (lawyer_id)
        REFERENCES lawyers(lawyer_id)
        ON DELETE SET NULL
);


-- HEARINGS
CREATE TABLE hearings (
    hearing_id INT AUTO_INCREMENT PRIMARY KEY,
    case_id INT NOT NULL,
    hearing_date DATE NOT NULL,
    hearing_time TIME,
    court_name VARCHAR(200),
    judge_name VARCHAR(150),
    notes TEXT,

    FOREIGN KEY (case_id)
        REFERENCES cases(case_id)
        ON DELETE CASCADE
);


-- DOCUMENTS
CREATE TABLE documents (
    document_id INT AUTO_INCREMENT PRIMARY KEY,
    case_id INT NOT NULL,
    document_name VARCHAR(255) NOT NULL,
    document_type VARCHAR(100),
    file_path VARCHAR(500),
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (case_id)
        REFERENCES cases(case_id)
        ON DELETE CASCADE
);


-- CASE NOTES
CREATE TABLE case_notes (
    note_id INT AUTO_INCREMENT PRIMARY KEY,
    case_id INT NOT NULL,
    note TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (case_id)
        REFERENCES cases(case_id)
        ON DELETE CASCADE
);


-- AUDIT LOGS
CREATE TABLE audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    action VARCHAR(100) NOT NULL,
    details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE SET NULL
);


-- SAMPLE ADMIN
INSERT INTO users
(name, email, password, role)
VALUES
(
    'sanjeev',
    'srisanjeev11@gmail.com',
    'Sanjeev@2007',
    'Admin'
);


-- SAMPLE CLIENTS
INSERT INTO clients
(name, email, phone, address)
VALUES
('Arun Kumar', 'arun@gmail.com', '9876543210', 'Madurai'),
('Bala Kumar', 'bala@gmail.com', '9876543211', 'Dindigul'),
('Karthik', 'karthik@gmail.com', '9876543212', 'Chennai');


-- SAMPLE LAWYERS
INSERT INTO lawyers
(name, email, phone, specialization, experience)
VALUES
('Adv. Raj Kumar', 'raj@gmail.com', '9876500001', 'Criminal Law', 10),
('Adv. Priya', 'priya@gmail.com', '9876500002', 'Civil Law', 7),
('Adv. Kumar', 'kumar@gmail.com', '9876500003', 'Corporate Law', 12);


-- SAMPLE CASES
INSERT INTO cases
(
    case_number,
    title,
    description,
    case_type,
    status,
    client_id,
    lawyer_id,
    filing_date
)
VALUES
(
    'CASE001',
    'Property Dispute',
    'Property ownership related legal dispute',
    'Civil',
    'Pending',
    1,
    2,
    '2026-09-01'
),
(
    'CASE002',
    'Criminal Complaint',
    'Criminal complaint case',
    'Criminal',
    'Under Investigation',
    2,
    1,
    '2026-09-05'
),
(
    'CASE003',
    'Business Agreement',
    'Business contract related dispute',
    'Corporate',
    'Pending',
    3,
    3,
    '2026-09-10'
);


-- SAMPLE HEARINGS
INSERT INTO hearings
(
    case_id,
    hearing_date,
    hearing_time,
    court_name,
    judge_name,
    notes
)
VALUES
(1, '2026-10-05', '10:30:00',
 'Madurai District Court', 'Justice Kumar',
 'Initial hearing'),

(2, '2026-10-10', '11:00:00',
 'Dindigul District Court', 'Justice Raj',
 'Investigation hearing'),

(3, '2026-10-15', '10:00:00',
 'Chennai High Court', 'Justice Priya',
 'Contract dispute hearing');


-- DATABASE VERIFICATION
SELECT DATABASE();

SHOW TABLES;

SELECT * FROM users;
SELECT * FROM clients;
SELECT * FROM lawyers;
SELECT * FROM cases;
SELECT * FROM hearings;
SELECT * FROM documents;
SELECT * FROM case_notes;
SELECT * FROM audit_logs;

-- TOTAL CASES
SELECT COUNT(*) AS total_cases
FROM cases;

-- TOTAL CLIENTS
SELECT COUNT(*) AS total_clients
FROM clients;

-- TOTAL LAWYERS
SELECT COUNT(*) AS total_lawyers
FROM lawyers;