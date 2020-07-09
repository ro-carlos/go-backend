CREATE USER IF NOT EXISTS carlos;
DROP DATABASE IF EXISTS DB CASCADE;
CREATE DATABASE DB;
GRANT ALL ON DATABASE DB TO carlos;


CREATE TABLE DB.Domain
(
Id SERIAL PRIMARY KEY,
IsDown BOOL,
Logo VARCHAR(255),
PreviousSSLGrade VARCHAR(255),
ServersChanged BOOL,
SSLGrade VARCHAR(255),
Title VARCHAR(255),
LastUpdate TIMESTAMPTZ
);

CREATE TABLE DB.Server
(
Id SERIAL PRIMARY KEY,
Address VARCHAR(255),
SSLGrade VARCHAR(255),
Country VARCHAR(255),
Owner VARCHAR(255),
DomainId INT
);

CREATE TABLE DB.Origin
(
IP VARCHAR(255) PRIMARY KEY,
MetaData VARCHAR(255)
);

CREATE TABLE DB.Connection
(
Id SERIAL PRIMARY KEY,
OriginIP VARCHAR(255),
DomainId INT,
Time TIMESTAMPTZ
);

ALTER TABLE DB.Server ADD CONSTRAINT domain_fk FOREIGN KEY (DomainId) REFERENCES DB.Domain (Id) ON DELETE CASCADE;
ALTER TABLE DB.Connection ADD CONSTRAINT connection_fk1 FOREIGN KEY (OriginIP) REFERENCES DB.Origin(IP) ON DELETE CASCADE;
ALTER TABLE DB.Connection ADD CONSTRAINT connection_fk2 FOREIGN KEY (DomainId) REFERENCES DB.Domain (Id) ON DELETE CASCADE;


INSERT INTO DB.Domain (Id, IsDown, Logo, PreviousSSLGrade, ServersChanged, SSLGrade, Title, LastUpdate) 
        VALUES (1, false, 'Any Logo', 'B', false, 'B', 'Any Title', '2020-07-08 00:00:00-05:00') RETURNING Id;

INSERT INTO DB.Server (ID, Address, SSLGrade, Country, Owner, DomainId) 
        VALUES (1, '172.217.0.46', 'B', 'US', 'Google Inc.', 1) RETURNING id;
INSERT INTO DB.Server (ID, Address, SSLGrade, Country, Owner, DomainId) 
        VALUES (2, '2607:f8b0:4005:802:0:0:0:200e', 'B', 'US', 'Google Inc.', 1) RETURNING Id;