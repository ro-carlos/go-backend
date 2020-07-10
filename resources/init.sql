CREATE USER IF NOT EXISTS carlos;
DROP DATABASE IF EXISTS DB CASCADE;
CREATE DATABASE DB;
GRANT ALL ON DATABASE DB TO carlos;


CREATE TABLE DB.Domain
(
Address VARCHAR(255) PRIMARY KEY,
IsDown BOOL,
Logo VARCHAR(255),
SSLGrade VARCHAR(255),
Title VARCHAR(255),
LastUpdate TIMESTAMPTZ
);

CREATE TABLE DB.Server
(
Address VARCHAR(255) PRIMARY KEY,
Country VARCHAR(255),
DomainAddress VARCHAR(255),
Owner VARCHAR(255),
SSLGrade VARCHAR(255),
LastUpdate TIMESTAMPTZ
);

CREATE TABLE DB.Origin
(
IP VARCHAR(255) PRIMARY KEY,
MetaData VARCHAR(255),
LastUpdate TIMESTAMPTZ
);

CREATE TABLE DB.Connection
(
Id SERIAL PRIMARY KEY,
OriginIP VARCHAR(255),
DomainAddress VARCHAR(255),
LastUpdate TIMESTAMPTZ
);

ALTER TABLE DB.Server ADD CONSTRAINT domain_fk FOREIGN KEY (DomainAddress) REFERENCES DB.Domain (Address) ON DELETE CASCADE;
ALTER TABLE DB.Connection ADD CONSTRAINT connection_fk1 FOREIGN KEY (OriginIP) REFERENCES DB.Origin(IP) ON DELETE CASCADE;
ALTER TABLE DB.Connection ADD CONSTRAINT connection_fk2 FOREIGN KEY (DomainAddress) REFERENCES DB.Domain (Address) ON DELETE CASCADE;


INSERT INTO DB.Domain (Address, IsDown, Logo, SSLGrade, Title, LastUpdate) 
VALUES ('google.com', false, 'Any Logo', 'B', 'Google Inc.', '2020-07-08 00:00:00-05:00');

INSERT INTO DB.Server (Address, SSLGrade, Country, Owner, DomainAddress, LastUpdate) 
        VALUES ('172.217.0.46', 'B', 'US', 'Google LLC', 'google.com', '2020-07-08 00:00:00-05:00');
INSERT INTO DB.Server (Address, SSLGrade, Country, Owner, DomainAddress, LastUpdate) 
        VALUES ('2607:f8b0:4005:802:0:0:0:200e', 'B', 'US', 'Google LLC', 'google.com', '2020-07-08 00:00:00-05:00');