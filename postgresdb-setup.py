import psycopg2
from psycopg2 import OperationalError, sql
import os
import time
import logging
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)

RETRY_ATTEMPTS = 2
RETRY_DELAY = 2


def connect_to_postgres():
    attempts = 0
    while attempts < RETRY_ATTEMPTS:
        try:
            postgress_connection = psycopg2.connect(
                dbname=os.getenv('POSTGRES_DB'),
                user=os.getenv('POSTGRES_USER'),
                password=os.getenv('POSTGRES_PASSWORD'),
                port=os.getenv('POSTGRES_PORT'),
                host=os.getenv('POSTGRES_HOST'),
                connect_timeout=10,
            )
            postgress_cursor = postgress_connection.cursor()
            logging.info("Successfully connected to PostgreSQL")
            return postgress_connection, postgress_cursor
        except OperationalError as e:
            attempts += 1
            logging.error(f"Failed to connect to PostgreSQL. Attempt {attempts}/{RETRY_ATTEMPTS}. Error: {e}")
            if attempts == RETRY_ATTEMPTS:
                logging.error("Could not establish connection to PostgreSQL after several attempts. Exiting.")
                return None, None
            time.sleep(RETRY_DELAY)


def create_table_if_not_exists(cursor, table_name, create_query):
    try:
        logging.info(f"Checking if table {table_name} exists...")
        cursor.execute(sql.SQL("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = %s
            );
        """), [table_name])

        exists = cursor.fetchone()[0]
        if not exists:
            logging.info(f"Creating table: {table_name}")
            cursor.execute(create_query)
            logging.info(f"Table {table_name} created successfully.")
        else:
            logging.info(f"Table {table_name} already exists. Skipping creation.")
    except Exception as e:
        logging.error(f"Error while creating table {table_name}: {e}")


def main():
    postgress_connection, postgress_cursor = connect_to_postgres()
    if not postgress_connection or not postgress_cursor:
        logging.error("Exiting script due to database connection failure.")
        return

    try:
        findings_cwe_table_query = """
        CREATE TABLE IF NOT EXISTS public.findings_cwe (
            id SERIAL PRIMARY KEY,  -- Unique identifier for each row
            finding_id VARCHAR(32) UNIQUE,  -- Finding ID
            cwe_id VARCHAR(10),  -- CWE ID
            cwe_name TEXT,  -- CWE Name
            affected_line TEXT,  -- Description of the affected line
            partial_code TEXT,  -- Partial code snippet
            file_name TEXT,  -- Name of the file containing the vulnerability
            status VARCHAR(20),  -- Status of the finding (e.g., FP/TP)
            org_id VARCHAR(32),  -- Organization ID
            reason TEXT,  -- Reason for the finding
            remediation_action TEXT,  -- Suggested remediation action
            scanner VARCHAR(20),  -- Scanner type
            scan_engine VARCHAR(50)  -- Scan engine name
        );
        """

        scans_table_query = """
        CREATE TABLE IF NOT EXISTS public.scans
        (
            id SERIAL PRIMARY KEY,  -- Unique identifier for each row
            group_id VARCHAR(24),  -- Group ID
            project_link TEXT,  -- Link to the project
            project VARCHAR(255),  -- Project name
            repository TEXT,  -- Repository details
            scan_link TEXT,  -- Link to the scan
            scan_id VARCHAR(24) UNIQUE,  -- Unique Scan ID
            branch VARCHAR(255),  -- Branch name
            commit VARCHAR(40),  -- Commit hash
            fp_vulnerabilities INTEGER,  -- False positive vulnerabilities count
            tp_vulnerabilities INTEGER,  -- True positive vulnerabilities count
            unverified_vulnerabilities INTEGER,  -- Unverified vulnerabilities count
            initiator VARCHAR(255),  -- Scan initiator
            findings_sast INTEGER,  -- SAST findings count
            findings_sca INTEGER,  -- SCA findings count
            findings_secrets INTEGER,  -- Secrets findings count
            findings_compliance INTEGER,  -- Compliance findings count
            findings_iac INTEGER,  -- IaC findings count
            findings_malware INTEGER,  -- Malware findings count
            findings_api INTEGER,  -- API findings count
            findings_pii INTEGER,  -- PII findings count
            findings_container INTEGER,  -- Container findings count
            tags TEXT,  -- Tags associated with the scan
            "timestamp" TIMESTAMP WITHOUT TIME ZONE,  -- Scan timestamp
            total_findings INTEGER  -- Total findings count
        );
        """

        synthesis_response = """
        CREATE TABLE IF NOT EXISTS public.synthesis_response
        (
            id SERIAL PRIMARY KEY,  -- Unique identifier for each row
            question VARCHAR NOT NULL,  -- Question text
            db_response VARCHAR NOT NULL,  -- Database response
            model_response VARCHAR NOT NULL  -- Model response
        );
        """

        sql_user_questions = """
        CREATE TABLE IF NOT EXISTS public.sql_user_questions
        (
            id SERIAL PRIMARY KEY,  -- Unique identifier for each row
            question VARCHAR NOT NULL,  -- User's question
            query VARCHAR NOT NULL  -- SQL query corresponding to the question
        );
        """

        report_page = """
        CREATE TABLE IF NOT EXISTS public.report_page
        (
            id SERIAL PRIMARY KEY,  -- Unique identifier for each row
            input VARCHAR NOT NULL,  -- Input data
            output VARCHAR NOT NULL  -- Output data
        );
        """
        questions_responses = """
        CREATE TABLE IF NOT EXISTS public.questions_responses
        (
            id SERIAL PRIMARY KEY,  -- Unique identifier for each row
            question VARCHAR NOT NULL,  -- Question text
            response VARCHAR NOT NULL  -- Response text
        );
        """
        error_responses = """
        CREATE TABLE IF NOT EXISTS public.error_responses
        (
            id SERIAL PRIMARY KEY,  -- Unique identifier for each row
            question VARCHAR NOT NULL  -- Question text
        );
        """

        datasets = """
        CREATE TABLE IF NOT EXISTS public.datasets
        (
            source VARCHAR,  -- Source of the dataset
            sinc VARCHAR,  -- Additional dataset metadata
            decision VARCHAR NOT NULL,  -- Decision associated with the dataset
            finding VARCHAR NOT NULL,  -- Finding details
            scanner VARCHAR NOT NULL,  -- Scanner type
            external_id VARCHAR NOT NULL,  -- External identifier
            id BIGINT PRIMARY KEY GENERATED BY DEFAULT AS IDENTITY 
                (INCREMENT 1 START 1 MINVALUE 1 MAXVALUE 9223372036854775807 CACHE 1)  -- Auto-incrementing unique identifier
        );
        """
        classification_response = """
        CREATE TABLE IF NOT EXISTS public.classification_response
        (
            id SERIAL PRIMARY KEY,  -- Unique identifier for each row
            question VARCHAR NOT NULL,  -- Question text
            result VARCHAR NOT NULL  -- Classification result
        );
        """

        agent_response = """
        CREATE TABLE IF NOT EXISTS public.agent_response
        (
            id SERIAL PRIMARY KEY,  -- Unique identifier for each row
            user_question VARCHAR NOT NULL,  -- User's question
            tag VARCHAR NOT NULL  -- Associated tag
        );
        """

        tables = {
            "findings_cwe": findings_cwe_table_query,
            "scans": scans_table_query,
            "synthesis_response": synthesis_response,
            "sql_user_questions": sql_user_questions,
            "report_page": report_page,
            "questions_responses": questions_responses,
            "error_responses": error_responses,
            "datasets": datasets,
            "classification_response": classification_response,
            "agent_response": agent_response
            
        }
        

        for table_name, create_query in tables.items():
            create_table_if_not_exists(postgress_cursor, table_name, create_query)

        postgress_connection.commit()
        logging.info("All tables created successfully.")
    except Exception as e:
        logging.error(f"An error occurred in the main function: {e}")
    finally:
        postgress_cursor.close()
        postgress_connection.close()
        logging.info("PostgreSQL connection closed.")


if __name__ == "__main__":
    main()
