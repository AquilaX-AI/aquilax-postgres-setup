# AquilaX Setup Table Creation Script

This project contains a script to create the necessary PostgreSQL tables for the AquilaX application. The script ensures that all required tables are created if they do not already exist. This document provides detailed instructions for setup, usage, and additional information.

## Prerequisites

Before running the script, ensure you have the following installed and configured:

1. **Python 3.7 or higher**
2. **PostgreSQL**
3. **`psycopg2` Python package**
4. **`.env` file with database credentials**
5. **Access to the PostgreSQL instance**

### Environment Variables

Create a `.env` file in the root directory of the project and include the following environment variables:

```plaintext
POSTGRES_DB=your_database_name
POSTGRES_USER=your_database_user
POSTGRES_PASSWORD=your_database_password
POSTGRES_HOST=your_database_host
POSTGRES_PORT=your_database_port
```

Replace the placeholder values with your PostgreSQL configuration.

## Tables Created

The script creates the following tables:

1. **`findings_cwe`**: Stores details about CWE findings.
2. **`scans`**: Contains information about scan results.
3. **`synthesis_response`**: Stores synthesized question responses.
4. **`sql_user_questions`**: Tracks user-submitted SQL questions.
5. **`report_page`**: Stores report input and output data.
6. **`questions_responses`**: Holds questions and their responses.
7. **`error_responses`**: Tracks errors related to specific questions.
8. **`datasets`**: Maintains metadata about datasets.
9. **`classification_response`**: Stores classification results for questions.
10. **`agent_response`**: Tracks agent responses to user queries.

## Usage

Follow these steps to run the script and create the required tables:

### Step 1: Install Dependencies

Run the following command to install the required Python packages:

```bash
pip install -r requirements.txt
```

### Step 2: Configure Environment Variables

Ensure the `.env` file is correctly set up with your PostgreSQL credentials.

### Step 3: Run the Script

Run the Python script to create the tables:

```bash
python create_tables.py
```

### Step 4: Verify Table Creation

After running the script, log in to your PostgreSQL instance and verify that the tables have been created. You can use the following SQL command:

```sql
\dt
```

This will list all tables in the public schema.

## Script Details

The script checks for the existence of each table before creating it. If a table already exists, the script skips its creation to prevent duplication or errors.

### Key Features

- **Idempotency**: Tables are created only if they do not already exist.
- **Environment-Specific Configuration**: Uses a `.env` file for database credentials.
- **Logging**: Provides detailed logs for each operation, making it easier to debug.
- **Extendability**: Additional tables can be added to the script as needed.

## Example Output

When running the script, you will see logs similar to the following:

```plaintext
INFO: Successfully connected to PostgreSQL
INFO: Checking if table findings_cwe exists...
INFO: Table findings_cwe already exists. Skipping creation.
INFO: Checking if table scans exists...
INFO: Creating table: scans
INFO: Table scans created successfully.
INFO: All tables created successfully.
INFO: PostgreSQL connection closed.
```

## Troubleshooting

- **Database Connection Issues**: Ensure the `.env` file contains valid credentials and the PostgreSQL server is running.
- **Python Dependency Errors**: Verify that all required packages are installed using `pip`.
- **Permission Issues**: Ensure the user specified in `POSTGRES_USER` has sufficient privileges to create tables.


## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

