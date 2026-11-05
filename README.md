# Email Investigation Agent

An AI agent for email investigation with human oversight. It examines
email text, explains its assessments, and coordinates external reviews through
Nebius, Toloka, and Tendem.

## How it works

- **AI investigation:** A Nebius model selects tools to inspect emails, assess
  suspicious indicators, and identify cases that need additional judgment.
- **Independent evaluation:** Toloka reviewers label selected emails and explain
  their decisions. Signal compares those results with its original assessments.
- **Expert review:** Tendem reviews ambiguous cases. Signal retrieves the report
  and reassesses the case while preserving the original assessment.
- **Oversight:** The interface brings together cases, review approvals, quality
  comparisons, and activity. A background worker tracks reviews and retrieves results.

## Run locally

Requires Python 3.11–3.14 and API keys for all three services.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
Copy-Item .env.example .env
```

For a new installation, fill in `.env`, then run:

```powershell
.\.venv\Scripts\python.exe setup_pipeline.py
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Keep an existing `.env` and `.local` directory when updating the application.
Setup provisions the Toloka pipeline once. Keep the server running to receive
review results automatically.

## Project structure

- `app.py`: Streamlit interface.
- `src/phishguard/`: Agent, investigation logic, provider clients, and workflow.
- `setup_pipeline.py`: Toloka pipeline configuration.
- `data/`: Fictional email samples and the review pipeline definition.
- `tests/`: Checks for investigation, workflow, and data behavior.

Local state is stored in SQLite under `.local`. Email text and returned reports
are treated as untrusted evidence. The application assesses supplied text; it
does not authenticate senders or take actions in a mailbox.
