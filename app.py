import hashlib
import json
import os
import time
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv

from phishguard import storage
from phishguard.investigator import recommended_action
from phishguard.toloka import usd_cents
from phishguard.workflow import REQUIRED, Workflow, cases, price_cents

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")
st.set_page_config(
    page_title="Email Investigation Agent | Human-supervised email investigation",
    page_icon="🛡️",
    layout="wide",
)
missing = [key for key in REQUIRED if not os.getenv(key, "").strip()]
if missing:
    st.error(
        "Email Investigation Agent cannot start. Set "
        + ", ".join(missing)
        + " in .env and restart. All three API keys are mandatory."
    )
    st.stop()
if not (ROOT / ".local/provider-setup.json").exists():
    st.error(
        "Toloka setup is missing. Run python setup_pipeline.py once before starting Email Investigation Agent."
    )
    st.stop()


@st.cache_resource
def worker() -> Workflow:
    workflow = Workflow()
    workflow.start()
    return workflow


try:
    workflow = worker()
except (ValueError, RuntimeError, OSError) as error:
    st.error(str(error))
    st.stop()
st.title("Email Investigation Agent")
st.caption("Email investigation · automated coordination · human oversight")
st.info(
    "AI triage → targeted expert review → independent quality audit → one evidence trail"
)


def queue(identifier: str, kind: str, payload: dict | None = None) -> None:
    storage.enqueue(identifier, kind, payload)
    st.toast("Queued. Email Investigation Agent will continue automatically.")


@st.fragment(run_every="3s")
def dashboard():
    readiness = storage.get("ready", {})
    if not readiness.get("ok"):
        st.warning(readiness.get("message", "Connecting…"))
        if st.button("Recheck connections"):
            queue("preflight-" + str(time.time_ns()), "preflight")
        return
    st.success("Nebius connected · Toloka pipeline validated · Tendem connected")
    rows = cases()
    saved = {row["id"]: storage.get("case:" + row["id"]) for row in rows}
    saved = {cid: value for cid, value in saved.items() if value}
    review = storage.get("toloka", {})
    expert = storage.get("tendem", {})
    commands = storage.commands()
    active = any(
        c["status"] in ("pending", "running") and c["kind"] == "investigate"
        for c in commands
    )
    batch = storage.get("batch", {})
    a, b, c, d = st.columns(4)
    a.metric("Emails assessed", f"{len(saved)} / {len(rows)}")
    b.metric(
        "Expert review",
        expert.get("status", "Not needed yet").replace("_", " ").title(),
    )
    c.metric(
        "Independent audit",
        review.get("status", "Not started").replace("_", " ").title(),
    )
    d.metric(
        "Needs your attention",
        sum(
            x.get("status")
            in (
                "awaiting_approval",
                "needs_clarification",
                "needs_funding",
                "failed",
                "submitting",
                "approving",
            )
            for x in (review, expert)
        ),
    )

    if batch.get("status") != "assessed":
        if st.button(
            "Start investigation" if not saved else "Continue investigation",
            type="primary",
            disabled=active,
        ):
            queue("investigate-" + str(time.time_ns()), "investigate")
        st.caption(
            "Assesses the 10 fictional emails, prepares a 3-email audit, and requests one expert quote if needed. Review requests require your approval."
        )
    else:
        st.caption(
            "AI triage complete. Human jobs continue in the background while the app is running. Completed assessments are reused."
        )

    cases_tab, attention_tab, quality_tab, activity_tab = st.tabs(
        [
            "Cases",
            "Needs your attention",
            "Quality monitoring",
            "Activity & connections",
        ]
    )
    with cases_tab:
        case_id = st.selectbox(
            "Email",
            [r["id"] for r in rows],
            format_func=lambda cid: next(r["subject"] for r in rows if r["id"] == cid),
        )
        row = next(r for r in rows if r["id"] == case_id)
        with st.expander("Email evidence", expanded=True):
            st.text(
                f"From: {row['sender']}\nSubject: {row['subject']}\n\n{row['body']}"
            )
        case = saved.get(case_id)
        if not case:
            st.info("This email is waiting for investigation.")
        else:
            answer = case.get("final", case["initial"])
            left, right = st.columns(2)
            left.metric("Current assessment", answer["label"].replace("_", " ").title())
            right.metric(
                "Evidence",
                "AI + expert report"
                if case.get("final")
                else "AI + URL structure checks",
            )
            st.write(answer["explanation"])
            st.write(
                "**Next step:** "
                + recommended_action(answer["label"], answer["needs_expert"])
            )
            for reason in answer["reasons"]:
                st.write("• " + reason)
            if expert.get("case_id") == case_id:
                st.caption("Tendem: " + expert["status"].replace("_", " "))
                st.write(
                    "**Agent routing reason:** " + expert.get("routing_reason", "")
                )
                st.write("**Question for the expert:** " + expert.get("question", ""))
            elif answer["needs_expert"]:
                st.caption(
                    "Additional evidence needed. Expert review is limited to one case per batch; other cases retain their initial assessments."
                )
            if case.get("expert_report"):
                with st.expander("Independent expert report", expanded=True):
                    st.text(case["expert_report"])
                with st.expander("Original AI assessment"):
                    st.json(case["initial"])
            if case.get("human_evaluation"):
                human = case["human_evaluation"]
                st.write(
                    "**Toloka human judgment:** " + human["label"].replace("_", " ")
                )
                st.text(human["rationale"])
                if case["disagreement"]:
                    st.warning(
                        "Human judgment differs from the original AI assessment. Review the evidence; no automatic override is applied."
                    )

    with attention_tab:
        st.write(
            "Approve scope and spending here. Email Investigation Agent handles submission, monitoring, and retrieval."
        )
        for service in ("Toloka", "Tendem"):
            st.caption(
                f"{service}: ${storage.committed(service) / 100:.2f} reserved of $45 operating limit · $5 held back from your $50 budget"
            )
        if review.get("status") == "awaiting_approval":
            estimate = review["estimate"]
            st.subheader("Independent human audit · 3 emails")
            st.write(
                "The agent selected three assessed emails. Reviewers assess the evidence without seeing the AI answer; a second human checks quality."
            )
            st.write(
                f"Expected **{estimate['total']['expected']}** · forecast maximum **{estimate['total']['worstCase']}**"
            )
            st.caption(estimate["disclaimer"])
            st.write("**Agent selection:** " + review.get("selection_reason", ""))
            with st.expander("Review instructions"):
                st.text(
                    json.loads(
                        (ROOT / "data/toloka_pipeline.json").read_text(encoding="utf-8")
                    )["nodes"][1]["settings"]["instruction"]
                )
            within = (
                usd_cents(estimate["total"]["worstCase"]) + storage.committed("Toloka")
                <= 4500
            )
            if st.button("Approve Toloka audit", disabled=not within):
                queue(
                    "approve-toloka:" + review["approval_token"],
                    "approve_toloka",
                    {"token": review["approval_token"]},
                )
            if not within:
                st.error(
                    "Forecast exceeds the remaining operating budget. No run will start."
                )
        if expert.get("status") == "awaiting_approval":
            contract = expert["contract"]
            st.subheader("Targeted expert review · " + expert["case_id"])
            st.write("Quoted price: **" + contract["price"]["formatted"] + "**")
            st.json(contract["contract"], expanded=True)
            within = (
                price_cents(contract["price"]) + storage.committed("Tendem") <= 4500
            )
            if st.button("Approve Tendem scope and price", disabled=not within):
                queue(
                    "approve-tendem:" + expert["approval_token"],
                    "approve_tendem",
                    {"token": expert["approval_token"]},
                )
            if not within:
                st.error(
                    "Quote exceeds the remaining operating budget. No approval will be submitted."
                )
        if expert.get("status") == "needs_clarification":
            st.subheader("Expert needs additional context")
            for message in expert.get("chat", {}).get("messages", []):
                if message.get("from") == "tendem":
                    st.text(message["text"])
            reply = st.text_area("Clarification", max_chars=4000)
            if st.button("Send clarification", disabled=not reply.strip()):
                token = hashlib.sha256(
                    (str(expert["last_seen_offset"]) + reply).encode()
                ).hexdigest()
                queue("reply:" + token, "reply", {"text": reply})
        for service, item in (("Toloka", review), ("Tendem", expert)):
            if item.get("status") in ("submitting", "approving"):
                st.warning(
                    f"{service}: submission in progress or outcome uncertain. Email Investigation Agent will not repeat this operation automatically."
                )
            if item.get("status") in ("failed", "needs_funding"):
                st.error(
                    f"{service}: {item.get('error') or item['status'].replace('_', ' ')}"
                )
            if storage.get(service + "_poll_error"):
                st.warning(service + ": " + storage.get(service + "_poll_error"))
        for command in commands:
            if command["status"] == "error":
                st.error(command["kind"] + ": " + command["error"])
        if not review and not expert:
            st.info(
                "Nothing to approve yet. Start investigation to prepare the review work."
            )

    with quality_tab:
        labels = review.get("labels", [])
        if not labels:
            st.info(
                "Independent judgments will appear automatically after the approved Toloka run completes. The agent chooses the sample and handles the transfers."
            )
        else:
            compared = [
                {
                    "Email": r["case_id"],
                    "AI": saved[r["case_id"]]["initial"]["label"],
                    "Human": r["label"],
                    "Rationale": r["rationale"],
                }
                for r in labels
            ]
            agreement = sum(r["AI"] == r["Human"] for r in compared) / len(compared)
            st.metric("Agreement on reviewed sample", f"{agreement:.0%}")
            st.dataframe(compared, hide_index=True, width="stretch")
            st.caption(
                "Three selected examples illustrate disagreement; they are not a statistically valid security benchmark."
            )
        st.write("**Security boundaries**")
        st.write(
            "Only fictional, text-only emails are used. Email Investigation Agent never visits email links, opens attachments, sends email, or modifies a mailbox. Email text and expert reports are treated as untrusted evidence."
        )
        st.write(
            "Toloka adds independent human judgment and quality control. Its platform security program does not certify an email as safe or make this app a production email-security gateway."
        )
        st.link_button("Toloka security and privacy", "https://toloka.ai/security")

    with activity_tab:
        st.dataframe(storage.events(), hide_index=True, width="stretch")
        st.caption(
            "All event times are UTC. Jobs persist in the local database; keep this app process running for automatic monitoring."
        )
        st.write("**Nebius model:** " + readiness["model"])
        st.write(
            "**Tendem balance at connection check:** "
            + readiness["tendem_balance"]["formatted"]
        )
        st.link_button("Open Toloka", "https://platform.toloka.ai")
        st.link_button("Open Tendem", "https://agent.tendem.ai")
        if st.button("Refresh connection checks"):
            queue("preflight-" + str(time.time_ns()), "preflight")


dashboard()
