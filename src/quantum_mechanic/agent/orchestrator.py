"""
================================================================
MODULE: quantum_mechanic.agent.orchestrator
----------------------------------------------------------------
PURPOSE:   The Langchain autonomous reasoning loop. Bridges the
           raw JSON API evidence sitting in SQLite with the
           markdown instructions sitting in ChromaDB.
================================================================
"""

import json
import logging
from pathlib import Path

from langchain_anthropic import ChatAnthropic
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate

from quantum_mechanic.agent.rag import build_or_load_vectorstore
from quantum_mechanic.core.workspace import Workspace

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are the Quantum Mechanic (QM) Intelligence Engine, a specialized autonomous agent for cloud offensive operations.
Your mission is to analyze the raw technical EVIDENCE gathered from the environment and cross-reference it with the QM PLAYBOOK to identify attack paths.

CONTEXT LAYERS:
1. <EVIDENCE>: Raw JSON results from QM modules (e.g., `enum_iam`, `enum_compute`). This represents reality in the target cloud.
2. <PLAYBOOK>: Documentation for QM techniques. This represents your available toolkit and how to use it.

YOUR CORE TASKS:
- SYNTHESIZE: Explain what the evidence means in plain English (e.g., "The current identity has the `Owner` role on Subscription X").
- IDENTIFY RISKS: Highlight dangerous permissions (e.g., `iam:PassRole`, `runCommand/action`, `serviceAccountTokenCreator`).
- RECOMMEND: Suggest the EXACT next QM command to run. Prefer modules that exploit identified risks.
- PIVOT: If evidence shows a way to get higher privileges or move to another resource, prioritize that.

CONSTRAINTS:
- Output Markdown. Be technical, concise, and objective.
- ONLY recommend `quantum_mechanic` commands (e.g., `run escalation/compute_identity_abuse --param ...`).
- DO NOT suggest generic cloud CLI commands (aws, gcloud, az).
- If the PLAYBOOK doesn't have a specific module for a risk you see, summarize the risk and state that a manual exploit or future QM module is required.

<EVIDENCE>
{evidence}
</EVIDENCE>

<PLAYBOOK>
{context}
</PLAYBOOK>
"""


class AgentOrchestrator:
    """The central intelligence hub for resolving operator queries."""

    def __init__(self, workspace: Workspace) -> None:
        self.workspace = workspace

        # Resolve the docs/ directory up 4 levels from this file
        # src/quantum_mechanic/agent/orchestrator.py -> root/docs
        self.docs_dir = Path(__file__).resolve().parent.parent.parent.parent / "docs"

        self.vectorstore = build_or_load_vectorstore(self.docs_dir, rebuild=False)
        self.retriever = self.vectorstore.as_retriever(search_kwargs={"k": 4})

        self.llm = ChatAnthropic(
            model_name="claude-3-7-sonnet-20250219",
            temperature=0,  # Strict determinism for offensive tooling
            max_tokens=2048,
        )

        prompt = ChatPromptTemplate.from_messages(
            [("system", SYSTEM_PROMPT), ("human", "{question}")]
        )

        # Helper to stringify Chroma documents into the prompt
        def format_docs(docs) -> str:
            return "\n\n---\n\n".join(doc.page_content for doc in docs)

        # The core computational DAG
        self.chain = (
            {
                "context": self.retriever | format_docs,
                "evidence": lambda x: x["evidence"],
                "question": lambda x: x["question"],
            }
            | prompt
            | self.llm
            | StrOutputParser()
        )

    def ask(self, question: str) -> str:
        """Process an operator's question against the LLM Chain."""
        # 1. Enforce active credential state
        cred_id = self.workspace.active_credential_id
        if not cred_id:
            return "❌ **Agent Error**: You must `use` a credential before asking the agent for advice, so it has context on who you are targeting."

        # 2. Gather historical evidence for this specific identity
        # We query the SQLite table built in Phase 11.1
        evidence_str = "No recent JSON evidence found. You must run `discovery/enum_iam` or similar modules first to generate context."

        try:
            rows = self.workspace.list_evidence_for_credential(cred_id, limit=5)
            if rows:
                compiled_evidence = []
                for r in rows:
                    try:
                        parsed = json.loads(r["output_json"])
                        compiled_evidence.append({"technique": r["technique_id"], "data": parsed})
                    except Exception as e:
                        logger.debug(
                            "Skipping malformed evidence row for technique %s: %s",
                            r["technique_id"],
                            e,
                        )

                if compiled_evidence:
                    evidence_str = json.dumps(compiled_evidence, indent=2)
        except Exception as e:
            logger.error("Failed to query evidence table for RAG: %s", e)

        # 3. Fire Langchain!
        logger.info("Invoking LLM chain with query: %s", question)
        return self.chain.invoke(
            {  # type: ignore
                "evidence": evidence_str,
                "question": question,
            }
        )
