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
from langchain_core.runnables import RunnablePassthrough

from quantum_mechanic.agent.rag import build_or_load_vectorstore
from quantum_mechanic.core.workspace import Workspace

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are Quantum Mechanic (QM), an offensive cloud security expert RAG Agent.
The operator relies on your advanced context to figure out what commands to run next.

You have access to two critical pieces of context:
1. THE EVIDENCE: The raw JSON output of previous modules run by the operator in their active workspace.
2. THE PLAYBOOK: Relevant excerpts from QM's own markdown documentation on how to exploit or enumerate this cloud infrastructure.

Your goal is to synthesize the EVIDENCE with the PLAYBOOK to provide a highly technical, actionable next step.
If the evidence gives them a specific permission (e.g. `iam:PassRole` or Azure `Owner`), you MUST recommend the exact QM module from the PLAYBOOK to exploit it.

RULES:
- Be incredibly concise. Output Markdown.
- NEVER recommend AWS/gcloud/az CLI commands. ONLY recommend `quantum_mechanic` shell commands (e.g. `run escalation/assume_role_chain`).
- If the PLAYBOOK does not explicitly contain a module to exploit the evidence, admit it and simply summarize their permissions instead. Do not invent modules.

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
            max_tokens=2048
        )
        
        prompt = ChatPromptTemplate.from_messages([
            ("system", SYSTEM_PROMPT),
            ("human", "{question}")
        ])
        
        # Helper to stringify Chroma documents into the prompt
        def format_docs(docs) -> str:
            return "\n\n---\n\n".join(doc.page_content for doc in docs)
            
        # The core computational DAG
        self.chain = (
            {
                "context": self.retriever | format_docs, 
                "evidence": lambda x: x["evidence"], 
                "question": lambda x: x["question"]
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
            rows = self.workspace.db.fetchall(
                "SELECT technique_id, output_json FROM evidence WHERE credential_id = ? ORDER BY id DESC LIMIT 5", 
                (cred_id,)
            )
            if rows:
                compiled_evidence = []
                for r in rows:
                    try:
                        parsed = json.loads(r["output_json"])
                        compiled_evidence.append({
                            "technique": r["technique_id"],
                            "data": parsed
                        })
                    except Exception as e:
                        logger.debug("Skipping malformed evidence row for technique %s: %s", r["technique_id"], e)
                        
                if compiled_evidence:
                    evidence_str = json.dumps(compiled_evidence, indent=2)
        except Exception as e:
            logger.error("Failed to query evidence table for RAG: %s", e)
            
        # 3. Fire Langchain!
        logger.info("Invoking LLM chain with query: %s", question)
        return self.chain.invoke({ # type: ignore
            "evidence": evidence_str,
            "question": question
        })
