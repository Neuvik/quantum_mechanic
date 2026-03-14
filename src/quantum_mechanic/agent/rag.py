# ================================================================
# MODULE: quantum_mechanic.agent.rag
# ----------------------------------------------------------------
# PURPOSE:   Vector database and semantic retrieval engine.
#            Chunks and embeds docs/techniques/*.md into ChromaDB
#            so the LLM can recommend QM modules from IAM evidence.
#
# DESIGN:    Lazy-load: if a vectorstore already exists it is reused
#            unless rebuild=True. Embeddings run locally via
#            all-MiniLM-L6-v2 (no external API call).
# ================================================================
"""
RAG — Retrieval-Augmented Generation engine for QM Agent.
"""

import logging
from pathlib import Path
from typing import List

from langchain_community.document_loaders import DirectoryLoader, TextLoader
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma
from langchain_core.documents import Document
from langchain_text_splitters import MarkdownHeaderTextSplitter, RecursiveCharacterTextSplitter

from quantum_mechanic.core.database import DEFAULT_WORKSPACE_DIR

logger = logging.getLogger(__name__)

# Global path for the technique documentation vectorstore
VECTORSTORE_DIR = DEFAULT_WORKSPACE_DIR.parent / "vectorstore"


def build_or_load_vectorstore(docs_dir: Path | str, rebuild: bool = False) -> Chroma:
    """Load the technique documentation, chunk it, and store in Chroma.
    
    If rebuild=False and the vectorstore exists, it will simply be loaded.
    
    Args:
        docs_dir: Path to the docs/ directory containing Markdown files.
        rebuild: Whether to force rebuild the vector database.
        
    Returns:
        The instantiated Chroma vector store.
    """
    embed_model = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    
    if VECTORSTORE_DIR.exists() and not rebuild:
        logger.debug("Loading existing Chroma vector store from %s", VECTORSTORE_DIR)
        return Chroma(persist_directory=str(VECTORSTORE_DIR), embedding_function=embed_model)

    if rebuild and VECTORSTORE_DIR.exists():
        import shutil
        logger.info("Rebuilding vector store. Clearing %s", VECTORSTORE_DIR)
        shutil.rmtree(VECTORSTORE_DIR, ignore_errors=True)

    VECTORSTORE_DIR.mkdir(parents=True, exist_ok=True)
    
    logger.info("Initializing Markdown document crawler on %s", docs_dir)
    
    # Base loader to just read text of all .md files
    loader = DirectoryLoader(
        str(docs_dir),
        glob="techniques/**/*.md",
        loader_cls=TextLoader
    )
    raw_docs = loader.load()
    logger.info("Loaded %d markdown documents from techniques library", len(raw_docs))
    
    # We want to split out by headers to isolate "Attack Paths (Next Steps)"
    headers_to_split_on = [
        ("#", "Header 1"),
        ("##", "Header 2"),
        ("###", "Header 3"),
    ]
    markdown_splitter = MarkdownHeaderTextSplitter(headers_to_split_on=headers_to_split_on)
    
    md_header_splits: List[Document] = []
    for doc in raw_docs:
        # Split the document
        splits = markdown_splitter.split_text(doc.page_content)
        # Preserve source metadata!
        for split in splits:
            split.metadata["source"] = doc.metadata.get("source", "unknown")
        md_header_splits.extend(splits)
        
    # Standard chunking inside those headers
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=1000,
        chunk_overlap=200,
        length_function=len
    )
    
    final_splits = text_splitter.split_documents(md_header_splits)
    logger.info("Created %d semantic chunks for RAG context", len(final_splits))
    
    logger.info("Embedding technique documentation into Chroma DB (this may take a minute...)")
    db = Chroma.from_documents(
        final_splits,
        embed_model,
        persist_directory=str(VECTORSTORE_DIR)
    )
    
    logger.info("Vector database successfully initialized.")
    return db
