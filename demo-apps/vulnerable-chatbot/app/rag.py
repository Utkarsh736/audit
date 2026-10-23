"""RAG retrieval - intentionally vulnerable (no access control on the store)."""
from langchain_community.vectorstores import Chroma

vectorstore = Chroma(persist_directory="./chroma_db")


def search_docs(query: str):
    # No per-user filter: any caller can retrieve ANY indexed document
    return vectorstore.similarity_search(query, k=5)
