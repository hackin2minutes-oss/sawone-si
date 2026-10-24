"""Retrieval for the chatbot (deliberately vulnerable: see README.md)."""
from langchain_community.document_loaders import WebBaseLoader
from langchain_community.vectorstores import FAISS
from langchain_openai import OpenAIEmbeddings

emb = OpenAIEmbeddings()
# planted: the index is a pickle; loading one from an untrusted place runs code
index = FAISS.load_local("knowledge/index", emb, allow_dangerous_deserialization=True)


def add_page(url: str):
    docs = WebBaseLoader(url).load()        # planted: any URL a user sends is fetched (SSRF, poisoning)
    index.add_documents(docs)


def context(question: str) -> str:
    return "\n".join(d.page_content for d in index.similarity_search(question, k=4))
